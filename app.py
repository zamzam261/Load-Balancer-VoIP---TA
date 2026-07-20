from flask import Flask, Response, render_template, stream_with_context
import json, time, csv, os, re, threading
from datetime import datetime
from collections import deque

app = Flask(__name__, template_folder="templates")

LB_LOG    = "/home/burhan/ta_voip/lb_log.csv"
LB_LC_LOG = "/home/burhan/ta_voip/lb_lc.log"
QOS_FILE  = "/home/burhan/ta_voip/qos_data.json"

qos_history = deque(maxlen=60)
lock = threading.Lock()


# ==========================================================
# FUNGSI PARSE lb_lc.log (tidak berubah)
# ==========================================================
def parse_lc_log():
    result = {
        "latency_avg": 0.0,
        "latency_max": 0.0,
        "methods": {"INVITE": 0, "ACK": 0, "BYE": 0},
        "gagal": 0
    }
    try:
        with open(LB_LC_LOG, 'r') as f:
            lines = f.readlines()
        lines = lines[-200:]
        for line in lines:
            m = re.search(r'Latency rata-rata\s*:\s*([\d.]+)', line)
            if m:
                result["latency_avg"] = float(m.group(1))
            m = re.search(r'Latency maks\s*:\s*([\d.]+)', line)
            if m:
                result["latency_max"] = float(m.group(1))
            m = re.search(r'(INVITE|ACK|BYE)\s*:\s*(\d+)', line)
            if m:
                result["methods"][m.group(1)] = int(m.group(2))
            m = re.search(r'Gagal\s*:\s*(\d+)', line)
            if m:
                result["gagal"] = int(m.group(1))
    except FileNotFoundError:
        pass
    return result


# ==========================================================
# FUNGSI PERHITUNGAN QoS DARI lb_log.csv
# PERUBAHAN: lc_stats sekarang selalu dihitung dari CSV
#            (tidak lagi bergantung pada file lb_lc.log untuk metode SIP)
#            sehingga data yang sama tersedia untuk RR maupun LC
# ==========================================================
def hitung_qos_dari_log():
    invite_delays = []
    routing       = {"B1": 0, "B2": 0}
    sip_methods   = {"INVITE": 0, "ACK": 0, "BYE": 0}
    prev_delay    = None
    jitter_list   = []
    algo_detected = "unknown"
    max_lat       = 0.0

    try:
        with open(LB_LOG, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                line_lower = line.lower()
                if "least" in line_lower:
                    algo_detected = "least_connection"
                elif "round" in line_lower:
                    algo_detected = "round_robin"

                parts = line.split(',')
                if len(parts) >= 5:
                    method  = parts[1].strip()
                    backend = parts[2].strip()

                    # Hitung breakdown metode SIP (untuk SEMUA algo)
                    if method in sip_methods:
                        sip_methods[method] += 1

                    # Hitung distribusi routing
                    if backend in routing:
                        routing[backend] += 1

                    # Hitung forwarding time dan jitter hanya dari INVITE
                    if method == "INVITE":
                        try:
                            fwd_ms = float(parts[4].strip())
                            invite_delays.append(fwd_ms)
                            if fwd_ms > max_lat:
                                max_lat = fwd_ms
                            if prev_delay is not None:
                                jitter_list.append(abs(fwd_ms - prev_delay))
                            prev_delay = fwd_ms
                        except ValueError:
                            continue
    except FileNotFoundError:
        pass

    avg_fwd    = round(sum(invite_delays) / len(invite_delays), 3) if invite_delays else 0
    avg_jitter = round(sum(jitter_list)   / len(jitter_list),   3) if jitter_list   else 0
    throughput = len(invite_delays)

    # PERUBAHAN: lc_stats dibuat dari data CSV, bukan dari lb_lc.log
    # Ini memastikan panel ini tersedia untuk KEDUA algoritma (RR & LC)
    shared_stats = {
        "methods":     sip_methods,
        "latency_max": round(max_lat, 3),
        "gagal":       0       # Diisi dari lb_lc.log jika ada
    }

    # Coba enrichment dari lb_lc.log jika file tersedia (opsional)
    try:
        lc_extra = parse_lc_log()
        shared_stats["latency_max"] = lc_extra["latency_max"] or shared_stats["latency_max"]
        shared_stats["gagal"]       = lc_extra["gagal"]
    except Exception:
        pass

    return {
        "avg_fwd_ms":    avg_fwd,       # PERUBAHAN: nama key diganti avg_fwd_ms
        "avg_jitter_ms": avg_jitter,
        "throughput":    throughput,
        "routing":       routing,
        "algo":          algo_detected,
        "shared_stats":  shared_stats   # PERUBAHAN: nama key diganti shared_stats (bukan lc_stats)
    }


# ==========================================================
# BACKGROUND MONITOR THREAD
# PERUBAHAN: log print pakai key avg_fwd_ms
# ==========================================================
def monitor_loop():
    while True:
        try:
            hasil = hitung_qos_dari_log()
            now   = datetime.now().strftime("%H:%M:%S")

            with lock:
                qos_history.append({
                    "timestamp": now,
                    "fwd":       hasil["avg_fwd_ms"],      # PERUBAHAN: key 'delay' -> 'fwd'
                    "jitter":    hasil["avg_jitter_ms"],
                    "throughput":hasil["throughput"]
                })

                with open(QOS_FILE, "w") as f:
                    json.dump({
                        "timestamps": [d["timestamp"] for d in qos_history],
                        "fwd":        [d["fwd"]       for d in qos_history],  # PERUBAHAN
                        "jitter":     [d["jitter"]    for d in qos_history],
                        "throughput": [d["throughput"] for d in qos_history]
                    }, f)

            print(
                f"[Monitor] {now}"
                f" | Algo:{hasil['algo']}"
                f" | FwdTime:{hasil['avg_fwd_ms']}ms"   # PERUBAHAN: label print
                f" | Jitter:{hasil['avg_jitter_ms']}ms"
                f" | B1:{hasil['routing']['B1']}"
                f" | B2:{hasil['routing']['B2']}"
            )

        except Exception as e:
            print(f"[Monitor] Error: {e}")

        time.sleep(3)


# ==========================================================
# ROUTE: Dashboard Utama
# ==========================================================
@app.route("/")
def index():
    return render_template("dashboard.html")


# ==========================================================
# ROUTE: SSE Stream
# PERUBAHAN:
# - Key 'delay' di payload diganti 'fwd' (forwarding time)
# - Key 'lc_stats' diganti 'shared_stats' (berlaku untuk KEDUA algo)
# ==========================================================
@app.route("/stream")
def stream():
    def generate():
        while True:
            payload = {}

            try:
                with open(QOS_FILE) as f:
                    payload["qos"] = json.load(f)
            except Exception:
                payload["qos"] = {
                    "timestamps": [], "fwd": [],   # PERUBAHAN: key 'delay' -> 'fwd'
                    "jitter": [], "throughput": []
                }

            hasil = hitung_qos_dari_log()
            payload["routing"]      = hasil["routing"]
            payload["algo"]         = hasil["algo"]
            payload["shared_stats"] = hasil["shared_stats"]  # PERUBAHAN: nama key

            yield f"data: {json.dumps(payload)}\n\n"
            time.sleep(3)

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
    )


# ==========================================================
# ENTRY POINT
# ==========================================================
if __name__ == "__main__":
    t = threading.Thread(target=monitor_loop, daemon=True)
    t.start()
    print("[Dashboard] Monitor aktif. Buka browser: http://<IP-LB>:5000")
    app.run(host="0.0.0.0", port=5000, threaded=True)
