import subprocess, sys, statistics
from datetime import datetime

def hitung_qos(pcap_file, skenario="", beban=""):
    """
    Fungsi utama untuk menganalisis file .pcap dan menghitung QoS (Delay, Jitter, Loss, Throughput).
    Membutuhkan 'tshark' (Wireshark versi Terminal) terinstal di sistem.
    """

    # 1. Menjalankan perintah TShark melalui subprocess untuk membaca file pcap
    # -r: membaca file
    # -T fields: format output berupa teks kolom
    # -e: field apa saja yang ingin diekstrak (waktu, ukuran paket, IP asal/tujuan, Port asal/tujuan)
    # -Y: filter, hanya ambil paket UDP di port 6000 ATAU rentang port RTP Asterisk (10000-20000)
    # -E separator=|: pisahkan antar kolom dengan karakter '|'
    hasil = subprocess.run([
        "tshark", "-r", pcap_file,
        "-T", "fields",
        "-e", "frame.time_epoch",
        "-e", "frame.len",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "udp.srcport",
        "-e", "udp.dstport",
        "-Y", "udp.port == 6000 or "
              "(udp.srcport >= 10000 and udp.srcport <= 20000) or "
              "(udp.dstport >= 10000 and udp.dstport <= 20000)",
        "-E", "separator=|"
    ], capture_output=True, text=True)

    # Memecah output teks dari TShark menjadi array per baris, dan membuang baris yang kosong
    baris = [b for b in hasil.stdout.strip().split('\n') if b]

    # Jika file pcap kosong atau tidak ada paket yang cocok dengan filter
    if not baris:
        print("Tidak ada paket ditemukan!")
        return

    # Pisah stream berdasarkan kombinasi IP asal dan Port asal (src_ip:src_port)
    # Sekaligus kumpulkan bytes (ukuran) dan timestamp (waktu) global untuk hitung throughput nanti
    stream = {}
    all_timestamps = []
    total_bytes = 0

    # Iterasi/looping setiap baris hasil bacaan TShark
    for b in baris:
        kolom = b.split('|')  # Pecah berdasarkan pemisah '|'

        # Pastikan baris memiliki 6 kolom sesuai parameter -e di atas, jika tidak lewati
        if len(kolom) < 6:
            continue

        try:
            ts       = float(kolom[0])  # Timestamp / Waktu datangnya paket
            pkt_len  = int(kolom[1])    # Panjang paket dalam Bytes
            src_ip   = kolom[2]         # IP Sumber
            src_port = kolom[4]         # Port Sumber
            key      = f"{src_ip}:{src_port}"  # Membuat kunci unik/ID untuk setiap stream/sesi

            # Jika sesi ini belum ada di dictionary, buat tempat baru
            if key not in stream:
                stream[key] = {'timestamps': [], 'bytes': 0}

            # Masukkan data waktu dan tambahkan ukuran bytes ke sesi tersebut
            stream[key]['timestamps'].append(ts)
            stream[key]['bytes'] += pkt_len

            # Kumpulkan juga untuk total keseluruhan (Global)
            all_timestamps.append(ts)
            total_bytes += pkt_len
        except:
            # Jika ada error konversi tipe data (misal string ke float), lewati baris ini
            continue

    # Filter: hanya ambil stream RTP yang berasal dari server Asterisk (karena port Asterisk diset 10000-20000)
    stream_asterisk = {
        k: v for k, v in stream.items()
        if int(k.split(':')[1]) >= 10000
    }

    # Jika ternyata tidak ada yang dari port 10000-20000, fallback (gunakan semua stream yang ada)
    if not stream_asterisk:
        print("Tidak ada stream Asterisk ditemukan, gunakan semua stream...")
        stream_asterisk = stream

    # Cetak header ringkasan awal ke layar
    print(f"\n{'='*60}")
    print(f"HASIL PENGUJIAN QoS VoIP")
    if skenario:
        print(f"Skenario : {skenario}")
    if beban:
        print(f"Beban    : {beban} panggilan simultan")
    print(f"File     : {pcap_file}")
    print(f"Waktu    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}")

    # Siapkan variabel penampung untuk menghitung rata-rata dari KESELURUHAN stream
    semua_delay      = []
    semua_jitter     = []
    semua_loss       = 0
    semua_paket      = 0
    semua_bytes      = 0
    semua_ts_first   = []
    semua_ts_last    = []

    # Proses perhitungan QoS per masing-masing Stream/Sesi
    for key, data in stream_asterisk.items():
        timestamps = data['timestamps']
        pkt_bytes  = data['bytes']

        # Jika paket dalam satu sesi kurang dari 2, tidak bisa dihitung delay antar paketnya
        if len(timestamps) < 2:
            continue

        # 1. Hitung DELAY: Selisih waktu kedatangan antara paket saat ini dan paket sebelumnya
        # Dikali 1000 untuk mengubah detik menjadi milidetik (ms)
        deltas = [(timestamps[i]-timestamps[i-1])*1000
                  for i in range(1, len(timestamps))]

        # 2. Hitung JITTER: Selisih absolut (nilai positif) antara delay saat ini dan delay sebelumnya
        jitter_list = [abs(deltas[i]-deltas[i-1])
                       for i in range(1, len(deltas))]

        # Cari nilai rata-rata dari list delay dan jitter
        avg_delay  = statistics.mean(deltas)
        avg_jitter = statistics.mean(jitter_list) if jitter_list else 0

        # 3. Hitung PACKET LOSS (Estimasi):
        # Jika ada jeda (delay) antar paket yang ukurannya melebihi 3x lipat rata-rata delay normal,
        # diasumsikan ada paket yang hilang/drop di tengah-tengah.
        gap_besar  = sum(1 for d in deltas if d > avg_delay * 3)

        # 4. Hitung THROUGHPUT per stream:
        # Rumus: (Total Bytes * 8 (jadikan bit)) / (Durasi Stream (detik)) / 1000 (jadikan kilo bit / kbps)
        durasi_stream = timestamps[-1] - timestamps[0]
        throughput_stream = (pkt_bytes * 8 / durasi_stream / 1000) if durasi_stream > 0 else 0

        # Gabungkan hasil per-stream ke dalam variabel penampung global
        semua_delay.extend(deltas)
        semua_jitter.extend(jitter_list)
        semua_loss      += gap_besar
        semua_paket     += len(timestamps)
        semua_bytes     += pkt_bytes
        semua_ts_first.append(timestamps[0])
        semua_ts_last.append(timestamps[-1])

        # Cetak metrik per stream/sesi ke layar
        print(f"\nStream {key}:")
        print(f"  Paket        : {len(timestamps)}")
        print(f"  Avg Delay    : {avg_delay:.3f} ms")
        print(f"  Avg Jitter   : {avg_jitter:.3f} ms")
        print(f"  Max Delay    : {max(deltas):.3f} ms")
        print(f"  Loss est.    : {gap_besar} paket")
        print(f"  Throughput   : {throughput_stream:.2f} kbps")

    print(f"\n{'='*60}")
    print("RINGKASAN AKHIR:")

    # Proses perhitungan rata-rata GLOBAL (seluruh stream digabung)
    if semua_delay:
        avg_d    = statistics.mean(semua_delay)
        avg_j    = statistics.mean(semua_jitter) if semua_jitter else 0
        max_d    = max(semua_delay)
        # Persentase Packet Loss = (Jumlah Paket Asumsi Hilang / Total Paket Datang) * 100
        loss_pct = (semua_loss / semua_paket * 100) if semua_paket > 0 else 0

        # Throughput total: bytes semua stream digabung / durasi keseluruhan uji coba
        durasi_total = max(semua_ts_last) - min(semua_ts_first)
        throughput_total = (semua_bytes * 8 / durasi_total / 1000) if durasi_total > 0 else 0

        # Cetak hasil agregat/global ke layar
        print(f"  Total stream    : {len(stream_asterisk)}")
        print(f"  Total paket     : {semua_paket}")
        print(f"  Total bytes     : {semua_bytes} bytes")
        print(f"  Durasi uji      : {durasi_total:.2f} detik")
        print(f"  Avg Delay       : {avg_d:.3f} ms")
        print(f"  Avg Jitter      : {avg_j:.3f} ms")
        print(f"  Max Delay       : {max_d:.3f} ms")
        print(f"  Packet Loss     : {loss_pct:.2f}%")
        print(f"  Throughput      : {throughput_total:.2f} kbps")

        # Validasi/Penilaian QoS berdasarkan standar ITU-T G.114
        print(f"\nStatus QoS:")
        print(f"  Delay  : {'✓ BAIK  (≤150ms)' if avg_d <= 150 else '✗ BURUK (>150ms)'} → {avg_d:.3f} ms")
        print(f"  Jitter : {'✓ BAIK  (≤30ms) ' if avg_j <= 30  else '✗ BURUK (>30ms) '} → {avg_j:.3f} ms")
        print(f"  Loss   : {'✓ BAIK  (≤1%)   ' if loss_pct <= 1 else '✗ BURUK (>1%)   '} → {loss_pct:.2f}%")
        print(f"  Tput   : {'✓ ADA   '} → {throughput_total:.2f} kbps")

        # Blok penyimpanan hasil perhitungan akhir ke dalam file .csv
        import csv
        # Ganti ekstensi .pcap di nama file menjadi _result.csv
        csv_file = pcap_file.replace('.pcap', '_result.csv')

        with open(csv_file, 'w', newline='') as f:
            w = csv.writer(f)
            # Menulis header CSV
            w.writerow(['skenario', 'beban', 'avg_delay_ms',
                        'avg_jitter_ms', 'max_delay_ms',
                        'packet_loss_pct', 'throughput_kbps'])
            # Menulis data nilai metrik ke dalam CSV, dibulatkan (round) agar rapi
            w.writerow([skenario, beban,
                        round(avg_d, 3), round(avg_j, 3),
                        round(max_d, 3), round(loss_pct, 2),
                        round(throughput_total, 2)])
        print(f"\nHasil disimpan ke: {csv_file}")

# Blok Eksekusi Program (Titik Masuk)
if __name__ == "__main__":
    # Mengambil parameter/argumen dari command line (Terminal).
    # Jika tidak ada parameter yang diberikan, akan menggunakan nilai default (seperti '/tmp/b1_s1_load10.pcap')
    pcap     = sys.argv[1] if len(sys.argv) > 1 else "/tmp/b1_s1_load10.pcap"
    skenario = sys.argv[2] if len(sys.argv) > 2 else "S1-Baseline"
    beban    = sys.argv[3] if len(sys.argv) > 3 else "10"

    # Jalankan fungsinya
    hitung_qos(pcap, skenario, beban)
