import socket
import time
import threading
import csv
import logging
import sys
from collections import defaultdict
from datetime import datetime
from queue import Queue, Full

# =========================
# LOGGING & CONFIG
# =========================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/home/burhan/ta_voip/lb.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

BACKENDS = {
    "B1": {"ip": "10.187.146.203", "port": 5060, "status": "UP"},
    "B2": {"ip": "10.187.146.204", "port": 5060, "status": "UP"}
}

LB_CONFIG = {
    "listen_ip":   "0.0.0.0",
    "listen_port": 5060,
    "num_workers": 8,
    "log_file":    "/home/burhan/ta_voip/lb_log.csv"
}


# =========================
# LOAD BALANCER CLASS
# =========================
class SIPLoadBalancer:

    def __init__(self, backends, config):
        self.backends      = backends
        self.num_backends  = len(backends)
        self.config        = config

        # Round-Robin state
        self.current_index = 0
        self.rr_lock       = threading.Lock()

        # Distribusi dan logging
        self.distribution  = defaultdict(int)
        self.log_lock      = threading.Lock()

        # Statistik
        self.stats = {
            'total_packets':     0,
            'forwarded_packets': 0,
            'failed_packets':    0,
            'forwarding_times':  [],
            'sip_methods':       defaultdict(int)
        }
        self.stats_lock = threading.Lock()

        # Socket utama (terima dari SIPp)
        self.client_socket = None

        # Socket per backend - unbound agar bisa recvfrom balasan backend
        self.backend_sockets = {}

        # Peta call_id -> backend_id dan call_id -> alamat SIPp
        self.call_id_map     = {}
        self.client_addr_map = {}
        self.session_lock    = threading.Lock()

        # Antrian kerja untuk worker thread
        self.work_queue     = Queue(maxsize=1000)
        self.worker_threads = []

        self._init_log_file()
        self._init_backend_sockets()

        logger.info("Load Balancer initialized (%d backends)", self.num_backends)

    # =========================
    # INISIALISASI
    # =========================
    def _init_backend_sockets(self):
        """
        Buat satu UDP socket per backend.
        Socket di-bind ke port acak (0.0.0.0:0) agar OS memilihkan port,
        sehingga recvfrom() dapat menerima balasan dari backend.
        """
        for backend_id in self.backends:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 262144)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 262144)
            sock.bind(("0.0.0.0", 0))  # port dipilih otomatis oleh OS
            self.backend_sockets[backend_id] = sock
            logger.info("[INIT] Backend socket %s terikat di port %d",
                        backend_id, sock.getsockname()[1])

    def _init_log_file(self):
        """
        Reset log setiap kali program dijalankan.
        Mode 'w' memastikan file selalu dibuat ulang dari kosong,
        sehingga data pengujian sebelumnya tidak terbawa.
        """
        with open(self.config['log_file'], 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['timestamp', 'sip_method', 'backend_id',
                             'backend_ip', 'forward_ms', 'algo'])
        logger.info("[LOG] File log direset: %s", self.config['log_file'])

    # =========================
    # ROUND-ROBIN
    # =========================
    def select_backend_roundrobin(self):
        """Pilih backend secara bergantian (Round-Robin)."""
        with self.rr_lock:
            backend_list       = list(self.backends.keys())
            selected_id        = backend_list[self.current_index]
            self.current_index = (self.current_index + 1) % self.num_backends
            self.distribution[selected_id] += 1
        return selected_id, self.backends[selected_id]

    # =========================
    # PARSER SIP
    # =========================
    def parse_sip_packet(self, data):
        """Ekstrak method dan Call-ID dari paket SIP."""
        try:
            text   = data.decode(errors="ignore")
            lines  = text.split('\r\n')
            first  = lines[0].split()
            method = first[0] if first else "UNKNOWN"

            call_id = None
            for line in lines:
                if line.upper().startswith("CALL-ID:"):
                    call_id = line.split(":", 1)[1].strip()
                    break

            return method, call_id
        except Exception:
            return "UNKNOWN", None

    # =========================
    # FORWARD: SIPp -> Backend
    # =========================
    def forward_to_backend(self, packet, client_addr):
        """
        Terima paket dari SIPp, pilih backend dengan Round-Robin,
        catat pemetaan call_id -> backend dan call_id -> alamat SIPp,
        lalu kirimkan paket ke backend yang dipilih.

        Untuk INVITE: backend dipilih baru via Round-Robin.
        Untuk ACK/BYE/CANCEL: backend diambil dari sesi yang sudah ada
        agar satu dialog SIP tetap ke backend yang sama (session affinity).
        """
        start = time.time()
        try:
            method, call_id = self.parse_sip_packet(packet)

            if method == "INVITE":
                with self.session_lock:
                    backend_id, backend = self.select_backend_roundrobin()
                    if call_id:
                        self.call_id_map[call_id]     = backend_id
                        self.client_addr_map[call_id] = client_addr
            else:
                with self.session_lock:
                    backend_id  = self.call_id_map.get(call_id)
                    if call_id and client_addr:
                        self.client_addr_map[call_id] = client_addr

                if backend_id is None:
                    backend_id, backend = self.select_backend_roundrobin()
                else:
                    backend = self.backends[backend_id]

            # Kirim ke backend
            self.backend_sockets[backend_id].sendto(
                packet, (backend["ip"], backend["port"])
            )

            latency = (time.time() - start) * 1000
            self._log_to_csv(method, backend_id, backend["ip"], latency)

            with self.stats_lock:
                self.stats['total_packets']      += 1
                self.stats['forwarded_packets']  += 1
                self.stats['forwarding_times'].append(latency)
                self.stats['sip_methods'][method] += 1

            logger.info("[FORWARD] %s -> %s (%s) %.3fms",
                        method, backend_id, backend["ip"], latency)

        except Exception as e:
            logger.error("[FORWARD ERROR] %s", e)
            with self.stats_lock:
                self.stats['failed_packets'] += 1

    # =========================
    # REPLY: Backend -> SIPp
    # =========================
    def _start_backend_reply_listener(self, backend_id, sock):
        """
        Thread per backend: baca balasan SIP dari backend,
        lalu teruskan ke alamat SIPp yang sesuai (lookup dari call_id_map).
        Ini adalah bagian yang sebelumnya tidak ada - penyebab call selalu gagal.
        """
        def listen():
            logger.info("[REPLY_LISTENER] %s aktif mendengarkan balasan backend",
                        backend_id)
            while True:
                try:
                    data, _ = sock.recvfrom(4096)
                    method, call_id = self.parse_sip_packet(data)

                    with self.session_lock:
                        client_addr = self.client_addr_map.get(call_id)

                    if client_addr and self.client_socket:
                        self.client_socket.sendto(data, client_addr)
                        logger.info("[REPLY] %s <- %s -> SIPp %s",
                                    method, backend_id, client_addr)
                    else:
                        logger.warning(
                            "[REPLY] Tidak ada client untuk call_id=%s method=%s",
                            call_id, method
                        )

                    # Bersihkan sesi setelah BYE atau CANCEL
                    if method in ("BYE", "CANCEL") and call_id:
                        with self.session_lock:
                            self.call_id_map.pop(call_id, None)
                            self.client_addr_map.pop(call_id, None)

                except Exception as e:
                    logger.error("[REPLY_LISTENER %s] Error: %s", backend_id, e)

        t = threading.Thread(target=listen, daemon=True,
                             name=f"reply-{backend_id}")
        t.start()

    # =========================
    # WORKER THREAD
    # =========================
    def worker(self):
        """Ambil paket dari antrian dan proses secara paralel."""
        while True:
            try:
                item = self.work_queue.get(timeout=1)
                if item is None:
                    break
                packet, addr = item
                self.forward_to_backend(packet, addr)
                self.work_queue.task_done()
            except Exception:
                pass

    def start_workers(self):
        for i in range(self.config['num_workers']):
            t = threading.Thread(target=self.worker, daemon=True,
                                 name=f"worker-{i}")
            t.start()
            self.worker_threads.append(t)
        logger.info("[WORKER] %d worker thread aktif", self.config['num_workers'])

    # =========================
    # LOGGING CSV
    # =========================
    def _log_to_csv(self, method, backend_id, ip, latency):
        with self.log_lock:
            with open(self.config['log_file'], 'a', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    datetime.now().isoformat(),
                    method,
                    backend_id,
                    ip,
                    f"{latency:.3f}",
                    "round_robin"
                ])

    # =========================
    # MAIN LOOP
    # =========================
    def run(self):
        # 1. Jalankan worker thread
        self.start_workers()

        # 2. Buat socket utama - mendengarkan dari SIPp
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 524288)
        self.client_socket.bind((self.config['listen_ip'],
                                  self.config['listen_port']))

        # 3. Jalankan reply listener untuk setiap backend
        #    (PENTING: harus setelah client_socket dibuat)
        for backend_id, sock in self.backend_sockets.items():
            self._start_backend_reply_listener(backend_id, sock)

        logger.info("Listening on %s:%d",
                    self.config['listen_ip'], self.config['listen_port'])

        try:
            while True:
                packet, addr = self.client_socket.recvfrom(4096)
                try:
                    self.work_queue.put_nowait((packet, addr))
                except Full:
                    logger.warning("[QUEUE] Penuh - paket dari %s dibuang", addr)

        except KeyboardInterrupt:
            logger.info("Menghentikan Load Balancer...")
            self._cleanup()

    # =========================
    # CLEANUP & STATISTIK
    # =========================
    def _cleanup(self):
        self._print_stats()

        # Kirim sinyal stop ke semua worker
        for _ in self.worker_threads:
            self.work_queue.put(None)

        if self.client_socket:
            self.client_socket.close()

        for sock in self.backend_sockets.values():
            sock.close()

    def _print_stats(self):
        with self.stats_lock:
            logger.info("=== STATISTIK AKHIR ===")
            logger.info("Total paket      : %d", self.stats['total_packets'])
            logger.info("Berhasil dikirim : %d", self.stats['forwarded_packets'])
            logger.info("Gagal            : %d", self.stats['failed_packets'])

            times = self.stats['forwarding_times']
            if times:
                logger.info("Latency rata-rata: %.3f ms", sum(times) / len(times))
                logger.info("Latency maks     : %.3f ms", max(times))

            total = sum(self.distribution.values())
            logger.info("Distribusi routing:")
            for k, v in self.distribution.items():
                pct = (v / total * 100) if total else 0
                logger.info("  %s: %d request (%.1f%%)", k, v, pct)

            logger.info("Metode SIP:")
            for method, count in self.stats['sip_methods'].items():
                logger.info("  %-10s: %d", method, count)


# =========================
# ENTRY POINT
# =========================
def main():
    lb = SIPLoadBalancer(BACKENDS, LB_CONFIG)
    lb.run()


if __name__ == "__main__":
    main()
