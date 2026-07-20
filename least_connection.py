"""
============================================================
LOAD BALANCER - LEAST CONNECTION ALGORITHM (S3)
Implementasi Load Balancing VoIP berbasis Python
VERSI REVISI
============================================================
Peneliti  : Muh Burhanudin Zam Zami (221344017)
Algoritma : Least Connection (S3)
VM        : VM Load Balancer (192.168.1.202)
Backend   : VM3 Asterisk B1 (192.168.1.203)
            VM4 Asterisk B2 (192.168.1.204)
============================================================

KONSEP LEAST CONNECTION:
  - Setiap INVITE masuk -> cek jumlah panggilan aktif di B1 dan B2
  - Backend dengan panggilan aktif PALING SEDIKIT dipilih
  - Saat INVITE diterima    : active_calls[backend] += 1
  - Saat BYE/CANCEL diterima: active_calls[backend] -= 1
  - Keputusan dibuat REAL-TIME berdasarkan kondisi aktual

FORMULA:
  Pilih backend j dimana:
  active_calls(j) = MIN { active_calls(i) }
  untuk semua backend i yang berstatus UP

PERBEDAAN DENGAN ROUND-ROBIN (S2):
  Round-Robin -> pilih bergiliran tanpa peduli kondisi server
  Least Conn  -> selalu pilih yang paling ringan bebannya

ALUR PAKET (SAMA SEPERTI round_robin.py):
  SIPp --INVITE--> LB --pilih backend--> Asterisk
       <--100 OK--    <--100 OK---------
       <--200 OK--    <--200 OK---------
       --ACK------>   --ACK------------>
       (RTP langsung antara SIPp dan Asterisk, tidak lewat LB)
       --BYE------>   --BYE------------>
       <--200 OK--    <--200 OK---------

============================================================
CATATAN REVISI (dibanding versi sebelumnya):
============================================================
1. RACE CONDITION saat INVITE sudah diperbaiki.
   Sebelumnya: pemilihan backend (select_backend_leastconn) dan
   penambahan active_calls (_increment_calls) dilakukan dalam DUA
   kali "with self.backend_lock" yang terpisah. Di antara kedua
   lock itu, worker thread lain bisa saja ikut membaca active_calls
   yang belum ter-update, sehingga dua panggilan sekaligus bisa
   "dianggap" masuk ke backend yang sama-sama paling kosong.
   Sekarang: seleksi + reservasi (increment) digabung menjadi SATU
   operasi atomik di dalam satu blok lock -> select_and_reserve_backend().

2. TIE-BREAK saat active_calls sama sekarang tidak selalu jatuh ke B1.
   Sebelumnya min() akan selalu mengambil backend pertama yang
   ditemukan saat nilai active_calls-nya sama (karena urutan dict),
   jadi B1 selalu "diuntungkan" tiap kali seri. Sekarang dipakai
   round-robin pointer (_rr_pointer) khusus untuk kasus seri, jadi
   distribusi saat active_calls sama akan bergantian B1/B2.

3. SESSION CLEANUP: call_id_map dan client_addr_map sekarang benar-
   benar dibersihkan setelah dialog SIP selesai (setelah balasan
   200 OK untuk BYE/CANCEL diteruskan ke SIPp), bukan dibiarkan
   menumpuk di memori (kode lama hanya punya "pass" kosong di
   listener, sehingga peta sesi bocor/leak selama LB berjalan lama).

4. Komentar dirapikan agar sesuai dengan apa yang benar-benar
   dilakukan kode, dan penomoran langkah pada docstring diperjelas.

Semua alur kerja, format log CSV, dan kompatibilitas dengan
dashboard TIDAK berubah.
============================================================
"""

import socket
import time
import threading
import csv
import logging
import sys
from collections import defaultdict
from datetime import datetime
from queue import Queue, Full

# ============================================================
# LOGGING - Tulis ke file dan terminal sekaligus
# ============================================================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/home/burhan/ta_voip/lb_lc.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


# ============================================================
# KONFIGURASI BACKEND DAN LOAD BALANCER
# ============================================================

# Daftar backend server Asterisk
# PENTING: IP harus sesuai dengan topologi VM kamu
BACKENDS = {
    "B1": {
        "ip"           : "10.187.146.203",   # IP VM Backend 1 (Asterisk)
        "port"         : 5060,
        "status"       : "UP",
        "active_calls" : 0,                 # Jumlah panggilan aktif saat ini
        "total_calls"  : 0,                 # Total panggilan yang pernah diterima
    },
    "B2": {
        "ip"           : "10.187.146.204",   # IP VM Backend 2 (Asterisk)
        "port"         : 5060,
        "status"       : "UP",
        "active_calls" : 0,
        "total_calls"  : 0,
    },
}

LB_CONFIG = {
    "listen_ip"   : "0.0.0.0",
    "listen_port" : 5060,
    "num_workers" : 8,
    "log_file"    : "/home/burhan/ta_voip/lb_log.csv",   # Sama formatnya dengan round_robin.py
}


# ============================================================
# KELAS UTAMA LOAD BALANCER LEAST CONNECTION
# ============================================================

class LeastConnectionLB:

    def __init__(self, backends, config):
        self.backends      = backends           # Dict backend
        self.config        = config

        # Lock untuk akses thread-safe ke data backend
        # Dibutuhkan karena banyak worker thread berjalan bersamaan
        self.backend_lock  = threading.Lock()

        # Lock untuk penulisan log CSV
        self.log_lock      = threading.Lock()

        # Statistik penggunaan
        self.stats = {
            'total_packets'    : 0,
            'forwarded_packets': 0,
            'failed_packets'   : 0,
            'forwarding_times' : [],
            'sip_methods'      : defaultdict(int),
        }
        self.stats_lock = threading.Lock()

        # Socket utama - menerima paket SIP dari SIPp di port 5060
        self.client_socket = None

        # Socket per backend - satu socket khusus untuk komunikasi ke masing-masing backend
        # Dibuat persistent (tidak dibuat ulang per paket) agar balasan backend bisa diterima
        self.backend_sockets = {}

        # Peta sesi:
        #   call_id_map    : call_id -> backend_id (backend mana yang menangani sesi ini)
        #   client_addr_map: call_id -> alamat SIPp (untuk kirim balik balasan)
        self.call_id_map     = {}
        self.client_addr_map = {}

        # REVISI: set call_id yang sedang menunggu balasan penutup dialog
        # (setelah BYE/CANCEL diteruskan). Dipakai reply listener untuk
        # tahu kapan sesi boleh dihapus dari memori.
        self.pending_close    = set()
        self.session_lock     = threading.Lock()

        # REVISI: pointer round-robin, khusus dipakai sebagai tie-break
        # saat dua atau lebih backend punya active_calls yang sama persis.
        self._rr_pointer = -1

        # Antrian kerja - paket masuk dimasukkan sini, worker thread yang mengerjakan
        self.work_queue     = Queue(maxsize=1000)
        self.worker_threads = []

        # Inisialisasi file log dan socket backend
        self._init_log_file()
        self._init_backend_sockets()

        logger.info("Least Connection LB siap (%d backend)", len(self.backends))
        self._print_backend_status()

    # ----------------------------------------------------------
    # INISIALISASI SOCKET BACKEND
    # ----------------------------------------------------------
    def _init_backend_sockets(self):
        """
        Membuat satu UDP socket PERMANEN per backend.

        KENAPA TIDAK BUAT SOCKET BARU PER PAKET?
        Kalau socket dibuat baru setiap pengiriman (seperti di versi lama):
          - Port pengirim berubah setiap paket
          - Asterisk membalas ke port yang sudah ditutup
          - Balasan tidak pernah sampai ke SIPp -> call timeout

        Dengan socket permanen yang di-bind ke port tetap:
          - Asterisk selalu tahu ke port mana harus membalas
          - Thread reply_listener bisa membaca balasan itu
          - Balasan diteruskan ke SIPp dengan benar
        """
        for backend_id in self.backends:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 262144)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 262144)

            # Bind ke port acak - OS yang memilih port yang tersedia
            # Hasilnya bisa dicek dengan sock.getsockname()[1]
            sock.bind(("0.0.0.0", 0))

            self.backend_sockets[backend_id] = sock
            logger.info("[INIT] Socket %s terikat di port %d",
                        backend_id, sock.getsockname()[1])

    def _init_log_file(self):
        """
        Tulis header CSV saat program pertama dijalankan.
        Format sama dengan round_robin.py agar dashboard bisa membacanya.
        """
        with open(self.config['log_file'], 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                'timestamp', 'sip_method', 'backend_id',
                'backend_ip', 'forward_ms',
                'active_calls_b1', 'active_calls_b2',  # Tambahan khusus LC
                'algo'                                   # Penanda algoritma
            ])

    # ----------------------------------------------------------
    # ALGORITMA INTI: LEAST CONNECTION SELECTOR
    # ----------------------------------------------------------
    def _pick_backend_id(self, available):
        """
        Helper murni untuk menentukan backend_id terpilih dari kumpulan
        backend yang UP ('available'). Dipakai oleh select_backend_leastconn
        (peek, tanpa reservasi) dan select_and_reserve_backend (atomik).

        Cara kerja:
          1. Cari nilai active_calls paling kecil di antara backend UP
          2. Kumpulkan semua backend yang active_calls-nya sama dengan
             nilai minimum itu (bisa lebih dari satu -> kondisi seri)
          3. Jika hanya satu kandidat -> langsung pilih itu
          4. Jika seri -> gunakan round-robin pointer supaya backend
             yang menang seri bergantian, tidak selalu backend pertama
        """
        min_calls = min(b["active_calls"] for b in available.values())
        candidates = [
            bid for bid, b in available.items()
            if b["active_calls"] == min_calls
        ]

        if len(candidates) == 1:
            return candidates[0]

        # REVISI: tie-break round-robin, bukan selalu ambil kandidat pertama
        self._rr_pointer = (self._rr_pointer + 1) % len(candidates)
        return candidates[self._rr_pointer]

    def select_backend_leastconn(self):
        """
        Versi "peek": hanya MEMBACA kondisi backend dan menentukan siapa
        yang akan dipilih, TANPA mengubah active_calls/total_calls.

        Dipakai untuk:
          - Fallback method selain INVITE/BYE/CANCEL yang belum punya
            sesi (mis. OPTIONS, REGISTER) -> tidak boleh menambah
            active_calls karena bukan awal panggilan baru
          - Keperluan lain yang hanya butuh tahu "siapa yang akan
            dipilih" tanpa efek samping

        Untuk INVITE (awal panggilan baru), JANGAN pakai method ini.
        Gunakan select_and_reserve_backend() supaya seleksi dan
        penambahan active_calls terjadi atomik (lihat penjelasan di
        bawah).
        """
        with self.backend_lock:
            available = {
                bid: b for bid, b in self.backends.items()
                if b["status"] == "UP"
            }
            if not available:
                return None, None, "Semua backend DOWN"

            selected_id = self._pick_backend_id(available)
            selected = self.backends[selected_id]

            conn_info = " | ".join([
                f"{bid}={b['active_calls']} aktif"
                for bid, b in self.backends.items()
            ])
            reason = (
                f"LC (peek): {selected_id} dipilih "
                f"(active_calls={selected['active_calls']}) "
                f"[{conn_info}]"
            )
            return selected_id, selected, reason

    def select_and_reserve_backend(self):
        """
        INTI ALGORITMA LEAST CONNECTION UNTUK INVITE (SESI BARU)

        REVISI PENTING: seleksi backend dan penambahan active_calls
        dilakukan dalam SATU blok lock yang sama (atomik), bukan dua
        lock terpisah seperti versi sebelumnya.

        Kenapa ini penting (race condition di versi lama):
          Worker thread 1 baca B1=3, B2=1 -> mau pilih B2
          Worker thread 2 baca B1=3, B2=1 -> mau pilih B2 (bersamaan,
            karena lock seleksi sudah dilepas sebelum increment jalan)
          Keduanya sama-sama menambah active_calls B2 setelahnya
          -> B2 menerima 2 panggilan baru padahal seharusnya cuma 1
             yang berhak, dan B1 yang harusnya kebagian jadi terlewat.

        Dengan versi ini:
          Seleksi backend dan "reservasi" (increment active_calls dan
          total_calls) terjadi sebelum lock dilepas, sehingga worker
          thread lain yang menyusul pasti membaca active_calls yang
          SUDAH ter-update -> tidak ada dua panggilan yang sama-sama
          menganggap diri mereka "yang pertama" ke backend paling kosong.

        Contoh kondisi dan keputusan:
          B1: 3 panggilan aktif, B2: 1 panggilan aktif -> pilih B2
          B1: 0 panggilan aktif, B2: 0 panggilan aktif -> seri, tie-break
          B1: 5 panggilan aktif, B2: 5 panggilan aktif -> seri, tie-break
          B1: DOWN,              B2: 2 panggilan aktif -> pilih B2 (satu-satunya UP)
        """
        with self.backend_lock:
            available = {
                bid: b for bid, b in self.backends.items()
                if b["status"] == "UP"
            }
            if not available:
                return None, None, "Semua backend DOWN"

            selected_id = self._pick_backend_id(available)
            selected = self.backends[selected_id]

            # Reservasi langsung di dalam lock yang sama -> atomik
            selected["active_calls"] += 1
            selected["total_calls"]  += 1

            conn_info = " | ".join([
                f"{bid}={b['active_calls']} aktif"
                for bid, b in self.backends.items()
            ])
            reason = (
                f"LC: {selected_id} dipilih & direservasi "
                f"(active_calls={selected['active_calls']}) "
                f"[{conn_info}]"
            )
            logger.info("[LC] %s active_calls: %d", selected_id, selected["active_calls"])

            return selected_id, selected, reason

    # ----------------------------------------------------------
    # MANAJEMEN KONEKSI AKTIF
    # ----------------------------------------------------------
    def _decrement_calls(self, backend_id):
        """
        Kurangi 1 dari active_calls backend saat sesi berakhir (BYE/CANCEL).
        Menggunakan max(0, ...) untuk mencegah nilai negatif jika ada
        ketidaksesuaian paket (misalnya BYE tanpa INVITE sebelumnya).
        """
        with self.backend_lock:
            if backend_id in self.backends:
                before = self.backends[backend_id]["active_calls"]
                self.backends[backend_id]["active_calls"] = max(
                    0, before - 1
                )
                logger.info(
                    "[LC] %s active_calls: %d -> %d",
                    backend_id, before,
                    self.backends[backend_id]["active_calls"]
                )

    # ----------------------------------------------------------
    # PARSER SIP - Baca Method dan Call-ID dari Paket
    # ----------------------------------------------------------
    def parse_sip_packet(self, data):
        """
        Membaca dua informasi penting dari paket SIP mentah (raw bytes):

        1. Method SIP: kata pertama di baris pertama
           Contoh: "INVITE sip:123@192.168.1.203 SIP/2.0" -> method = "INVITE"
           Untuk balasan dari Asterisk: "SIP/2.0 100 Trying" -> method = "SIP/2.0"

        2. Call-ID: header yang mengidentifikasi satu dialog SIP unik
           Contoh: "Call-ID: 1-17065@192.168.1.201" -> call_id = "1-17065@192.168.1.201"
           Digunakan sebagai kunci untuk session affinity
        """
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

    # ----------------------------------------------------------
    # FORWARD: SIPp -> Backend
    # ----------------------------------------------------------
    def forward_to_backend(self, packet, client_addr):
        """
        Fungsi utama yang dijalankan oleh worker thread untuk setiap paket masuk.

        LOGIKA SESSION AFFINITY:
        Dalam protokol SIP, satu panggilan terdiri dari beberapa pesan:
          INVITE -> 100 -> 200 -> ACK -> (RTP) -> BYE -> 200

        Semua pesan dalam SATU panggilan harus ke backend YANG SAMA.
        Caranya: gunakan Call-ID sebagai kunci untuk mengingat backend.

        Alur pengambilan keputusan:
          INVITE  -> select_and_reserve_backend() (atomik) -> simpan di call_id_map
          ACK     -> Cek call_id_map -> Gunakan backend yang sama dengan INVITE
          BYE     -> Cek call_id_map -> Gunakan backend yang sama -> kurangi
                     active_calls -> tandai call_id sebagai pending_close
          CANCEL  -> sama seperti BYE
        """
        start = time.time()
        try:
            method, call_id = self.parse_sip_packet(packet)

            # -- INVITE: Sesi Baru -> Jalankan Algoritma LC (atomik) --
            if method == "INVITE":
                backend_id, backend, reason = self.select_and_reserve_backend()

                if backend_id is None:
                    logger.error("[LC] Semua backend DOWN. Paket dibuang.")
                    with self.stats_lock:
                        self.stats['failed_packets'] += 1
                    return

                # Simpan pemetaan sesi agar ACK dan BYE bisa ke backend yang sama
                if call_id:
                    with self.session_lock:
                        self.call_id_map[call_id]     = backend_id
                        self.client_addr_map[call_id] = client_addr

                logger.info("[LC] INVITE %s -> %s | %s", call_id, backend_id, reason)

            # -- ACK/BYE/CANCEL/dll: Sesi Lama -> Ikuti Backend Sebelumnya --
            else:
                with self.session_lock:
                    backend_id = self.call_id_map.get(call_id)
                    if call_id and client_addr:
                        self.client_addr_map[call_id] = client_addr

                if backend_id is None:
                    # Tidak ada sesi yang cocok - bisa terjadi untuk OPTIONS atau REGISTER
                    # Gunakan LC selector versi "peek" sebagai fallback (tidak menambah active_calls)
                    backend_id, backend, _ = self.select_backend_leastconn()
                    if backend_id is None:
                        logger.warning("[LC] Tidak ada sesi untuk %s, backend DOWN", call_id)
                        return
                else:
                    backend = self.backends[backend_id]

                # Jika BYE atau CANCEL: sesi berakhir -> kurangi active_calls
                # dan tandai call_id ini sedang menunggu balasan penutup,
                # supaya nanti reply listener tahu kapan sesi boleh dihapus.
                if method in ("BYE", "CANCEL") and call_id:
                    self._decrement_calls(backend_id)
                    with self.session_lock:
                        self.pending_close.add(call_id)
                    logger.info("[LC] %s %s -> %s (sesi berakhir, menunggu balasan penutup)",
                                method, call_id, backend_id)

            # -- Ambil snapshot active_calls untuk dicatat ke log --
            with self.backend_lock:
                ac_b1 = self.backends.get("B1", {}).get("active_calls", 0)
                ac_b2 = self.backends.get("B2", {}).get("active_calls", 0)

            # -- Kirim paket ke backend yang dipilih --
            self.backend_sockets[backend_id].sendto(
                packet, (backend["ip"], backend["port"])
            )

            # Hitung waktu forwarding
            latency = (time.time() - start) * 1000

            # Catat ke CSV
            self._log_to_csv(method, backend_id, backend["ip"],
                             latency, ac_b1, ac_b2)

            # Update statistik
            with self.stats_lock:
                self.stats['total_packets']       += 1
                self.stats['forwarded_packets']   += 1
                self.stats['forwarding_times'].append(latency)
                self.stats['sip_methods'][method] += 1

            logger.info("[FORWARD] %s -> %s (%s) %.3fms | B1:%d B2:%d",
                        method, backend_id, backend["ip"],
                        latency, ac_b1, ac_b2)

        except Exception as e:
            logger.error("[FORWARD ERROR] %s", e)
            with self.stats_lock:
                self.stats['failed_packets'] += 1

    # ----------------------------------------------------------
    # REPLY LISTENER: Backend -> SIPp
    # ----------------------------------------------------------
    def _start_backend_reply_listener(self, backend_id, sock):
        """
        Thread yang berjalan terus-menerus untuk masing-masing backend.

        KENAPA DIBUTUHKAN?
        Setelah lb mengirim INVITE ke Asterisk, Asterisk akan membalas
        dengan 100 Trying, 200 OK, dsb. Balasan itu datang ke socket
        backend (backend_sockets[backend_id]).

        Tanpa listener ini:
          - Balasan masuk ke socket tapi tidak dibaca
          - SIPp tidak pernah menerima 100/200 OK
          - SIPp mengulang INVITE terus (retransmisi)
          - Setelah 5 detik (timer B): call timeout -> GAGAL

        Dengan listener ini:
          1. Balasan dari Asterisk datang ke backend_socket
          2. Listener membaca balasan (recvfrom)
          3. Cari alamat SIPp dari client_addr_map[call_id]
          4. Kirim balasan ke SIPp melalui client_socket
          5. SIPp menerima 100/200 OK -> call berhasil

        REVISI: setelah balasan untuk BYE/CANCEL diteruskan (call_id
        sudah ditandai pending_close oleh forward_to_backend), sesi
        BENAR-BENAR dihapus dari call_id_map, client_addr_map, dan
        pending_close. Versi sebelumnya hanya berisi 'pass' di sini,
        sehingga peta sesi terus menumpuk selama LB berjalan lama.
        """
        def listen():
            logger.info("[REPLY] Listener %s aktif di port %d",
                        backend_id, sock.getsockname()[1])
            while True:
                try:
                    # Tunggu balasan dari Asterisk
                    data, _ = sock.recvfrom(4096)
                    method, call_id = self.parse_sip_packet(data)

                    # Cari alamat SIPp yang harus menerima balasan ini
                    with self.session_lock:
                        client_addr = self.client_addr_map.get(call_id)

                    if client_addr and self.client_socket:
                        # Teruskan balasan ke SIPp
                        self.client_socket.sendto(data, client_addr)
                        logger.info("[REPLY] %s <- %s -> SIPp %s",
                                    method, backend_id, client_addr)
                    else:
                        logger.warning(
                            "[REPLY] Tidak ada client untuk "
                            "call_id=%s method=%s", call_id, method
                        )

                    # Bersihkan sesi dari memori setelah balasan penutup
                    # dialog (mis. 200 OK untuk BYE/CANCEL) diteruskan.
                    if method == "SIP/2.0" and call_id:
                        with self.session_lock:
                            if call_id in self.pending_close:
                                self.call_id_map.pop(call_id, None)
                                self.client_addr_map.pop(call_id, None)
                                self.pending_close.discard(call_id)
                                logger.info(
                                    "[SESSION] %s dibersihkan dari memori",
                                    call_id
                                )

                except Exception as e:
                    logger.error("[REPLY %s] Error: %s", backend_id, e)

        t = threading.Thread(
            target=listen,
            daemon=True,
            name=f"reply-{backend_id}"
        )
        t.start()

    # ----------------------------------------------------------
    # WORKER THREAD - Proses Paket dari Antrian
    # ----------------------------------------------------------
    def worker(self):
        """
        Worker thread mengambil paket dari work_queue dan memprosesnya.

        KENAPA PAKAI ANTRIAN + WORKER THREAD?
        Tanpa ini:
          main loop menerima paket -> proses (blocking) -> tunggu selesai
          -> paket berikutnya baru bisa diterima
          -> di load 50 panggilan, banyak paket yang menunggu terlalu lama

        Dengan antrian + 8 worker thread:
          main loop terima paket -> masuk antrian (cepat, non-blocking)
          -> 8 worker langsung proses paralel
          -> throughput jauh lebih tinggi
        """
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
            t = threading.Thread(
                target=self.worker,
                daemon=True,
                name=f"lc-worker-{i}"
            )
            t.start()
            self.worker_threads.append(t)
        logger.info("[WORKER] %d worker thread aktif",
                    self.config['num_workers'])

    # ----------------------------------------------------------
    # LOGGING CSV
    # ----------------------------------------------------------
    def _log_to_csv(self, method, backend_id, ip,
                    latency, ac_b1, ac_b2):
        """
        Tulis satu baris ke CSV per paket yang diproses.
        Format kompatibel dengan dashboard (kolom timestamp, sip_method,
        backend_id, backend_ip, forward_ms) plus tambahan kolom LC.
        """
        with self.log_lock:
            with open(self.config['log_file'], 'a', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    datetime.now().isoformat(),
                    method,
                    backend_id,
                    ip,
                    f"{latency:.3f}",
                    ac_b1,
                    ac_b2,
                    "least_connection"
                ])

    # ----------------------------------------------------------
    # MONITORING STATUS - Thread Background
    # ----------------------------------------------------------
    def _start_monitor(self, interval=10):
        """
        Thread background yang mencetak status backend setiap 'interval' detik.
        Berguna untuk memantau distribusi beban selama pengujian berlangsung.
        """
        def monitor():
            while True:
                time.sleep(interval)
                with self.backend_lock:
                    logger.info("=== STATUS BACKEND (Least Connection) ===")
                    for bid, b in self.backends.items():
                        bar = "#" * min(b["active_calls"], 20)
                        logger.info(
                            "  %s (%s) | Status: %s | "
                            "Aktif: %2d | Total: %4d | %s",
                            bid, b["ip"], b["status"],
                            b["active_calls"], b["total_calls"], bar
                        )
                with self.stats_lock:
                    logger.info(
                        "  Forwarded: %d | Failed: %d | "
                        "Avg latency: %.3f ms",
                        self.stats['forwarded_packets'],
                        self.stats['failed_packets'],
                        (sum(self.stats['forwarding_times']) /
                         len(self.stats['forwarding_times'])
                         if self.stats['forwarding_times'] else 0)
                    )

        t = threading.Thread(target=monitor, daemon=True, name="monitor")
        t.start()

    # ----------------------------------------------------------
    # MAIN LOOP - Program Utama
    # ----------------------------------------------------------
    def run(self):
        """
        Urutan startup yang benar:

        1. Jalankan worker thread (siap proses paket)
        2. Buat client_socket (socket utama, port 5060)
           HARUS dibuat sebelum reply_listener karena listener
           membutuhkan self.client_socket untuk kirim balik ke SIPp
        3. Jalankan reply_listener per backend
        4. Jalankan monitor thread
        5. Main loop: terima paket dari SIPp -> masukkan antrian
        """
        # Langkah 1: Worker thread
        self.start_workers()

        # Langkah 2: Socket utama
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.client_socket.setsockopt(
            socket.SOL_SOCKET, socket.SO_RCVBUF, 524288
        )
        self.client_socket.bind((
            self.config['listen_ip'],
            self.config['listen_port']
        ))
        logger.info("[LB] Mendengarkan di %s:%d",
                    self.config['listen_ip'],
                    self.config['listen_port'])

        # Langkah 3: Reply listener per backend
        for backend_id, sock in self.backend_sockets.items():
            self._start_backend_reply_listener(backend_id, sock)

        # Langkah 4: Monitor
        self._start_monitor(interval=10)

        logger.info("[LB] Least Connection LB siap. Menunggu paket SIP...")

        # Langkah 5: Main loop
        try:
            while True:
                packet, addr = self.client_socket.recvfrom(4096)
                try:
                    self.work_queue.put_nowait((packet, addr))
                except Full:
                    logger.warning(
                        "[QUEUE] Penuh - paket dari %s dibuang", addr
                    )

        except KeyboardInterrupt:
            logger.info("[LB] Dihentikan oleh user.")
            self._cleanup()

    # ----------------------------------------------------------
    # CLEANUP DAN STATISTIK AKHIR
    # ----------------------------------------------------------
    def _cleanup(self):
        """Tutup semua socket dan cetak statistik akhir saat program dihentikan."""
        self._print_final_stats()

        # Kirim sinyal stop ke worker thread
        for _ in self.worker_threads:
            self.work_queue.put(None)

        if self.client_socket:
            self.client_socket.close()

        for sock in self.backend_sockets.values():
            sock.close()

    def _print_final_stats(self):
        logger.info("=" * 50)
        logger.info("=== STATISTIK AKHIR (Least Connection) ===")
        logger.info("=" * 50)

        with self.stats_lock:
            logger.info("Total paket      : %d",
                        self.stats['total_packets'])
            logger.info("Berhasil dikirim : %d",
                        self.stats['forwarded_packets'])
            logger.info("Gagal            : %d",
                        self.stats['failed_packets'])

            times = self.stats['forwarding_times']
            if times:
                logger.info("Latency rata-rata: %.3f ms",
                            sum(times) / len(times))
                logger.info("Latency maks     : %.3f ms", max(times))

            logger.info("Metode SIP:")
            for method, count in self.stats['sip_methods'].items():
                logger.info("  %-10s: %d", method, count)

        with self.backend_lock:
            logger.info("Distribusi routing:")
            total = sum(b["total_calls"] for b in self.backends.values())
            for bid, b in self.backends.items():
                pct = (b["total_calls"] / total * 100) if total else 0
                logger.info(
                    "  %s: %d panggilan (%.1f%%)",
                    bid, b["total_calls"], pct
                )

    def _print_backend_status(self):
        logger.info("Backend terdaftar:")
        for bid, b in self.backends.items():
            logger.info("  %s -> %s:%d [%s]",
                        bid, b["ip"], b["port"], b["status"])


# ============================================================
# ENTRY POINT
# ============================================================

def main():
    lb = LeastConnectionLB(BACKENDS, LB_CONFIG)
    lb.run()


if __name__ == "__main__":
    main()
