# Load Balancer VoIP (SIP) — Round-Robin vs Least Connection

Tugas Akhir: Implementasi dan analisis performa Load Balancer untuk trafik SIP/VoIP
menggunakan dua algoritma — **Round-Robin** dan **Least Connection** — dilengkapi
dashboard monitoring QoS realtime dan skrip analisis QoS dari file capture (.pcap).

**Peneliti:** Muh Burhanudin Zam Zami (221344017)

## Struktur Proyek

```
.
├── load_balancer/
│   ├── round_robin.py        # Load Balancer - algoritma Round-Robin (S2)
│   └── least_connection.py   # Load Balancer - algoritma Least Connection (S3)
├── dashboard/
│   ├── app.py                 # Server Flask + SSE untuk dashboard monitoring
│   └── templates/
│       └── dashboard.html     # Tampilan dashboard QoS realtime
├── analysis/
│   └── hitung_qos.py          # Skrip analisis QoS (delay, jitter, loss, throughput) dari .pcap
├── requirements.txt
├── .gitignore
└── README.md
```

> Catatan: seluruh isi/logika program **tidak diubah** dari versi asli — hanya dirapikan
> (indentasi, struktur folder, encoding karakter) agar siap di-push ke GitHub.

## Kebutuhan (Requirements)

- Python 3.8+
- `tshark` (Wireshark CLI) terpasang di sistem — dibutuhkan oleh `analysis/hitung_qos.py`
- Paket Python pada `requirements.txt`

Instal dependensi Python:

```bash
pip install -r requirements.txt
```

## Konfigurasi

Sebelum menjalankan, sesuaikan variabel berikut di masing-masing file dengan topologi VM Anda:

- `load_balancer/round_robin.py` dan `load_balancer/least_connection.py`:
  - `BACKENDS` — IP & port backend Asterisk (B1, B2)
  - `LB_CONFIG` — IP/port listen LB, jumlah worker, path file log
- `dashboard/app.py`:
  - `LB_LOG`, `LB_LC_LOG`, `QOS_FILE` — path file log yang sama dengan konfigurasi di atas

## Cara Menjalankan

1. Jalankan salah satu Load Balancer (pilih salah satu algoritma untuk skenario pengujian):
   ```bash
   python3 load_balancer/round_robin.py
   # atau
   python3 load_balancer/least_connection.py
   ```
2. Jalankan dashboard monitoring (di terminal terpisah):
   ```bash
   python3 dashboard/app.py
   ```
   Buka browser ke `http://<IP-LB>:5000`
3. Setelah pengujian trafik SIP selesai dan file `.pcap` sudah ditangkap, hitung QoS:
   ```bash
   python3 analysis/hitung_qos.py <path_ke_file.pcap> "<nama_skenario>" <beban_panggilan>
   ```
   Contoh:
   ```bash
   python3 analysis/hitung_qos.py /tmp/b1_s1_load10.pcap "S1-Baseline" 10
   ```

## Langkah Push ke GitHub

Ikuti langkah berikut agar hasil rapi dan tersusun di GitHub:

1. **Buat repository baru** di GitHub (jangan centang "Initialize with README" agar tidak konflik).

2. **Masuk ke folder proyek** ini di terminal lokal Anda:
   ```bash
   cd nama-folder-proyek
   ```

3. **Inisialisasi git** (jika belum):
   ```bash
   git init
   ```

4. **Cek isi `.gitignore`** sudah menyertakan file log/hasil pengujian (`*.log`, `*.csv`,
   `*.json`, `*.pcap`) agar tidak ikut ter-commit — file ini sudah disiapkan.

5. **Tambahkan seluruh file ke staging:**
   ```bash
   git add .
   ```

6. **Buat commit pertama:**
   ```bash
   git commit -m "Initial commit: Load Balancer VoIP (Round-Robin & Least Connection) + Dashboard QoS"
   ```

7. **Hubungkan ke repository GitHub** (ganti URL dengan milik Anda):
   ```bash
   git remote add origin https://github.com/<username>/<nama-repo>.git
   ```

8. **Set branch utama ke `main`** (jika perlu):
   ```bash
   git branch -M main
   ```

9. **Push ke GitHub:**
   ```bash
   git push -u origin main
   ```

10. **Verifikasi** — buka repository di GitHub dan pastikan struktur folder
    (`load_balancer/`, `dashboard/`, `analysis/`) tampil rapi sesuai daftar di atas.

### Update selanjutnya (setelah revisi kode)

```bash
git add .
git commit -m "Deskripsi singkat perubahan"
git push
```

## Catatan Konsistensi Data

`dashboard/app.py` membaca file log CSV yang sama (`lb_log.csv`) baik dari
`round_robin.py` maupun `least_connection.py`, sehingga dashboard dapat menampilkan
panel QoS yang identik untuk kedua algoritma dan memudahkan perbandingan hasil pengujian.
