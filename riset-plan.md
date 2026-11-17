# Rencana Eksekusi Penelitian WP-SecOps

> **Judul:** *Rancang Bangun WP-SecOps: Platform Centralized Vulnerability Management Berbasis Async IO untuk Otomatisasi Audit Keamanan WordPress*
> **Dashboard Hasil:** `http://127.0.0.1:5000/riset` (5 tabel komparatif + Export CSV / Copy Markdown)

---

## 1. Tujuan Eksperimen (Data Bab 4)

1. Membuktikan peningkatan kecepatan (*speedup* & efisiensi waktu) eksekusi **Async IO Parallel** dibanding **Sequential** (**Tabel 1**).
2. Membuktikan peningkatan cakupan deteksi pipeline 4 fase (*WhatWeb + WPScan + Nuclei + Hardening*) dibanding single-tool (**Tabel 2**).
3. Mengukur efektivitas algoritma korelasi *confidence* (`Cross-verified`, `Confirmed`, `Likely`, `Unconfirmed`) (**Tabel 3**).
4. Membandingkan postur keamanan otomatis lintas 3 generasi WordPress (**Tabel 4**).
5. Menganalisis *trade-off* mode deteksi `passive` vs `mixed` vs `aggressive` (**Tabel 5**).

---

## 2. Persiapan Lingkungan Lab

### 2.1 Jalankan Target WordPress (`docker-compose.yml`)
Rekomendasi: **10 target** (atau minimal 6 target: 2 per grup jika RAM terbatas).

| Grup | Kontainer | Port | Versi WP | Skenario Kondisi Target (disarankan) |
|---|---|---|---|---|
| **Grup A (Legacy)** | `wp1` | `8081` | WP 4.6 | Default + plugin lama/rentan + `readme.html` terbuka |
| | `wp2` | `8082` | WP 4.9 | Default + directory listing aktif + user `admin` |
| | `wp3` | `8083` | WP 5.0 | Default + file backup dummy (`wp-config.php.bak`) |
| **Grup B (Mid-Era)** | `wp4` | `8084` | WP 5.4 | 1–2 plugin populer outdated |
| | `wp5` | `8085` | WP 5.8 | `xmlrpc.php` aktif + REST API users terbuka |
| | `wp6` | `8086` | WP 6.0 | Campuran plugin aktif + tema default |
| | `wp7` | `8087` | WP 6.2 | Sebagian di-hardening (tanpa `readme.html`) |
| **Grup C (Modern)** | `wp8` | `8088` | WP 6.4 | Plugin up-to-date, konfigurasi standar |
| | `wp9` | `8089` | WP 6.5 | Security headers ditambahkan |
| | `wp10` | `8090` | Latest | **Baseline hardened** (kontrol hijau) |

Perintah (di environment yang memiliki Docker):
```bash
# Jalankan semua (atau per grup: docker compose up -d db1 wp1 db2 wp2 ...)
docker compose up -d
```
Selesaikan wizard instalasi awal WordPress di tiap port (`http://localhost:8081` s/d `8090`).

### 2.2 Pastikan Layanan WP-SecOps Aktif
- Cek `/system-status`: **WhatWeb**, **WPScan**, **Nuclei + Templates**, **Celery Worker & Redis** berstatus siap/aktif.
- Tambahkan seluruh target ke halaman **Servers** (`http://localhost:8081` s/d `http://localhost:8090`).

---

## 3. Skenario Pengambilan Data

### Tahap 1 — Benchmark *Sequential* vs *Async IO Parallel* (Tabel 1)
1. Buka `/riset`.
2. Pilih minimal **3 target representatif** (1 Grup A, 1 Grup B, 1 Grup C — atau seluruh 10 target jika waktu mencukupi).
3. Klik **"Run Pair Benchmark (Seq vs Parallel)"** pada masing-masing target tersebut.
   - Sistem akan menjalankan 1× `sequential` lalu 1× `parallel` secara bergantian agar tidak saling berebut CPU/jaringan.
4. Catat nilai `T_seq`, `T_par`, `Speedup`, dan `Efisiensi (%)`.

### Tahap 2 — Audit Penuh Lintas Generasi (Tabel 2, 3, 4)
1. Buka halaman **Servers**, pilih seluruh target yang belum di-scan (atau gunakan **Bulk Scan** mode `passive`).
2. Pastikan seluruh target berstatus `scanned`.
3. Buka `/riset` — **Tabel 2, Tabel 3, dan Tabel 4** akan terisi otomatis dari hasil scan terbaru tiap target.

### Tahap 3 — Perbandingan Mode Deteksi (Tabel 5)
1. Pilih **1–3 target yang sama** (disarankan dari Grup B yang punya beberapa plugin).
2. Jalankan scan masing-masing 1× dengan mode:
   - `passive` (sudah ada dari Tahap 2)
   - `mixed` (atur dari modal opsi scan di `/servers`)
   - `aggressive` (atur dari modal opsi scan di `/servers`)
3. Buka `/riset` dan amati **Tabel 5** (durasi WPScan, jumlah komponen, temuan/detik).

---

## 4. Ekspor & Dokumentasi Hasil

1. Pada `/riset`, klik **Export CSV** untuk menyimpan seluruh tabel ke folder `penelitian/` (untuk lampiran / grafik di Excel/Python).
2. Klik **Copy Markdown** untuk menempel tabel langsung ke draf Bab 4.
3. Simpan screenshot halaman:
   - `/servers` (tampilan kartu warna merah/kuning/hijau setelah 10 target selesai)
   - `/history/<id>` (detail korelasi `Cross-verified`/`Confirmed` + rekomendasi AI)
   - `/history/<id>/workflow` (timeline 4 fase)
   - `/riset` (5 tabel komparatif)

---

## 5. Checklist Sebelum Penulisan Bab 4

- [ ] Seluruh target (`wp1`–`wp10` atau minimal 6 target) berstatus `scanned`
- [ ] Minimal 3 target memiliki pasangan data `sequential` dan `parallel` (Tabel 1 tanpa tanda `*`)
- [ ] Minimal 1 target diuji di ketiga mode `passive`, `mixed`, `aggressive` (Tabel 5 terisi penuh)
- [ ] Seluruh 5 CSV dari `/riset` sudah diekspor dan di-backup
