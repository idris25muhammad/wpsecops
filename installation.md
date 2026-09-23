# Panduan Instalasi & Menjalankan Projek di WSL Ubuntu

Dokumen ini menjelaskan langkah-langkah untuk menyiapkan dan menjalankan projek di lingkungan WSL (Windows Subsystem for Linux) Ubuntu.

## Prasyarat
Sebelum memulai, pastikan WSL Ubuntu sudah terpasang di sistem Windows Anda.

## Langkah-langkah

### 1. Masuk ke Direktori Projek di WSL
Buka terminal WSL Ubuntu Anda dan arahkan ke lokasi folder projek ini. Karena projek berada di Windows (`C:\idlabs\wpsecops`), WSL memetakan drive Windows tersebut di direktori `/mnt/c`:
```bash
cd /mnt/c/idlabs/wpsecops
```

### 2. Install Dependensi Sistem (Python, Redis, & Ruby)
Projek ini memerlukan Redis sebagai broker untuk Celery (diatur di `tasks.py`) dan WPScan CLI (yang dipanggil oleh `services/wpscan_runner.py`).

Jalankan perintah berikut di terminal WSL untuk menginstal seluruh kebutuhan sistem:
```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv redis-server ruby ruby-dev build-essential patch zlib1g-dev liblzma-dev libsqlite3-dev libcurl4-openssl-dev
```

### 3. Install WPScan CLI
Karena runner memanggil perintah `wpscan` secara langsung di sistem, instal WPScan melalui Ruby Gems:
```bash
sudo gem install wpscan
```
*Pastikan instalasi berhasil dengan memeriksa versi:*
```bash
wpscan --version
```

### 4. Jalankan Redis Server
Mulai layanan Redis server yang dibutuhkan oleh Celery broker:
```bash
sudo service redis-server start
```

### 5. Buat Python Virtual Environment Baru (venv)
> [!IMPORTANT]
> Jangan membuat virtual environment di dalam direktori Windows mount (`/mnt/c/...`) karena sistem file Windows (`drvfs`) sering mengalami masalah perizinan (permission denied/operation not permitted) dan performa yang lambat saat menginstal package Python.
> 
> Buatlah virtual environment di direktori home Linux asli Anda (`~/`):
```bash
python3 -m venv ~/venv-wsl
source ~/venv-wsl/bin/activate
```

### 6. Install Python Packages
Instal seluruh library Python yang tercantum di `requirements.txt`:
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### 7. Konfigurasi Environment (`.env`)
Salin file `env.example` menjadi `.env` jika belum ada, lalu sesuaikan konfigurasi Anda:
```bash
cp env.example .env
# Edit file .env sesuai kebutuhan
nano .env
```

### 8. Jalankan Celery Worker
Buka terminal WSL baru, aktifkan virtual environment, lalu jalankan worker Celery:
```bash
source ~/venv-wsl/bin/activate
celery -A tasks.celery_app worker --loglevel=info
```

### 9. Jalankan Flask App
Di terminal utama, aktifkan virtual environment dan jalankan aplikasi Flask:
```bash
source ~/venv-wsl/bin/activate
python app.py
```
Aplikasi akan berjalan di `http://127.0.0.1:5000` dan dapat diakses langsung dari browser Windows Anda di `http://localhost:5000`.
