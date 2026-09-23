# Panduan Deploy WP-SecOps ke Ubuntu Server (Production)

Dokumen ini menjelaskan langkah demi langkah untuk melakukan deployment **WP-SecOps** pada server Ubuntu (20.04 / 22.04 / 24.04 LTS) agar berjalan sebagai layanan latar belakang yang tangguh (*production-ready*).

---

## Arsitektur Deployment

- **Web Server & Reverse Proxy**: Nginx (Port 80/443 dengan SSL/TLS)
- **WSGI Application Server**: Gunicorn (menjalankan Flask di `127.0.0.1:5000`)
- **Background Worker**: Celery Worker (dikelola via `systemd`)
- **Message Broker & Result Store**: Redis Server (`redis://127.0.0.1:6379/0`)
- **Database**: SQLite (default di `instance/wpsecops.db`)
- **Scanner Engines**: WhatWeb, WPScan, Nuclei, Hardening Runner (Python)

---

## 1. Persiapan Server & Paket Sistem

Hubungkan ke server Ubuntu Anda via SSH, kemudian perbarui repositori dan instal paket inti:

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3 python3-pip python3-venv git curl wget unzip \
    build-essential redis-server nginx ufw
```

Pastikan Redis sudah aktif:
```bash
sudo systemctl enable --now redis-server
sudo systemctl status redis-server --no-pager
```

---

## 2. Instalasi Mesin Pemindai (Scanner Tools)

WP-SecOps menggunakan 4 fase pemindaian sekuensial. Jalankan instalasi untuk masing-masing alat:

### Fase 1: WhatWeb
```bash
sudo apt install -y whatweb
whatweb --version
```

### Fase 2: WPScan
WPScan membutuhkan runtime Ruby dan pustaka kompilasi native:
```bash
sudo apt install -y ruby ruby-dev zlib1g-dev liblzma-dev libsqlite3-dev libcurl4-openssl-dev
sudo gem install wpscan
wpscan --version
```

### Fase 3: Nuclei & Template
Unduh binary Linux resmi dari ProjectDiscovery:
```bash
NUCLEI_VER="3.3.0"
wget https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VER}/nuclei_${NUCLEI_VER}_linux_amd64.zip
unzip nuclei_${NUCLEI_VER}_linux_amd64.zip
sudo mv nuclei /usr/local/bin/
rm nuclei_${NUCLEI_VER}_linux_amd64.zip README.md LICENSE.md

# Unduh template default Nuclei
nuclei -update-templates
nuclei -version
```

### Fase 4: Hardening Runner
Modul ini bawaan Python (`requests`). Akan terpasang otomatis saat instalasi `requirements.txt`.

---

## 3. Clone Repository & Siapkan Virtual Environment

Sebaiknya letakkan aplikasi di direktori `/var/www/wpsecops` (atau folder home user server Anda):

```bash
# Buat direktori dan atur kepemilikan user aktif (misal user: ubuntu)
sudo mkdir -p /var/www/wpsecops
sudo chown -R $USER:$USER /var/www/wpsecops

# Clone repository
git clone https://github.com/Antihero25Dev/wpsecops.git /var/www/wpsecops
cd /var/www/wpsecops

# Buat virtual environment
python3 -m venv venv
source venv/bin/activate

# Upgrade pip & install dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

---

## 4. Konfigurasi Environment (`.env`) & Inisialisasi DB

Salin file contoh konfigurasi dan atur nilainya:

```bash
cp env.example .env
nano .env
```

Sesuaikan parameter penting berikut di dalam file `.env`:
```ini
# Generate secret key unik: python3 -c 'import secrets; print(secrets.token_hex(32))'
FLASK_SECRET_KEY=ganti_dengan_random_string_panjang_dan_rahasia
FLASK_ENV=production

# Database (default SQLite)
DATABASE_URL=sqlite:///wpsecops.db

# Celery Redis Broker
CELERY_BROKER_URL=redis://127.0.0.1:6379/0
CELERY_RESULT_BACKEND=redis://127.0.0.1:6379/0
CELERY_TASK_ALWAYS_EAGER=False

# API Key untuk Analisis Kerentanan AI (Pilih salah satu atau keduanya)
VULN_ANALYZER_PROVIDER=gemini
GEMINI_API_KEY=AIzaSy...
GEMINI_MODEL=gemini-3.5-flash

# Opsional: Anthropic Claude
# ANTHROPIC_API_KEY=sk-ant-...
# ANTHROPIC_MODEL=claude-sonnet-5
```

Inisialisasi database SQLite dan buat akun admin default:
```bash
python3 -c "from app import create_app; create_app()"
```
> [!IMPORTANT]
> Akun admin default yang terbuat adalah **`admin`** dengan password **`admin123`**. Segera ganti password setelah pertama kali login melalui dashboard.

Pastikan direktori database dan cache dapat ditulis oleh user:
```bash
mkdir -p instance ai_cache
chmod 755 instance ai_cache
```

---

## 5. Konfigurasi Layanan Latar Belakang (Systemd)

Gunakan `systemd` agar Flask (Gunicorn) dan Celery Worker berjalan otomatis saat server booting dan otomatis me-restart jika terjadi error.

*(Ganti `ubuntu` dengan username Linux yang menjalankan aplikasi jika berbeda)*

### A. Service Web Gunicorn (`/etc/systemd/system/wpsecops-web.service`)
```bash
sudo nano /etc/systemd/system/wpsecops-web.service
```

Isi dengan:
```ini
[Unit]
Description=WP-SecOps Gunicorn Web Service
After=network.target redis-server.service

[Service]
User=ubuntu
Group=ubuntu
WorkingDirectory=/var/www/wpsecops
Environment="PATH=/var/www/wpsecops/venv/bin:/usr/local/bin:/usr/bin:/bin"
ExecStart=/var/www/wpsecops/venv/bin/gunicorn \
    --workers 3 \
    --bind 127.0.0.1:5000 \
    --access-logfile /var/www/wpsecops/access.log \
    --error-logfile /var/www/wpsecops/error.log \
    app:app

Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### B. Service Celery Worker (`/etc/systemd/system/wpsecops-celery.service`)
```bash
sudo nano /etc/systemd/system/wpsecops-celery.service
```

Isi dengan:
```ini
[Unit]
Description=WP-SecOps Celery Worker Service
After=network.target redis-server.service

[Service]
User=ubuntu
Group=ubuntu
WorkingDirectory=/var/www/wpsecops
Environment="PATH=/var/www/wpsecops/venv/bin:/usr/local/bin:/usr/bin:/bin"
ExecStart=/var/www/wpsecops/venv/bin/celery \
    -A tasks.celery_app worker \
    --loglevel=info \
    --concurrency=2

Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### Aktifkan dan Jalankan Layanan:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now wpsecops-web
sudo systemctl enable --now wpsecops-celery

# Cek status layanan
sudo systemctl status wpsecops-web --no-pager
sudo systemctl status wpsecops-celery --no-pager
```

---

## 6. Konfigurasi Nginx & Reverse Proxy

Buat file konfigurasi Nginx untuk mengarahkan trafik web ke Gunicorn:

```bash
sudo nano /etc/nginx/sites-available/wpsecops
```

Isi konfigurasi (ganti `domainanda.com` dengan domain atau IP Public server Anda):
```nginx
server {
    listen 80;
    server_name domainanda.com; # atau isi dengan IP Public server

    client_max_body_size 50M;

    # Static assets langsung dilayani Nginx untuk performa maksimal
    location /static/ {
        alias /var/www/wpsecops/static/;
        expires 30d;
        access_log off;
    }

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Timeout yang cukup untuk streaming log & long polling
        proxy_read_timeout 300s;
        proxy_connect_timeout 75s;
    }
}
```

Aktifkan konfigurasi dan uji sintaks Nginx:
```bash
sudo ln -s /etc/nginx/sites-available/wpsecops /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t
sudo systemctl restart nginx
```

---

## 7. Pengaturan Firewall (UFW)

Amankan port server dengan UFW:
```bash
sudo ufw allow OpenSSH
sudo ufw allow 'Nginx Full'
sudo ufw enable
sudo ufw status
```

---

## 8. Pasang SSL/TLS Gratis (Let's Encrypt / Certbot)

Jika Anda menggunakan domain, aktifkan HTTPS secara otomatis:

```bash
sudo apt install -y certbot python3-certbot-nginx
sudo certbot --nginx -d domainanda.com
```

Sertifikat akan otomatis diperpanjang sebelum masa berlakunya habis.

---

## 9. Perintah Pemeliharaan (Maintenance Cheatsheet)

| Aksi | Perintah |
| :--- | :--- |
| **Melihat log Web (Flask/Gunicorn)** | `sudo journalctl -u wpsecops-web -f` |
| **Melihat log Celery Worker (Scan Pipeline)** | `sudo journalctl -u wpsecops-celery -f` |
| **Restart Web App** | `sudo systemctl restart wpsecops-web` |
| **Restart Background Worker** | `sudo systemctl restart wpsecops-celery` |
| **Update Kode Aplikasi Terbaru** | `cd /var/www/wpsecops && git pull origin main && sudo systemctl restart wpsecops-web wpsecops-celery` |
| **Update Template Nuclei** | `nuclei -update-templates` |
