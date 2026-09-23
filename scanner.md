# Panduan Instalasi Security Scanner di Ubuntu / WSL

Dokumen ini menjelaskan langkah-langkah untuk menginstal dan menyiapkan 4 fase mesin pemindai keamanan WP-SecOps:
1. **WhatWeb** (FASE 1: Identifikasi Teknologi & CMS)
2. **WPScan** (FASE 2: WordPress Fingerprinting + Enumerasi Tanpa API)
3. **Nuclei** (FASE 3: WordPress Exposure Detection)
4. **Hardening Checker** (FASE 4: Audit Hardening Eksternal Berbasis Python)

---

## 1. FASE 1: Panduan Instalasi WhatWeb

WhatWeb digunakan untuk mendeteksi web server, versi PHP, library JavaScript, dan CMS.

### Langkah-langkah:
1. Update repositori paket dan instal WhatWeb:
   ```bash
   sudo apt update
   sudo apt install -y whatweb
   ```
2. Alternatif via Ruby Gems (jika ingin versi gem):
   ```bash
   sudo gem install whatweb
   ```
3. Verifikasi instalasi:
   ```bash
   whatweb --version
   ```

---

## 2. FASE 2: Panduan Instalasi WPScan

WPScan ditulis dengan Ruby dan digunakan untuk mengenali tema, plugin aktif/kadaluwarsa, dan username tanpa memerlukan API token.

### Langkah-langkah:
1. Pastikan paket sistem terbaru dan instal dependensi Ruby:
   ```bash
   sudo apt update
   sudo apt install -y ruby ruby-dev build-essential patch zlib1g-dev liblzma-dev libsqlite3-dev libcurl4-openssl-dev
   ```
2. Instal WPScan via Ruby Gems:
   ```bash
   sudo gem install wpscan
   ```
3. Verifikasi instalasi:
   ```bash
   wpscan --version
   ```

---

## 3. FASE 3: Panduan Instalasi Nuclei

Nuclei ditulis menggunakan bahasa Go. Cara tercepat adalah mengunduh prebuilt binary untuk Linux.

### Langkah-langkah:
1. Instal utilitas `wget` dan `unzip`:
   ```bash
   sudo apt update
   sudo apt install -y wget unzip
   ```
2. Unduh rilis binary Linux terbaru dari GitHub (contoh versi `3.3.0` arsitektur `amd64`):
   ```bash
   wget https://github.com/projectdiscovery/nuclei/releases/download/v3.3.0/nuclei_3.3.0_linux_amd64.zip
   ```
3. Ekstrak dan pindahkan binary ke PATH sistem:
   ```bash
   unzip nuclei_3.3.0_linux_amd64.zip
   sudo mv nuclei /usr/local/bin/
   rm nuclei_3.3.0_linux_amd64.zip README.md LICENSE.md
   ```
4. Unduh atau perbarui template Nuclei:
   ```bash
   nuclei -update-templates
   ```
5. Verifikasi instalasi:
   ```bash
   nuclei -version
   ```

---

## 4. FASE 4: WordPress Hardening Checker

Modul ini **terintegrasi langsung** di dalam sistem WP-SecOps (`services/hardening_runner.py`) dan berjalan menggunakan HTTP request murni via modul Python `requests`.

Tidak diperlukan instalasi binary CLI tambahan untuk Fase 4. Cukup pastikan dependensi Python terpasang di virtual environment:
```bash
pip install requests
```
Semua 13 parameter pengecekan hardening (HTTPS, wp-config, XML-RPC, security headers, file backup, dsb.) akan berjalan otomatis.
