#!/bin/bash

# Fungsi untuk menghentikan celery saat script dihentikan
cleanup() {
    echo "Menghentikan Celery worker..."
    if [ ! -z "$CELERY_PID" ]; then
        kill $CELERY_PID 2>/dev/null
    fi
    exit
}

# Hubungkan trap ke fungsi cleanup saat menerima signal SIGINT/SIGTERM (Ctrl+C)
trap cleanup SIGINT SIGTERM EXIT

# Aktifkan virtual environment di home Linux
if [ -f "$HOME/venv-wsl/bin/activate" ]; then
    source ~/venv-wsl/bin/activate
else
    echo "Virtual environment ~/venv-wsl tidak ditemukan!"
    echo "Silakan buat terlebih dahulu dengan: python3 -m venv ~/venv-wsl"
    exit 1
fi

# Pastikan redis-server berjalan
echo "Memeriksa Redis server..."
sudo service redis-server start

# Jalankan Celery worker di background dan simpan output ke log
echo "Menjalankan Celery worker di background (Log tersimpan di celery.log)..."
celery -A tasks.celery_app worker --loglevel=info > celery.log 2>&1 &
CELERY_PID=$!

# Jalankan aplikasi Flask di foreground
echo "Menjalankan Flask app..."
python3 app.py

