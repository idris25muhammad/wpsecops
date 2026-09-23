#!/bin/bash

# Warna output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=========================================================="
echo "          SYSTEM & SERVICE CHECKER - WPSECOPS             "
echo "=========================================================="

# Fungsi untuk memeriksa command CLI
check_command() {
    local cmd_name=$1
    local install_hint=$2
    if command -v "$cmd_name" >/dev/null 2>&1; then
        echo -e "[${GREEN} OK ${NC}] $cmd_name sudah terinstall."
        return 0
    else
        echo -e "[${RED}FAIL${NC}] $cmd_name BELUM terinstall."
        if [ ! -z "$install_hint" ]; then
            echo -e "       -> Solusi: $install_hint"
        fi
        return 1
    fi
}

# 1. Periksa Python & Pip
check_command "python3" "sudo apt install python3 -y"
check_command "pip3" "sudo apt install python3-pip -y"

# 2. Periksa Ruby & RubyGems
check_command "ruby" "sudo apt install ruby ruby-dev -y"
check_command "gem" "sudo apt install ruby-dev -y"

# 3. Periksa Redis Server
check_command "redis-server" "sudo apt install redis-server -y"

if command -v redis-server >/dev/null 2>&1; then
    # Cek apakah running
    if service redis-server status >/dev/null 2>&1; then
        echo -e "[${GREEN} OK ${NC}] Redis-server service aktif/running."
    else
        echo -e "[${YELLOW}WARN${NC}] Redis-server service tidak aktif. Mencoba menjalankan..."
        sudo service redis-server start
        if service redis-server status >/dev/null 2>&1; then
            echo -e "[${GREEN} OK ${NC}] Redis-server berhasil dijalankan."
        else
            echo -e "[${RED}FAIL${NC}] Gagal menjalankan Redis-server secara otomatis. Silakan jalankan 'sudo service redis-server start' secara manual."
        fi
    fi
fi

# 4. Periksa WhatWeb CLI (FASE 1)
check_command "whatweb" "sudo apt install whatweb -y atau gem install whatweb"

# 5. Periksa WPScan CLI (FASE 2)
check_command "wpscan" "sudo gem install wpscan"

# 6. Periksa Nuclei CLI (FASE 3)
check_command "nuclei" "Silakan unduh pre-built binary untuk Linux di rilis GitHub Nuclei"


# 7. Periksa Virtual Environment Python
VENV_DIR="$HOME/venv-wsl"
if [ -d "$VENV_DIR" ]; then
    echo -e "[${GREEN} OK ${NC}] Virtual environment python ditemukan di $VENV_DIR"
    # Aktifkan dan cek package
    source "$VENV_DIR/bin/activate"
    
    echo "Memeriksa library python penting..."
    MISSING_LIBS=0
    # Modul dotenv dibaca sebagai dotenv
    for lib in flask celery redis eventlet dotenv requests json_repair; do
        python3 -c "import $lib" >/dev/null 2>&1
        if [ $? -eq 0 ]; then
            echo -e "  - $lib: ${GREEN}Terpasang${NC}"
        else
            echo -e "  - $lib: ${RED}BELUM Terpasang${NC}"
            MISSING_LIBS=$((MISSING_LIBS + 1))
        fi
    done
    
    if [ $MISSING_LIBS -gt 0 ]; then
        echo -e "[${YELLOW}WARN${NC}] Ada library python yang belum terpasang di venv."
        echo -e "       -> Solusi: Jalankan 'pip install -r requirements.txt'"
    fi
    deactivate
else
    echo -e "[${RED}FAIL${NC}] Virtual environment tidak ditemukan di $VENV_DIR"
    echo -e "       -> Solusi: python3 -m venv ~/venv-wsl"
fi

# 8. Periksa File .env
if [ -f ".env" ]; then
    echo -e "[${GREEN} OK ${NC}] File .env ditemukan."
    # Cek API Keys
    if grep -q "GEMINI_API_KEY=your_gemini_api_key_here" .env || grep -q "ANTHROPIC_API_KEY=your_anthropic_api_key_here" .env; then
        echo -e "[${YELLOW}WARN${NC}] API Key di dalam .env masih menggunakan nilai default. Pastikan Anda mengisinya agar AI analyzer berfungsi."
    fi
else
    echo -e "[${RED}FAIL${NC}] File .env belum dibuat."
    echo -e "       -> Solusi: cp env.example .env dan konfigurasikan isinya."
fi

echo "=========================================================="
