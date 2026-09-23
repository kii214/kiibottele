FROM ubuntu:22.04

# Set non-interactive mode
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV TZ=Asia/Jakarta

# Update, upgrade dan install dependensi dasar Ubuntu
RUN apt-get update -y && apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
    sudo curl wget git bash build-essential \
    software-properties-common \
    python3 python3-pip python3-venv python3-dev \
    tzdata ca-certificates gnupg lsb-release \
    tshark wireshark-common binwalk \
    wkhtmltopdf \
    # Clean up untuk mengurangi ukuran image
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy source code
COPY . /app

# Jalankan script installer lengkap (apt + pip tools CTF)
RUN chmod +x scripts/install_all_tools.sh && \
    bash scripts/install_all_tools.sh || true

# Install Python dependencies
RUN pip3 install --no-cache-dir --break-system-packages -e .

# Buat direktori data persisten
RUN mkdir -p /root/.kiibot

# Volume mount untuk data persisten
VOLUME ["/root/.kiibot"]

# Default command: jalankan Telegram Bot
CMD ["python3", "scripts/kiibot_telegram_bot.py"]
