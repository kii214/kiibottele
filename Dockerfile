FROM kalilinux/kali-rolling:latest

# Set non-interactive mode
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

# Update and install dependencies
RUN apt-get update -y && apt-get upgrade -y && \
    apt-get install -y sudo curl wget git bash build-essential \
    python3 python3-pip python3-venv python3-dev \
    wkhtmltopdf wireshark tshark binwalk \
    # Clean up to reduce image size
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy source code
COPY . /app

# Run the complete installer script from KIIBOT
RUN chmod +x scripts/install_all_tools.sh && \
    ./scripts/install_all_tools.sh

# Install Python dependencies globally within the container
RUN pip3 install --no-cache-dir --break-system-packages -e .

# Create volume mount points for persistent data
VOLUME ["/root/.kiibot"]

# Default command: run the telegram bot
CMD ["python3", "scripts/kiibot_telegram_bot.py"]
