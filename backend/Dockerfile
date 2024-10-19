FROM python:3.12.1-slim

RUN apt-get update && apt-get -y install \
    curl unzip automake libtool make gcc pkg-config wget libmagic1 \
    libgl1 libglib2.0-0 libgomp1 cron git poppler-utils libmupdf-dev \
    net-tools clamdscan clamav-daemon && \
    rm -rf /var/lib/apt/lists/*

# Download and install YARA
RUN wget https://github.com/VirusTotal/yara/archive/refs/tags/v4.4.0.tar.gz -O yara-4.4.0.tar.gz && \
    tar -zxf yara-4.4.0.tar.gz && \
    cd yara-4.4.0 && \
    ./bootstrap.sh && \
    ./configure && \
    make && \
    make install && \
    cd .. && \
    rm -rf yara-4.4.0 yara-4.4.0.tar.gz

# Switch working directory
WORKDIR /app

COPY requirements.txt .

RUN python -m pip install --upgrade pip \
    && pip install -r requirements.txt \
    && pip install --default-timeout=10000 uvicorn[standard] gunicorn

COPY . .

# Ensure the script is executable
RUN chmod +x ./scripts/dev_start.sh

# Expose the FastAPI port
EXPOSE 8000

CMD ["bash", "./scripts/dev_start.sh"]
