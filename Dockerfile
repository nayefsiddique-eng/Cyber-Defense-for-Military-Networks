FROM python:3.11-slim

WORKDIR /app

# Install system dependencies for confluent-kafka (librdkafka) and Scapy (tcpdump)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    librdkafka-dev \
    tcpdump \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Create necessary directories for lightweight mode
RUN mkdir -p data/db data/telemetry data/pcaps data/scenarios

EXPOSE 8000

CMD ["python", "-m", "src.main", "api"]
