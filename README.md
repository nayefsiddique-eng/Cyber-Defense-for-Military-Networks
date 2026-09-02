# Military Network Cyber Defense Range

A realistic digital twin of a multi-enclave military network designed for generating high-fidelity cyber telemetry and simulating MITRE ATT&CK scenarios.

## Architecture

This system uses a dual-mode architecture to accommodate varying hardware constraints:

* **Lightweight Mode (Default)**: Runs completely in-process using Python `asyncio.Queue` and SQLite/JSONL files. Requires < 1GB RAM.
* **Full Mode**: Uses Docker Compose to run Redpanda (Kafka), OpenSearch, and the Python app. Requires 4GB+ RAM.

## Features

* **Digital Twin**: Simulates 30+ assets across 6 military enclaves (DMZ, NIPRNet, TOC, SIPRNet, Tactical Edge, SCADA).
* **Realistic Telemetry**: Generates Windows EVTX, Linux auth.log, Zeek conn/dns, PAN-OS firewall, and Suricata EVE logs.
* **Attack Simulation**: Models 7 MITRE ATT&CK techniques without deploying malware (e.g., Password Spraying, Kerberoasting, HTTPS Beaconing).
* **Streaming Pipeline**: Normalizes raw events to OCSF v1.3.0 schema and stores them.
* **Real-time PCAP**: Generates accurate `.pcap` files via Scapy during the simulation.

## Setup

1. Install requirements:
   ```bash
   pip install -r requirements.txt
   ```
   *(Note: The `confluent-kafka` package requires librdkafka C headers. On Windows, you might need build tools).*

2. Create data directories:
   ```bash
   mkdir -p data/db data/telemetry data/pcaps data/scenarios
   ```

## Usage

The CLI (`src/main.py`) provides three main commands:

**1. Start the FastAPI Control Plane**
```bash
python -m src.main api
```
Access the Swagger UI at `http://localhost:8000/docs` to start simulations.

**2. Run Standalone Simulation**
```bash
python -m src.main simulate --duration 3600 --seed 42
```
Generates telemetry data in `data/telemetry/`.

**3. Run Standalone Pipeline**
```bash
python -m src.main pipeline
```
Listens on the event bus and normalizes/stores events.

## Full Mode (Docker)

To run the full stack with Redpanda and OpenSearch:

```bash
docker compose up -d
```
