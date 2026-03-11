# IoT Forensics Sniffer (MQTT + CoAP)

A small passive tool for capturing and analyzing IoT network traffic.  
It focuses on **MQTT** (TCP/1883) and **CoAP** (UDP/5683), stores basic packet info in **SQLite**, runs a few simple anomaly detectors, classifies devices (rule-based + optional KMeans), and can generate **JSON/PDF** reports.  
There is also a lightweight **Flask REST API** and a simple **HTML dashboard**.

## What it does (high level)

- Read packets from a **PCAP** file (offline mode) or sniff live traffic (live mode)
- Detect anomalies (currently **3 detectors**):
  - `MQTT_BRUTEFORCE` (too many CONNECT messages from one IP in a short time)
  - `SENSITIVE_PAYLOAD` (payload contains keywords like `password`, `token`, `key`, etc.)
  - `SUSPICIOUS_TOPIC` (topics like `/cmd`, `/exec`, `/admin`, `/shell`, `/firmware`, etc.)
- Save results into an SQLite database:
  - packets
  - anomalies
  - device classification
- Generate reports:
  - JSON report (`forensics_report.json`)
  - PDF report (`forensics_report.pdf`) if `fpdf2` is installed
- REST API endpoints for stats/anomalies/devices
- Dashboard page (`dashboard/index.html`) that calls the API and shows charts/tables

## Quick start

```bash
# 1) Go to the project folder
cd IoT-ForensicsSniffer

# 2) Install dependencies
pip install -r requirements.txt

# 3) (Optional) create a .env file
# There is no .env.example in this repo right now, but the app reads env vars if you set them.
# You can create .env manually if you want.

# 4) Put your capture file somewhere (example: captures/normal.pcap)
mkdir -p captures
# cp your_file.pcap captures/normal.pcap

# 5) Run offline analysis (PCAP mode is the default)
python main.py
