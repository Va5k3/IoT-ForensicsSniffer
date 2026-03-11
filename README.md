# IoT Forenzički Sniffer

Pasivni sistem za snimanje i analizu mrežnog saobraćaja IoT uređaja.  
Podržava **MQTT** (TCP/1883) i **CoAP** (UDP/5683) protokole, automatski detektuje anomalije, klasifikuje uređaje ML algoritmima i generiše forenzičke izvještaje.

---

## Brzi start

```bash
# 1. Klonirajte / raspakujte projekat
cd iot-forensics

# 2. Instalirajte zavisnosti
pip install -r requirements.txt

# 3. Kopirajte konfiguraciju
cp .env.example .env

# 4. Stavite vaš .pcap fajl u captures/ folder
mkdir captures
# cp vaš_fajl.pcap captures/normal.pcap

# 5. Pokrenite analizu
python main.py
```

---

## Načini rada

### PCAP mod — analiza snimljenog fajla

```bash
python main.py
python main.py --mode pcap --pcap captures/scan_A.pcap
python main.py --mode pcap --pcap captures/attack.pcap --report json
python main.py --mode pcap --report pdf
python main.py --mode pcap --report both
```

### Live mod — real-time sniffing

> Zahtijeva root/admin privilegije!

```bash
sudo python main.py --mode live --interface eth0
sudo python main.py --mode live --interface wlan0
sudo python main.py --mode live --interface any    # svi interfejsi (Linux)

# + generiši izvještaj kada zaustaviš (Ctrl+C)
sudo python main.py --mode live --interface eth0 --report json
```

### Samo REST API

```bash
python api.py
# Dostupno na: http://localhost:5000
```

### Samo izvještaj iz postojeće baze

```bash
python report.py --format json
python report.py --format pdf
python report.py --format both
```

---

## Arhitektura

```
main.py              ← CLI ulazna tačka (argparse + .env)
│
├── pcap mod → reader.py → parser.py → detector.py → database.py
│                                    ↗
└── live mod → sniffer.py ──────────
                                     ↓
                           classifier.py (ML klasifikacija)
                                     ↓
                             report.py (JSON + PDF)
                                     ↓
                               api.py (Flask REST)
```

---

## Detektori anomalija (6 aktivnih)

| Detektor               | Protokol | Ozbiljnost | Opis |
|------------------------|----------|------------|------|
| `MQTT_BRUTEFORCE`      | MQTT     | CRITICAL   | >10 CONNECT poruka u 60s |
| `SENSITIVE_PAYLOAD`    | MQTT     | HIGH       | Ključne riječi u payloadu (password, token, key…) |
| `SUSPICIOUS_TOPIC`     | MQTT     | HIGH       | Sumnjivi topici (/cmd, /exec, /admin, /shell…) |
| `MQTT_PUBLISH_FLOOD`   | MQTT     | HIGH       | >50 PUBLISH poruka u 10s |
| `COAP_SUSPICIOUS_PATH` | CoAP     | MEDIUM     | Sumnjive URI putanje (/admin, /firmware…) |
| `COAP_FLOOD`           | CoAP     | HIGH       | >30 CoAP zahtjeva u 10s |

---

## Klasifikacija IoT uređaja

### Rule-based (automatska)

| Tip uređaja        | Karakteristike |
|--------------------|----------------|
| IP Camera          | Veliki paketi (>900B), visoka frekvencija (>60/min) |
| IoT Sensor         | Mali paketi (<250B), niska frekvencija (<15/min) |
| Smart Hub/Gateway  | Mnogo destinacija (≥5), srednji paketi |
| Smart Actuator     | Mali paketi, umjerena frekvencija (5–40/min) |
| Mobile/Laptop      | Mnogo destinacija (≥8), veći paketi |

### ML (KMeans clustering)
Kada ima ≥4 uređaja, scikit-learn KMeans grupiše uređaje sa sličnim prometnim obrascima u klastere (0–3).

---

## REST API endpointi

| Endpoint             | Opis |
|----------------------|------|
| `GET /api/stats`     | Ukupne statistike (paketi, anomalije, protokoli) |
| `GET /api/anomalies` | Posljednjih 100 anomalija |
| `GET /api/attackers` | Top 10 IP adresa po broju anomalija |
| `GET /api/timeline`  | Anomalije po minutama (za grafikon) |
| `GET /api/devices`   | Klasifikovani IoT uređaji |
| `GET /api/health`    | Health check |

---

## Struktura projekta

```
iot-forensics/
├── .env.example        ← Primjer konfiguracije (kopirajte u .env)
├── .gitignore
├── requirements.txt    ← Python zavisnosti
├── README.md
│
├── main.py             ← Ulazna tačka, CLI, pcap/live modovi
├── sniffer.py          ← Live scapy sniffer
├── reader.py           ← Čitanje .pcap fajlova
├── parser.py           ← MQTT parser + CoAP parser (RFC 7252)
├── detector.py         ← 6 detektora anomalija
├── classifier.py       ← ML + rule-based klasifikacija uređaja
├── database.py         ← SQLite operacije
├── api.py              ← Flask REST API
├── report.py           ← JSON + PDF forenzički izvještaji
├── logger_config.py    ← Centralizovani logging
│
└── captures/           ← Stavite .pcap fajlove ovdje
    └── (vaši .pcap fajlovi)
```

---

## Konfiguracija (.env)

```env
DB_PATH=forensics.db          # Putanja do baze (ne briše se pri ponovnom pokretanju)
PCAP_PATH=captures/normal.pcap
INTERFACE=eth0                 # Za live mod
LOG_LEVEL=INFO                 # DEBUG / INFO / WARNING / ERROR
LOG_FILE=forensics.log
API_PORT=5000
REPORT=none                    # none / json / pdf / both
```

---

## Zahtjevi

- Python 3.10+
- Root/sudo privilegije za live snimanje
- Linux/Mac preporučeno (Windows podržan sa Npcap za scapy)
