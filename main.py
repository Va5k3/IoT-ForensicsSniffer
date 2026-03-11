"""
Glavni ulazni punkt IoT Forenzičkog Sniffera.

Načini rada:
  pcap  — čita i analizira .pcap fajl (default)
  live  — pasivno snima mrežni saobraćaj u realnom vremenu

Upotreba:
  python main.py
  python main.py --mode pcap --pcap captures/scan_A.pcap
  python main.py --mode pcap --pcap captures/attack.pcap --report json
  python main.py --mode pcap --report pdf
  python main.py --mode pcap --report both
  sudo python main.py --mode live --interface eth0
  sudo python main.py --mode live --interface any --report json
"""

import argparse
import os

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from classifier import classify_all_devices
from database import init_db, save_anomaly, save_device, save_packet
from detector import run_all_detectors
from logger_config import setup_logger
from parser import parse_coap, parse_mqtt
from reader import load_pcap

logger = setup_logger("main")


# ---------------------------------------------------------------------------
# PCAP mod
# ---------------------------------------------------------------------------

def process_pcap(conn, pcap_path: str) -> tuple:
    """Učitava pcap, analizira sve pakete, sprema u bazu. Vraća (paketi, anomalije)."""
    if not os.path.exists(pcap_path):
        logger.error(f"PCAP fajl ne postoji: {pcap_path}")
        return 0, 0

    data = load_pcap(pcap_path)
    anomaly_count = 0

    for p in data:
        save_packet(conn, p)

        if not p["raw"]:
            continue

        # Parsiraj po protokolu
        parsed = None
        if p["protocol"] == "MQTT":
            parsed = parse_mqtt(p["raw"])
        elif p["protocol"] == "CoAP":
            parsed = parse_coap(p["raw"])

        if not parsed:
            continue

        # Pokreni SVE detektore — jedan paket može imati više anomalija
        anomalies = run_all_detectors(parsed, p["src_ip"], p["timestamp"])
        for anomaly in anomalies:
            save_anomaly(conn, anomaly, p["timestamp"])
            anomaly_count += 1
            logger.warning(
                f"[ANOMALY] {anomaly['severity']:8s} | {anomaly['ip']:15s} "
                f"| {anomaly['type']} | {anomaly['description']}"
            )

    conn.commit()

    # Klasifikacija IoT uređaja
    logger.info("Klasifikujem IoT uređaje...")
    devices = classify_all_devices(conn)
    for device in devices:
        save_device(conn, device)
    conn.commit()

    # Summary
    logger.info("")
    logger.info("=" * 55)
    logger.info(" SUMMARY")
    logger.info("=" * 55)
    logger.info(f" Ukupno paketa : {len(data)}")
    logger.info(f" Anomalija     : {anomaly_count}")
    logger.info(f" Uređaja       : {len(devices)}")
    if devices:
        logger.info(" Klasifikovani uređaji:")
        for d in devices:
            logger.info(f"   {d['ip']:15s} → {d['device_type']}")
    logger.info("=" * 55)

    return len(data), anomaly_count


# ---------------------------------------------------------------------------
# Izvještaji
# ---------------------------------------------------------------------------

def _generate_reports(conn, report_type: str) -> None:
    from report import generate_json_report, generate_pdf_report
    if report_type in ("json", "both"):
        path = generate_json_report(conn)
        logger.info(f"JSON izvještaj: {path}")
    if report_type in ("pdf", "both"):
        path = generate_pdf_report(conn)
        if path:
            logger.info(f"PDF izvještaj: {path}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="IoT Forenzički Sniffer — MQTT & CoAP analiza",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Primjeri:
  python main.py
  python main.py --mode pcap --pcap captures/scan_A.pcap --report json
  python main.py --mode pcap --report pdf
  sudo python main.py --mode live --interface eth0
  sudo python main.py --mode live --interface any
        """,
    )
    ap.add_argument("--mode", "-m",
        choices=["pcap", "live"],
        default=os.getenv("MODE", "pcap"),
        help="Način rada (default: pcap)")
    ap.add_argument("--pcap", "-p",
        default=os.getenv("PCAP_PATH", "captures/normal.pcap"),
        help="Putanja do .pcap fajla")
    ap.add_argument("--interface", "-i",
        default=os.getenv("INTERFACE", "eth0"),
        help="Mrežni interfejs za live mod")
    ap.add_argument("--db",
        default=os.getenv("DB_PATH", "forensics.db"),
        help="Putanja do SQLite baze")
    ap.add_argument("--report", "-r",
        choices=["json", "pdf", "both", "none"],
        default=os.getenv("REPORT", "none"),
        help="Generiši forenzički izvještaj")
    return ap


def main() -> None:
    args = _build_parser().parse_args()

    logger.info("IoT Forenzički Sniffer — pokretanje")
    logger.info(f"Mod: {args.mode} | DB: {args.db}")

    conn = init_db(args.db)

    try:
        if args.mode == "pcap":
            process_pcap(conn, args.pcap)
        elif args.mode == "live":
            from sniffer import start_live_sniff
            start_live_sniff(conn, interface=args.interface)

        if args.report != "none":
            _generate_reports(conn, args.report)

    except KeyboardInterrupt:
        logger.info("Zaustavljeno od strane korisnika.")
    finally:
        conn.commit()
        conn.close()
        logger.info("Baza podataka zatvorena.")


if __name__ == "__main__":
    main()
