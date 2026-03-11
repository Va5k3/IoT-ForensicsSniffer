import argparse
import os
import threading

from scapy.all import sniff, get_if_list
from scapy.layers.inet import IP, TCP, UDP

from database import init_db, save_packet, save_anomaly
from detector import run_all_detectors
from logger_config import setup_logger
from parser import parse_coap, parse_mqtt

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

logger = setup_logger("sniffer")

_db_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Obrada jednog paketa (scapy callback)
# ---------------------------------------------------------------------------

def _process_packet(packet, conn) -> None:
    try:
        if not packet.haslayer(IP):
            return

        entry = None

        if packet.haslayer(TCP):
            tcp = packet[TCP]
            if tcp.dport == 1883 or tcp.sport == 1883:
                entry = {
                    "timestamp": float(packet.time),
                    "src_ip":    packet[IP].src,
                    "dst_ip":    packet[IP].dst,
                    "protocol":  "MQTT",
                    "size":      len(packet),
                    "raw":       bytes(tcp.payload),
                }
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            if udp.dport == 5683 or udp.sport == 5683:
                entry = {
                    "timestamp": float(packet.time),
                    "src_ip":    packet[IP].src,
                    "dst_ip":    packet[IP].dst,
                    "protocol":  "CoAP",
                    "size":      len(packet),
                    "raw":       bytes(udp.payload),
                }

        if entry is None:
            return

        with _db_lock:
            save_packet(conn, entry)

        if entry["raw"]:
            parsed = (
                parse_mqtt(entry["raw"])
                if entry["protocol"] == "MQTT"
                else parse_coap(entry["raw"])
            )
            if parsed:
                anomalies = run_all_detectors(parsed, entry["src_ip"], entry["timestamp"])
                if anomalies:
                    with _db_lock:
                        for a in anomalies:
                            save_anomaly(conn, a, entry["timestamp"])
                    for a in anomalies:
                        logger.warning(
                            f"[ANOMALY] {a['severity']:8s} | {a['ip']:15s} "
                            f"| {a['type']} | {a['description']}"
                        )

        with _db_lock:
            conn.commit()

    except Exception as e:
        logger.error(f"Greška pri obradi paketa: {e}", exc_info=True)


# ---------------------------------------------------------------------------
# Javna funkcija
# ---------------------------------------------------------------------------

def start_live_sniff(conn, interface: str = None) -> None:
    """
    Pokreće live packet capture.

    Args:
        conn      : SQLite konekcija (iz init_db)
        interface : Naziv interfejsa. None → čita iz .env INTERFACE, default 'eth0'
    """
    if interface is None:
        interface = os.getenv("INTERFACE", "eth0")

    if interface != "any":
        available = get_if_list()
        if interface not in available:
            logger.error(
                f"Interfejs '{interface}' nije pronađen.\n"
                f"Dostupni: {', '.join(available)}\n"
                f"Savjet: koristite 'any' za sve interfejse (Linux)."
            )
            return

    logger.info("=" * 55)
    logger.info(" IoT Forenzički Sniffer — Live Mode")
    logger.info("=" * 55)
    logger.info(f" Interfejs : {interface}")
    logger.info(f" Filter    : TCP/1883 (MQTT)  |  UDP/5683 (CoAP)")
    logger.info(f" Zaustavi  : Ctrl+C")
    logger.info("=" * 55)

    try:
        sniff(
            iface=interface,
            filter="tcp port 1883 or udp port 5683",
            prn=lambda pkt: _process_packet(pkt, conn),
            store=False,
        )
    except KeyboardInterrupt:
        logger.info("Sniffing zaustavljen (Ctrl+C).")
    except PermissionError:
        logger.error("Nemate privilegije. Pokrenite: sudo python main.py --mode live")
    except Exception as e:
        logger.error(f"Greška u snifferu: {e}", exc_info=True)
    finally:
        with _db_lock:
            conn.commit()
        logger.info("Sniffer zatvoren.")


# ---------------------------------------------------------------------------
# Standalone pokretanje
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="IoT Live Sniffer")
    ap.add_argument("--interface", "-i", default=os.getenv("INTERFACE", "eth0"))
    ap.add_argument("--db", default=os.getenv("DB_PATH", "forensics.db"))
    args = ap.parse_args()

    db_conn = init_db(args.db)
    start_live_sniff(db_conn, interface=args.interface)
    db_conn.close()
