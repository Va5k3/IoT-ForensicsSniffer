import os
from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP, UDP
from logger_config import setup_logger

logger = setup_logger("reader")


def load_pcap(filepath: str) -> list:
    """
    Učitaj .pcap fajl i vrati listu IoT paketa.

    Svaki paket je dict sa ključevima:
      timestamp, src_ip, dst_ip, protocol, size, raw
    """
    if not os.path.exists(filepath):
        logger.error(f"PCAP fajl nije pronađen: {filepath}")
        return []

    logger.info(f"Čitam pcap: {filepath}")
    packets = rdpcap(filepath)
    results = []

    for packet in packets:
        if not packet.haslayer(IP):
            continue

        if packet.haslayer(TCP):
            tcp = packet[TCP]
            if tcp.dport == 1883 or tcp.sport == 1883:
                results.append({
                    "timestamp": float(packet.time),
                    "src_ip":    packet[IP].src,
                    "dst_ip":    packet[IP].dst,
                    "protocol":  "MQTT",
                    "size":      len(packet),
                    "raw":       bytes(tcp.payload),
                })

        elif packet.haslayer(UDP):
            udp = packet[UDP]
            if udp.dport == 5683 or udp.sport == 5683:
                results.append({
                    "timestamp": float(packet.time),
                    "src_ip":    packet[IP].src,
                    "dst_ip":    packet[IP].dst,
                    "protocol":  "CoAP",
                    "size":      len(packet),
                    "raw":       bytes(udp.payload),
                })

    mqtt_n = sum(1 for p in results if p["protocol"] == "MQTT")
    coap_n = sum(1 for p in results if p["protocol"] == "CoAP")
    logger.info(f"Pronađeno {len(results)} IoT paketa  (MQTT: {mqtt_n}, CoAP: {coap_n})")
    return results


# ---------------------------------------------------------------------------
# Standalone
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "captures/normal.pcap"
    data = load_pcap(target)
    print(f"Ukupno paketa : {len(data)}")
    print(f"MQTT paketa   : {sum(1 for p in data if p['protocol'] == 'MQTT')}")
    print(f"CoAP paketa   : {sum(1 for p in data if p['protocol'] == 'CoAP')}")
    if data:
        print(f"Prvi paket    : {data[0]}")
