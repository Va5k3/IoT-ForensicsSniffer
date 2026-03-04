from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP, UDP
target = "captures/scan_A.pcap"




def load_pcap(filepath : str) -> list:
    packets = rdpcap(filepath)
    results = [] # ovo je lista u koju ćemo spremiti rezultate. # 
    for packet in packets:
        if packet.haslayer(IP):
            if packet.haslayer(TCP):
                if packet[TCP].dport == 1883 or packet[TCP].sport == 1883: #Message Queue Telemetry Transport (MQTT) - protokol koji se koristi za komunikaciju između IoT uređaja.
                    results.append({
                        "timestamp" : float(packet.time),
                        "src_ip" : packet[IP].src,
                        "dst_ip" : packet[IP].dst,
                        "protocol" : "MQTT",
                        "size" : len(packet),
                        "raw" : bytes(packet[TCP].payload)
                    })
            elif packet.haslayer(UDP):
                if packet[UDP].dport == 5683 or packet[UDP].sport == 5683: #Constrained Application Protocol (CoAP) - protokol koji se koristi za komunikaciju između IoT uređaja.
                    results.append({
                        "timestamp" : float(packet.time),
                        "src_ip" : packet[IP].src,
                        "dst_ip" : packet[IP].dst,
                        "protocol" : "CoAP",
                        "size" : len(packet),
                        "raw" : bytes(packet[UDP].payload)
                    })
    return results

if __name__ == "__main__":
    data = load_pcap(target)
    print(f"Ukupno paketa : {len(data)}")
    print(f"MQTT paketa : {sum(1 for p in data if p['protocol'] == 'MQTT')}")  
    print(f"CoAP paketa : {sum(1 for p in data if p['protocol'] == 'CoAP')}")
    print(f"Prvi paket : {data[0]}")