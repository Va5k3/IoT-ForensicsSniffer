from collections import defaultdict
from parser import parse_mqtt
from reader import load_pcap

connect_times = defaultdict(list) #kljuc je ip adresa, a vrijednost je lista timestampova kada je ta adresa poslala CONNECT poruku



def detect(parsed_packet: dict, src_ip: str, timestamp: float) -> dict | None:

     if parsed_packet["msg_type"] == "CONNECT":
        connect_times[src_ip].append(timestamp) #dodajemo timestamp u listu za tu ip adresu
        connTime = [t for t in connect_times[src_ip] if timestamp - t < 60] #filtriramo timestampove koji su unutar posljednjih 60 sekundi 
        connect_times[src_ip] = connTime #a zatim ažuriramo listu samo sa tim timestampovima
        if(len(connTime) > 10): #ako je broj CONNECT poruka unutar posljednjih 60 sekundi veći od 10, onda imamo sumnjivu aktivnost
            return {
                "type" : "MQTT_BRUTEFORCE",
                "severity" : "CRITICAL",
                "ip" : src_ip,
                "count" : len(connTime),
                "description" : f"Brute force: {len(connTime)} CONNECT poruka u posljednjih 60 sekundi"
            }
        return None
    
if __name__ == "__main__":
    
    data = load_pcap("captures/scan_A.pcap")

    anomalije = []
    for p in data:
        if len(p['raw']) > 0:
            parsed = parse_mqtt(p['raw'])
            if parsed:
                anomaly = detect(parsed, p["src_ip"], p["timestamp"])
                if anomaly:
                    anomalije.append(anomaly)
    print(f"Detektovano anomalija: {len(anomalije)}")
    for a in anomalije[:10]:
        print(a)