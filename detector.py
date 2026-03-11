from collections import defaultdict


connect_times = defaultdict(list) #kljuc je ip adresa, a vrijednost je lista timestampova kada je ta adresa poslala CONNECT poruku



def detectBruteForce(parsed_packet: dict, src_ip: str, timestamp: float) -> dict | None:

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
     return None

def detectSensitivePayload(parsed_packet: dict, src_ip: str, timestamp: float) -> dict | None:
    if parsed_packet["msg_type"] == "PUBLISH":
        payload = parsed_packet["payload"].lower()
        if "password" in payload or "token" in payload or "key" in payload  or "secret" in payload or "passwd" in payload:
            return {
                "type" : "SENSITIVE_PAYLOAD",
                "severity" : "HIGH",
                "ip" : src_ip,
                "description" : f"Osetljiva rec u payload : '{payload}'"
            }
    return None
def detectSuspiciousTopic(parsed_packet: dict, src_ip: str, timestamp: float) -> dict | None:
    if parsed_packet["msg_type"] == "PUBLISH":
        topic = parsed_packet["topic"].lower()
        if "/cmd" in topic or "/exec" in topic or "/admin" in topic or "/shell" in topic or "/firmware" in topic:
            return {
                "type" : "SUSPICIOUS_TOPIC",
                "severity" : "HIGH",
                "ip" : src_ip,
                "description" : f"Sumnjiv topic : '{topic}'"
            }
    return None
    
_ALL_DETECTORS = [detectBruteForce, detectSensitivePayload, detectSuspiciousTopic]

def run_all_detectors(parsed, src_ip, timestamp):
    """Jedan paket može imati više anomalija istovremeno."""
    anomalies = []
    for detector in _ALL_DETECTORS:
        result = detector(parsed, src_ip, timestamp)
        if result:
            anomalies.append(result)
    return anomalies


#if __name__ == "__main__":
    
    #data = load_pcap("captures/scan_A.pcap")

    #anomalije = []
    #for p in data:
    #    if len(p['raw']) > 0:
    #        parsed = parse_mqtt(p['raw'])
    #        if parsed:
    #            anomaly = detectBruteForce(parsed, p["src_ip"], p["timestamp"])
    #            if anomaly:
    #                anomalije.append(anomaly)
    #print(f"Detektovano anomalija: {len(anomalije)}")
    #for a in anomalije[:10]:
    #    print(a)