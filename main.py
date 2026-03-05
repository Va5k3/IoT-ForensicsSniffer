from reader import load_pcap
from parser import parse_mqtt
from detector import detectBruteForce, detectSensitivePayload, detectSuspiciousTopic
from database import init_db, save_anomaly, save_packet


def main():
    # inicijalizacije baze podataka
    conn = init_db("forensics.db")
    print("Baza podataka inicijalizovana.")

    #ucitavanje paketa iz pcap datoteke
    data = load_pcap("captures/scan_A.pcap")
    print(f"Ucitano {len(data)} paketa")

    #trazenje anomalija
    anomaly_count = 0

    for p in data:
        #cuvamo svaki paket u bazu
        save_packet(conn, p)

        #ako ima payloada parisamo MQTT
        if len(p['raw']) > 0:
            parsed = parse_mqtt(p['raw'])
            if parsed:
                #proveravamo da li je napad
                anomaly = detectBruteForce(parsed, p["src_ip"], p["timestamp"])
                if not anomaly:
                    anomaly = detectSensitivePayload(parsed, p["src_ip"], p["timestamp"])
                if not anomaly:
                    anomaly = detectSuspiciousTopic(parsed, p["src_ip"], p["timestamp"])
                if anomaly:
                    save_anomaly(conn, anomaly, p["timestamp"])
                    anomaly_count += 1
                    print(f"[!!!] {anomaly['severity']} | {anomaly['ip']} | {anomaly['description']}")


    conn.commit()

    print("\n" + "="*50)
    print("SUMMARY")
    print("="*50)
    print(f"Ukupno paketa:    {len(data)}")
    print(f"Anomalija:        {anomaly_count}")

    paketi    = conn.execute("SELECT COUNT(*) FROM packets").fetchone()[0]
    anomalije = conn.execute("SELECT COUNT(*) FROM anomaly").fetchone()[0]
    print(f"Paketa u bazi:    {paketi}")
    print(f"Anomalija u bazi: {anomalije}")

if __name__ == "__main__":
    main()