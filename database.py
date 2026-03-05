import sqlite3


def init_db(path: str):
    conn = sqlite3.connect(path)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL,
            src_ip TEXT,
            dst_ip TEXT,
            protocol TEXT,
            size INTEGER       
            )
        """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS anomaly (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL,
            ip TEXT,
            type TEXT,
            severity TEXT,
            description TEXT       
            )
        """)
    
    conn.commit()
    return conn

def save_packet(conn, packet: dict):   #insert_packet funkcija prima konekciju i paket u obliku rječnika, a zatim ubacuje te podatke u bazu podataka.
    conn.execute("""
        INSERT INTO packets (timestamp, src_ip, dst_ip, protocol, size)
        VALUES (?, ?, ?, ?, ?)
    """, (packet["timestamp"], packet["src_ip"], packet["dst_ip"], packet["protocol"], packet["size"]))

def save_anomaly(conn, anomaly: dict, timestamp: float): 
    conn.execute("""
            INSERT INTO anomaly (type, severity, ip, description, timestamp)
                 VALUES (?,?,?,?,?)
                 """, (anomaly["type"],anomaly["severity"], anomaly["ip"], anomaly["description"], timestamp))
    
if __name__ == "__main__":
    conn = init_db("test.db")
    print("Baza podataka inicijalizovana.")

    save_packet(conn, {
      "timestamp": 1234567.0,
        "src_ip":    "10.0.0.5",
        "dst_ip":    "10.0.0.1",
        "protocol":  "MQTT",
        "size":      74
    })
    save_anomaly(conn, {
        "type":        "MQTT_BRUTEFORCE",
        "severity":    "CRITICAL",
        "ip":          "10.0.0.5",
        "description": "11 pokušaja za 60s"
    }, timestamp=1234567.0)

    
    conn.commit()
                
    paketi    = conn.execute("SELECT * FROM packets").fetchall()
    anomalije = conn.execute("SELECT * FROM anomaly").fetchall()

    print(f"Paketa u bazi:    {len(paketi)}")
    print(f"Anomalija u bazi: {len(anomalije)}")
    print(paketi)
    print(anomalije)