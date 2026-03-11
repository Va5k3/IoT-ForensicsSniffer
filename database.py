import sqlite3
import os

def init_db(path: str):
    
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row

    conn.execute("""
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL, src_ip TEXT, dst_ip TEXT,
            protocol TEXT, size INTEGER
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS anomaly (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL, ip TEXT, type TEXT,
            severity TEXT, description TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT UNIQUE, device_type TEXT, ml_cluster INTEGER,
            pkt_count INTEGER, avg_size REAL, unique_dst INTEGER,
            pkt_per_min REAL, last_seen REAL
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
    
def save_device(conn, device: dict):
    conn.execute("""
        INSERT INTO devices (ip, device_type, ml_cluster, pkt_count, avg_size, unique_dst, pkt_per_min, last_seen)
        VALUES (?,?,?,?,?,?,?,?)
        ON CONFLICT(ip) DO UPDATE SET
            device_type=excluded.device_type, ml_cluster=excluded.ml_cluster,
            pkt_count=excluded.pkt_count, avg_size=excluded.avg_size,
            unique_dst=excluded.unique_dst, pkt_per_min=excluded.pkt_per_min,
            last_seen=excluded.last_seen
    """, (device["ip"], device["device_type"], device.get("ml_cluster"),
          device["pkt_count"], device["avg_size"], device["unique_dst"],
          device.get("pkt_per_min", 0.0), device.get("last_seen", 0.0)))
    
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