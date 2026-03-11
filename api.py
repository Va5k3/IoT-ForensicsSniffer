from flask import Flask, jsonify
from flask_cors import CORS
import sqlite3
from datetime import datetime

app = Flask(__name__)
CORS(app)
DB_PATH  = "forensics.db"

def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row # omogućava nam da pristupamo kolonama po imenu, a ne samo po indeksu - umjesto da koristimo row[0], row[1] itd., možemo koristiti row["timestamp"], row["ip"], row["description"] itd. Ovo čini kod čitljivijim i lakšim za održavanje, jer ne moramo pamtiti redoslijed kolona u tabeli.
    return conn

@app.route("/api/stats")
def stats():
    conn = get_conn()
    ukupno_paketa = conn.execute("SELECT COUNT(*) FROM packets").fetchone()[0]
    ukupno_anomalija = conn.execute("SELECT COUNT(*) FROM anomaly").fetchone()[0]
    broj_napadaca = conn.execute("SELECT COUNT(DISTINCT ip) FROM anomaly").fetchone()[0]
    return jsonify({
        "total_packets": ukupno_paketa,
        "total_anomalies": ukupno_anomalija,
        "unique_attackers": broj_napadaca
    })

@app.route("/api/anomalies")
def anomalies():
    conn = get_conn()
    anomalije = conn.execute("SELECT timestamp, ip, type, severity, description FROM anomaly ORDER BY timestamp DESC LIMIT 100").fetchall()
    return jsonify([
        {
            "timestamp": datetime.fromtimestamp(row["timestamp"]).strftime("%Y-%m-%d %H:%M:%S"),
            "ip": row["ip"],
            "type": row["type"],
            "severity": row["severity"],
            "description": row["description"]
        }
        for row in anomalije
    ])

@app.route("/api/attackers")
def attackers():
    conn = get_conn()
    napadaci = conn.execute("""
        SELECT ip, COUNT(*) as broj
        FROM anomaly
        GROUP BY ip
        ORDER BY broj DESC
        LIMIT 10
    """).fetchall()
    return jsonify([
        {
            "ip": row["ip"],
            "anomaly_count": row["broj"]
        }
        for row in napadaci
    ])

@app.route("/api/timeline")
def timeline():
    conn = get_conn()
    # Grupiši anomalije po minutama
    # strftime('%H:%M', ...) pretvara timestamp u format "15:31"
    rows = conn.execute("""
        SELECT 
            strftime('%H:%M', datetime(timestamp, 'unixepoch')) as minuta,
            COUNT(*) as broj
        FROM anomaly
        GROUP BY minuta
        ORDER BY minuta ASC
        LIMIT 60
    """).fetchall()
    return jsonify([
        {"time": row["minuta"], "count": row["broj"]}
        for row in rows
    ])

@app.route("/api/devices")
def devices():
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT ip, device_type, pkt_count, avg_size, unique_dst, pkt_per_min, ml_cluster "
            "FROM devices ORDER BY pkt_count DESC"
        ).fetchall()
        return jsonify([{
            "ip": r["ip"], "device_type": r["device_type"],
            "pkt_count": r["pkt_count"], "avg_size": round(float(r["avg_size"] or 0), 1),
            "unique_dst": r["unique_dst"], "pkt_per_min": round(float(r["pkt_per_min"] or 0), 2),
            "ml_cluster": r["ml_cluster"],
        } for r in rows])
    except:
        return jsonify([])

@app.route("/api/health")
def health():
    return jsonify({"status": "ok"})



if __name__ == "__main__":
    app.run(debug=True, port=5000)