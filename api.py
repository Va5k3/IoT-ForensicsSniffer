from flask import Flask, jsonify
import sqlite3
from datetime import datetime

app = Flask(__name__)
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


if __name__ == "__main__":
    app.run(debug=True, port=5000)