import os
import sqlite3
from datetime import datetime

from flask import Flask, jsonify
from flask_cors import CORS
from logger_config import setup_logger

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

logger  = setup_logger("api")
app     = Flask(__name__)
CORS(app)
DB_PATH = os.getenv("DB_PATH", "forensics.db")


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ---------------------------------------------------------------------------
# Endpointi
# ---------------------------------------------------------------------------

@app.route("/api/stats")
def stats():
    """Ukupne statistike: paketi, anomalije, napadači, protokoli."""
    with get_conn() as conn:
        total_packets    = conn.execute("SELECT COUNT(*) FROM packets").fetchone()[0]
        total_anomalies  = conn.execute("SELECT COUNT(*) FROM anomaly").fetchone()[0]
        unique_attackers = conn.execute("SELECT COUNT(DISTINCT ip) FROM anomaly").fetchone()[0]
        severity_rows    = conn.execute(
            "SELECT severity, COUNT(*) AS cnt FROM anomaly GROUP BY severity"
        ).fetchall()
        proto_rows = conn.execute(
            "SELECT protocol, COUNT(*) AS cnt FROM packets GROUP BY protocol"
        ).fetchall()

    return jsonify({
        "total_packets":    total_packets,
        "total_anomalies":  total_anomalies,
        "unique_attackers": unique_attackers,
        "severity_breakdown": {r["severity"]: r["cnt"] for r in severity_rows},
        "protocols":          {r["protocol"]: r["cnt"] for r in proto_rows},
    })


@app.route("/api/anomalies")
def anomalies():
    """Posljednjih 100 anomalija, najnovije prve."""
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT timestamp, ip, type, severity, description
            FROM anomaly ORDER BY timestamp DESC LIMIT 100
        """).fetchall()

    return jsonify([
        {
            "timestamp":   datetime.fromtimestamp(float(r["timestamp"])).strftime("%Y-%m-%d %H:%M:%S"),
            "ip":          r["ip"],
            "type":        r["type"],
            "severity":    r["severity"],
            "description": r["description"],
        }
        for r in rows
    ])


@app.route("/api/attackers")
def attackers():
    """Top 10 IP adresa po broju anomalija."""
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT ip, COUNT(*) AS broj, GROUP_CONCAT(DISTINCT type) AS types
            FROM anomaly GROUP BY ip ORDER BY broj DESC LIMIT 10
        """).fetchall()

    return jsonify([
        {"ip": r["ip"], "anomaly_count": r["broj"], "types": r["types"]}
        for r in rows
    ])


@app.route("/api/timeline")
def timeline():
    """Broj anomalija po minutama (za grafikon)."""
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT
                strftime('%H:%M', datetime(timestamp, 'unixepoch')) AS minuta,
                COUNT(*) AS broj
            FROM anomaly
            GROUP BY minuta ORDER BY minuta ASC LIMIT 60
        """).fetchall()

    return jsonify([{"time": r["minuta"], "count": r["broj"]} for r in rows])


@app.route("/api/devices")
def devices():
    """Lista klasifikovanih IoT uređaja."""
    try:
        with get_conn() as conn:
            rows = conn.execute("""
                SELECT ip, device_type, pkt_count, avg_size, unique_dst, pkt_per_min, ml_cluster
                FROM devices ORDER BY pkt_count DESC
            """).fetchall()

        return jsonify([
            {
                "ip":          r["ip"],
                "device_type": r["device_type"],
                "pkt_count":   r["pkt_count"],
                "avg_size":    round(float(r["avg_size"] or 0), 1),
                "unique_dst":  r["unique_dst"],
                "pkt_per_min": round(float(r["pkt_per_min"] or 0), 2),
                "ml_cluster":  r["ml_cluster"],
            }
            for r in rows
        ])
    except sqlite3.OperationalError:
        return jsonify([])   # stara baza bez tabele 'devices'


@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "db": DB_PATH})


# ---------------------------------------------------------------------------
# Pokretanje
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    port = int(os.getenv("API_PORT", 5000))
    logger.info(f"API server: http://localhost:{port}")
    app.run(debug=True, port=port)
