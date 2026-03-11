import argparse
import json
import os
import sqlite3
from datetime import datetime

from logger_config import setup_logger

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

logger = setup_logger("report")

try:
    from fpdf import FPDF
    _PDF_OK = True
except ImportError:
    _PDF_OK = False
    logger.warning("fpdf2 nije instaliran. Instalirajte: pip install fpdf2")


# ---------------------------------------------------------------------------
# Prikupljanje podataka
# ---------------------------------------------------------------------------

def _collect(conn: sqlite3.Connection) -> dict:
    conn.row_factory = sqlite3.Row

    total_packets   = conn.execute("SELECT COUNT(*) FROM packets").fetchone()[0]
    total_anomalies = conn.execute("SELECT COUNT(*) FROM anomaly").fetchone()[0]

    protocols = {
        r["protocol"]: r["cnt"]
        for r in conn.execute(
            "SELECT protocol, COUNT(*) AS cnt FROM packets GROUP BY protocol"
        ).fetchall()
    }

    attackers = [
        {"ip": r["ip"], "anomaly_count": r["broj"], "types": r["types"] or ""}
        for r in conn.execute("""
            SELECT ip, COUNT(*) AS broj, GROUP_CONCAT(DISTINCT type) AS types
            FROM anomaly GROUP BY ip ORDER BY broj DESC LIMIT 10
        """).fetchall()
    ]

    anomalies = [
        {
            "timestamp":   datetime.fromtimestamp(float(r["timestamp"])).strftime("%Y-%m-%d %H:%M:%S"),
            "ip":          r["ip"],
            "type":        r["type"],
            "severity":    r["severity"],
            "description": r["description"],
        }
        for r in conn.execute(
            "SELECT timestamp, ip, type, severity, description "
            "FROM anomaly ORDER BY timestamp DESC LIMIT 100"
        ).fetchall()
    ]

    critical = [a for a in anomalies if a["severity"] == "CRITICAL"]

    severity_counts = {
        r["severity"]: r["cnt"]
        for r in conn.execute(
            "SELECT severity, COUNT(*) AS cnt FROM anomaly GROUP BY severity"
        ).fetchall()
    }

    try:
        devices = [
            {
                "ip":          r["ip"],
                "device_type": r["device_type"],
                "pkt_count":   r["pkt_count"],
                "avg_size":    round(float(r["avg_size"] or 0), 1),
                "unique_dst":  r["unique_dst"],
                "pkt_per_min": round(float(r["pkt_per_min"] or 0), 2),
                "ml_cluster":  r["ml_cluster"],
            }
            for r in conn.execute(
                "SELECT ip, device_type, pkt_count, avg_size, unique_dst, pkt_per_min, ml_cluster "
                "FROM devices ORDER BY pkt_count DESC"
            ).fetchall()
        ]
    except sqlite3.OperationalError:
        devices = []

    return {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "summary": {
            "total_packets":      total_packets,
            "total_anomalies":    total_anomalies,
            "unique_attackers":   len(attackers),
            "critical_count":     len(critical),
            "severity_breakdown": severity_counts,
        },
        "protocols":     protocols,
        "top_attackers": attackers,
        "anomalies":     anomalies,
        "critical":      critical,
        "devices":       devices,
    }


# ---------------------------------------------------------------------------
# JSON izvještaj
# ---------------------------------------------------------------------------

def generate_json_report(conn: sqlite3.Connection,
                         output_path: str = "forensics_report.json") -> str:
    data = _collect(conn)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    logger.info(f"JSON izvještaj sačuvan: {output_path}")
    return output_path


# ---------------------------------------------------------------------------
# PDF izvještaj
# ---------------------------------------------------------------------------

class _PDF(FPDF if _PDF_OK else object):

    def header(self):
        self.set_font("Helvetica", "B", 10)
        self.set_fill_color(30, 30, 30)
        self.set_text_color(255, 255, 255)
        self.cell(0, 8, "  IoT Forensics Report — Confidential", ln=True, fill=True)
        self.set_text_color(0, 0, 0)
        self.ln(2)

    def footer(self):
        self.set_y(-12)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(120, 120, 120)
        self.cell(0, 6, f"Stranica {self.page_no()}", align="C")
        self.set_text_color(0, 0, 0)

    def section_title(self, title: str):
        self.set_font("Helvetica", "B", 13)
        self.set_fill_color(240, 240, 240)
        self.cell(0, 8, f"  {title}", ln=True, fill=True)
        self.ln(2)

    def kv(self, key: str, value: str):
        self.set_font("Helvetica", "B", 10)
        self.cell(65, 6, key)
        self.set_font("Helvetica", "", 10)
        self.cell(0, 6, str(value), ln=True)

    def tbl_header(self, cols):
        self.set_font("Helvetica", "B", 9)
        self.set_fill_color(50, 50, 50)
        self.set_text_color(255, 255, 255)
        for label, w in cols:
            self.cell(w, 7, label, border=1, fill=True)
        self.ln()
        self.set_text_color(0, 0, 0)

    def tbl_row(self, values, cols, fill=False):
        self.set_font("Helvetica", "", 8)
        if fill:
            self.set_fill_color(248, 248, 248)
        for i, (_, w) in enumerate(cols):
            val = str(values[i]) if i < len(values) else ""
            if len(val) > w // 4 + 8:
                val = val[:w // 4 + 5] + "..."
            self.cell(w, 6, val, border=1, fill=fill)
        self.ln()


def generate_pdf_report(conn: sqlite3.Connection,
                        output_path: str = "forensics_report.pdf") -> str | None:
    if not _PDF_OK:
        logger.error("fpdf2 nije instaliran. Instalirajte: pip install fpdf2")
        return None

    data = _collect(conn)
    s    = data["summary"]

    pdf = _PDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # Naslov
    pdf.set_font("Helvetica", "B", 22)
    pdf.ln(8)
    pdf.cell(0, 12, "IoT Forensics Report", ln=True, align="C")
    pdf.set_font("Helvetica", "", 11)
    pdf.cell(0, 7, f"Generisan: {data['generated_at']}", ln=True, align="C")
    pdf.ln(10)

    # 1. Sažetak
    pdf.section_title("1. Sažetak")
    pdf.kv("Ukupno paketa:",        str(s["total_packets"]))
    pdf.kv("Ukupno anomalija:",     str(s["total_anomalies"]))
    pdf.kv("Jedinstvenih napadača:",str(s["unique_attackers"]))
    pdf.kv("Kritičnih anomalija:",  str(s["critical_count"]))
    pdf.ln(3)
    if s["severity_breakdown"]:
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(0, 6, "Anomalije po ozbiljnosti:", ln=True)
        pdf.set_font("Helvetica", "", 10)
        for sev, cnt in s["severity_breakdown"].items():
            pdf.cell(0, 6, f"   {sev}: {cnt}", ln=True)
    pdf.ln(5)

    # 2. Protokoli
    pdf.section_title("2. Protokoli")
    pdf.set_font("Helvetica", "", 10)
    for proto, cnt in data["protocols"].items():
        pdf.cell(0, 6, f"   {proto}: {cnt} paketa", ln=True)
    pdf.ln(5)

    # 3. Uređaji
    if data["devices"]:
        pdf.section_title("3. Klasifikovani IoT uređaji")
        cols = [("IP adresa",38),("Tip uređaja",42),("Paketi",20),
                ("Avg. vel. (B)",28),("Dest. IP",22),("ML klaster",24)]
        pdf.tbl_header(cols)
        for i, d in enumerate(data["devices"]):
            pdf.tbl_row([
                d["ip"], d["device_type"], str(d["pkt_count"]),
                str(d["avg_size"]), str(d["unique_dst"]),
                str(d["ml_cluster"]) if d["ml_cluster"] is not None else "-",
            ], cols, fill=(i % 2 == 0))
        pdf.ln(5)

    # 4. Top napadači
    if data["top_attackers"]:
        pdf.section_title("4. Top napadači")
        cols = [("IP adresa",45),("Anomalija",30),("Tipovi",115)]
        pdf.tbl_header(cols)
        for i, a in enumerate(data["top_attackers"]):
            pdf.tbl_row([a["ip"], str(a["anomaly_count"]), a["types"]], cols, fill=(i%2==0))
        pdf.ln(5)

    # 5. Kritične anomalije
    if data["critical"]:
        pdf.section_title(f"5. Kritične anomalije ({len(data['critical'])})")
        cols = [("Timestamp",38),("IP adresa",32),("Opis",120)]
        pdf.tbl_header(cols)
        for i, a in enumerate(data["critical"]):
            pdf.tbl_row([a["timestamp"], a["ip"], a["description"]], cols, fill=(i%2==0))
        pdf.ln(5)

    # 6. Sve anomalije
    pdf.section_title(f"6. Sve anomalije (posljednjih 100)")
    cols = [("Timestamp",35),("IP",28),("Tip",38),("Ozbiljnost",22),("Opis",67)]
    pdf.tbl_header(cols)
    for i, a in enumerate(data["anomalies"]):
        pdf.tbl_row(
            [a["timestamp"], a["ip"], a["type"], a["severity"], a["description"]],
            cols, fill=(i % 2 == 0),
        )

    pdf.output(output_path)
    logger.info(f"PDF izvještaj sačuvan: {output_path}")
    return output_path


# ---------------------------------------------------------------------------
# Standalone
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Generiši forenzički izvještaj")
    ap.add_argument("--format", "-f", choices=["json", "pdf", "both"], default="json")
    ap.add_argument("--db", default=os.getenv("DB_PATH", "forensics.db"))
    args = ap.parse_args()

    conn = sqlite3.connect(args.db)
    conn.row_factory = sqlite3.Row

    if args.format in ("json", "both"):
        generate_json_report(conn)
    if args.format in ("pdf", "both"):
        generate_pdf_report(conn)

    conn.close()
