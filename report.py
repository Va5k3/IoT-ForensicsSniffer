import sqlite3
from datetime import datetime

conn = sqlite3.connect("forensics.db")

ukupno_paketa = conn.execute("SELECT COUNT(*) FROM packets").fetchone()[0]
print(f"Ukupno paketa: {ukupno_paketa}")


ukupno_anomalija = conn.execute("SELECT COUNT(*) FROM anomaly").fetchone()[0]
print(f"Ukupno anomalija: {ukupno_anomalija}")

napadaci = conn.execute("""
    SELECT ip, COUNT(*) as broj
    FROM anomaly
    GROUP BY ip
    ORDER BY broj DESC
""").fetchall()

print("\nTOP NAPADAČI:")
for ip, broj in napadaci:
    print(f"  {ip} → {broj} anomalija")

kritične = conn.execute(
    "SELECT timestamp, ip, description FROM anomaly WHERE severity = ?",
    ("CRITICAL",)
).fetchall()

print(f"\nKRITIČNE ANOMALIJE ({len(kritične)}):")
#for timestamp, ip, description in kritične:
#    dt = datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
#    print(f"  [{dt}] {ip} → {description}")