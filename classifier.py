"""
ML klasifikacija IoT uređaja na osnovu mrežnog ponašanja.

Dva sloja klasifikacije:
  1. Rule-based  — brza, deterministička (5 tipova uređaja)
  2. KMeans ML   — unsupervised clustering kada ima ≥4 uređaja
                   (scikit-learn + numpy)

Klasifikacija se bazira isključivo na saobraćajnim obrascima:
  prosječna veličina paketa, frekvencija, broj destinacija.
"""

import sqlite3
from logger_config import setup_logger

logger = setup_logger("classifier")

# ---------------------------------------------------------------------------
# Rule-based pravila (redoslijed je bitan — prvo odgovarajuće pravilo pobijedi)
# ---------------------------------------------------------------------------
_RULES = [
    ("IP Camera",         lambda f: f["avg_size"] > 900  and f["pkt_per_min"] > 60),
    ("IoT Sensor",        lambda f: f["avg_size"] < 250  and f["pkt_per_min"] < 15),
    ("Smart Hub/Gateway", lambda f: f["unique_dst"] >= 5 and f["avg_size"] < 600),
    ("Smart Actuator",    lambda f: f["avg_size"] < 350  and 5 <= f["pkt_per_min"] <= 40),
    ("Mobile/Laptop",     lambda f: f["unique_dst"] >= 8 and f["avg_size"] > 350),
]


def _rule_classify(feat: dict) -> str:
    for label, rule in _RULES:
        try:
            if rule(feat):
                return label
        except Exception:
            pass
    return "Unknown IoT Device"


# ---------------------------------------------------------------------------
# Feature ekstrakcija iz baze
# ---------------------------------------------------------------------------

def _extract_features(conn: sqlite3.Connection) -> dict:
    """Vraća dict {ip: feature_dict} iz tabele packets."""
    rows = conn.execute("""
        SELECT
            src_ip,
            COUNT(*)               AS pkt_count,
            AVG(size)              AS avg_size,
            MIN(size)              AS min_size,
            MAX(size)              AS max_size,
            COUNT(DISTINCT dst_ip) AS unique_dst,
            MIN(timestamp)         AS first_seen,
            MAX(timestamp)         AS last_seen
        FROM packets
        GROUP BY src_ip
        HAVING COUNT(*) >= 3
    """).fetchall()

    features = {}
    for r in rows:
        duration    = max(float(r["last_seen"]) - float(r["first_seen"]), 1.0)
        pkt_per_min = (r["pkt_count"] / duration) * 60.0

        features[r["src_ip"]] = {
            "pkt_count":   r["pkt_count"],
            "avg_size":    float(r["avg_size"] or 0),
            "min_size":    float(r["min_size"] or 0),
            "max_size":    float(r["max_size"] or 0),
            "unique_dst":  r["unique_dst"],
            "pkt_per_min": round(pkt_per_min, 3),
            "last_seen":   float(r["last_seen"] or 0),
        }
    return features


# ---------------------------------------------------------------------------
# KMeans clustering
# ---------------------------------------------------------------------------

def _ml_cluster(features: dict) -> dict:
    """Grupiše uređaje KMeans-om. Vraća {ip: cluster_id}."""
    try:
        import numpy as np
        from sklearn.cluster import KMeans
        from sklearn.preprocessing import StandardScaler
    except ImportError:
        logger.warning("scikit-learn/numpy nisu instalirani — ML clustering preskočen.")
        return {}

    ips = list(features.keys())
    X = [[
        features[ip]["pkt_count"],
        features[ip]["avg_size"],
        features[ip]["unique_dst"],
        features[ip]["pkt_per_min"],
    ] for ip in ips]

    import numpy as np
    X_arr    = np.array(X, dtype=float)
    n_clust  = min(4, len(ips))
    X_scaled = StandardScaler().fit_transform(X_arr)
    labels   = KMeans(n_clusters=n_clust, random_state=42, n_init=10).fit_predict(X_scaled)

    logger.info(f"ML clustering: {n_clust} klastera za {len(ips)} uređaja.")
    return {ip: int(lbl) for ip, lbl in zip(ips, labels)}


# ---------------------------------------------------------------------------
# Javni API
# ---------------------------------------------------------------------------

def classify_all_devices(conn: sqlite3.Connection) -> list:
    """
    Klasifikuje sve IoT uređaje iz baze.
    Vraća listu dict-ova za database.save_device().
    """
    features = _extract_features(conn)

    if not features:
        logger.warning("Nema dovoljno paketa za klasifikaciju (minimalno 3 po IP-u).")
        return []

    ml_labels = _ml_cluster(features) if len(features) >= 4 else {}

    results = []
    for ip, feat in features.items():
        device_type = _rule_classify(feat)
        ml_cluster  = ml_labels.get(ip)

        cluster_str = f" (ML klaster {ml_cluster})" if ml_cluster is not None else ""
        logger.info(
            f"Uređaj: {ip:15s} → {device_type:20s}{cluster_str} "
            f"| {feat['pkt_count']} pkts | avg {feat['avg_size']:.0f}B "
            f"| {feat['pkt_per_min']:.1f} pkt/min"
        )

        results.append({
            "ip":          ip,
            "device_type": device_type,
            "ml_cluster":  ml_cluster,
            "pkt_count":   feat["pkt_count"],
            "avg_size":    round(feat["avg_size"], 1),
            "unique_dst":  feat["unique_dst"],
            "pkt_per_min": feat["pkt_per_min"],
            "last_seen":   feat["last_seen"],
        })

    return results


# ---------------------------------------------------------------------------
# Standalone test
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sqlite3 as _sq
    conn = _sq.connect("forensics.db")
    conn.row_factory = _sq.Row
    devices = classify_all_devices(conn)
    print(f"Klasifikovano uređaja: {len(devices)}")
    for d in devices:
        print(f"  {d['ip']:15s} → {d['device_type']:20s} | ML klaster: {d['ml_cluster']}")
    conn.close()
