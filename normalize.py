import json
import sqlite3
import sys

AGENT_CIBLE = "victime-ubuntu"

COLS = ["alert_id", "timestamp", "severity", "rule_id", "rule_desc",
        "hostname", "src_ip", "dst_ip", "user", "mitre_technique"]

def normalize_wazuh(a):
    r = a.get("rule", {})
    d = a.get("data", {})
    mitre = r.get("mitre", {}).get("id") or r.get("mitre_techniques", [])
    return {
        "alert_id": a.get("id"),
        "timestamp": a.get("timestamp"),
        "severity": r.get("level"),
        "rule_id": r.get("id"),
        "rule_desc": r.get("description"),
        "hostname": a.get("agent", {}).get("name"),
        "src_ip": d.get("srcip"),
        "dst_ip": a.get("agent", {}).get("ip"),
        "user": d.get("srcuser") or d.get("dstuser"),
        "mitre_technique": mitre[0] if mitre else None,
    }

def init_db():
    db = sqlite3.connect("alerts.db")
    db.execute("""CREATE TABLE IF NOT EXISTS alerts (
        alert_id TEXT PRIMARY KEY, timestamp TEXT, severity INTEGER,
        rule_id TEXT, rule_desc TEXT, hostname TEXT, src_ip TEXT,
        dst_ip TEXT, user TEXT, mitre_technique TEXT)""")
    return db

def save(db, n):
    db.execute("INSERT OR IGNORE INTO alerts VALUES (%s)" % ",".join("?" * len(COLS)),
               [n[c] for c in COLS])

if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "alerts_11.json"
    db = init_db()
    with open(path) as f:
        for line in f:
            try:
                a = json.loads(line)
            except json.JSONDecodeError:
                continue
            if a.get("agent", {}).get("name") != AGENT_CIBLE:
                continue
            save(db, normalize_wazuh(a))
    db.commit()
    print("Alertes stockées :", db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0])
