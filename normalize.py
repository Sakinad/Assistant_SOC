import json
import sqlite3
import sys

AGENT_CIBLE = "victime-ubuntu"

def normalize_wazuh(a):
    r = a.get("rule", {})
    return {
        "id": a.get("id"),
        "timestamp": a.get("timestamp"),
        "source": "wazuh",
        "host": a.get("agent", {}).get("name"),
        "rule_id": r.get("id"),
        "rule_description": r.get("description"),
        "severity": r.get("level"),
        "mitre_ids": r.get("mitre", {}).get("id") or r.get("mitre_techniques", []),
        "src_ip": a.get("data", {}).get("srcip"),
        "raw_log": a.get("full_log"),
        "label": None,
    }

path = sys.argv[1] if len(sys.argv) > 1 else "alerts_11.json"

db = sqlite3.connect("alerts.db")
db.execute("""CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY, timestamp TEXT, source TEXT, host TEXT,
    rule_id TEXT, rule_description TEXT, severity INTEGER,
    mitre_ids TEXT, src_ip TEXT, raw_log TEXT, label TEXT)""")

with open(path) as f:
    for line in f:
        try:
            a = json.loads(line)
        except json.JSONDecodeError:
            continue
        if a.get("agent", {}).get("name") != AGENT_CIBLE:
            continue
        n = normalize_wazuh(a)
        db.execute(
            "INSERT OR IGNORE INTO alerts VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (n["id"], n["timestamp"], n["source"], n["host"], n["rule_id"],
             n["rule_description"], n["severity"], json.dumps(n["mitre_ids"]),
             n["src_ip"], n["raw_log"], n["label"]))
db.commit()
print("Alertes stockées :", db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0])
