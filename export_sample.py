import json, sqlite3
db = sqlite3.connect("alerts.db")
db.row_factory = sqlite3.Row
rows = [dict(r) for r in db.execute(
    "SELECT * FROM alerts "
    "WHERE mitre_technique IS NOT NULL "
    "AND rule_desc NOT LIKE 'CIS Ubuntu%' "
    "ORDER BY timestamp LIMIT 100"
)]
json.dump(rows, open("data/alerts_sample.json", "w"), indent=2, ensure_ascii=False)
print(len(rows), "alertes exportées")
