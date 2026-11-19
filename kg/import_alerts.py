"""Importe les alertes Wazuh normalisées (format docs/api.md) dans Neo4j.

Usage (depuis la racine du dépôt) :
    python kg/import_alerts.py                       # data/alerts_sample.json
    python kg/import_alerts.py chemin/vers/alertes.json
    python kg/import_alerts.py --dry-run             # sans Neo4j : simple vérification
"""
import ipaddress
import json
import sys
from pathlib import Path

DEFAULT_FILE = Path(__file__).resolve().parent.parent / "data" / "alerts_sample.json"
LOGIN_RULE_ID = "5501"   # "PAM: Login session opened" -> relation LOGGED_INTO

# Identifiants renommés dans les versions récentes d'ATT&CK (ancien -> nouveau)
TECH_ALIASES = {
    "T1562.001": "T1685",   # Disable or Modify Tools
}


def is_internal(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return None


def prepare(alerts):
    """Transforme les alertes en lignes prêtes pour Neo4j. Ignore les valeurs null."""
    alert_rows, ip_links, user_links, tech_links, login_links = [], [], [], [], []
    skipped = 0
    for a in alerts:
        aid = a.get("alert_id")
        host = a.get("hostname")
        if not aid or not host:
            skipped += 1
            continue
        alert_rows.append({
            "id": str(aid),
            "timestamp": a.get("timestamp"),
            "severity": a.get("severity"),
            "rule_id": str(a["rule_id"]) if a.get("rule_id") is not None else None,
            "rule_desc": a.get("rule_desc"),
            "host": host,
            "mitre_raw": a.get("mitre_technique"),
        })
        for role, key in (("src", "src_ip"), ("dst", "dst_ip")):
            ip = a.get(key)
            if ip:
                ip_links.append({"id": str(aid), "ip": ip, "role": role,
                                 "internal": is_internal(ip)})
        user = a.get("user")
        if user:
            user_links.append({"id": str(aid), "user": user})
            if str(a.get("rule_id")) == LOGIN_RULE_ID:
                login_links.append({"user": user, "host": host})
        tech = a.get("mitre_technique")
        if tech and tech.lower() != "none":
            tech_links.append({"id": str(aid), "tech": TECH_ALIASES.get(tech, tech)})
    return alert_rows, ip_links, user_links, tech_links, login_links, skipped


def main():
    args = [x for x in sys.argv[1:] if not x.startswith("--")]
    dry = "--dry-run" in sys.argv
    path = Path(args[0]) if args else DEFAULT_FILE
    alerts = json.loads(path.read_text(encoding="utf-8"))
    alert_rows, ip_links, user_links, tech_links, login_links, skipped = prepare(alerts)

    print(f"Fichier : {path}")
    print(f"Alertes lues : {len(alerts)} | valides : {len(alert_rows)} | ignorées : {skipped}")
    print(f"Liens prévus : {len(ip_links)} INVOLVES(IP), {len(user_links)} INVOLVES(User), "
          f"{len(tech_links)} MAPPED_TO, {len({(l['user'], l['host']) for l in login_links})} LOGGED_INTO")
    if dry:
        print("Mode --dry-run : rien n'est écrit dans Neo4j.")
        return

    from config import get_driver   # import tardif : le mode --dry-run n'a pas besoin de .env
    driver = get_driver()
    with driver.session() as s:
        s.run("UNWIND $rows AS r "
              "MERGE (a:Alert {alert_id:r.id}) "
              "SET a.timestamp=r.timestamp, a.severity=r.severity, "
              "    a.rule_id=r.rule_id, a.rule_desc=r.rule_desc, "
              "    a.mitre_raw=r.mitre_raw "
              "MERGE (h:Host {hostname:r.host}) "
              "MERGE (a)-[:TRIGGERED_ON]->(h)", rows=alert_rows)
        s.run("UNWIND $rows AS r "
              "MATCH (a:Alert {alert_id:r.id}) "
              "MERGE (i:IP {address:r.ip}) SET i.is_internal=r.internal "
              "MERGE (a)-[:INVOLVES {role:r.role}]->(i)", rows=ip_links)
        s.run("UNWIND $rows AS r "
              "MATCH (a:Alert {alert_id:r.id}) "
              "MERGE (u:User {username:r.user}) "
              "MERGE (a)-[:INVOLVES]->(u)", rows=user_links)
        res = s.run("UNWIND $rows AS r "
                    "MATCH (a:Alert {alert_id:r.id}) "
                    "OPTIONAL MATCH (t:Technique {attack_id:r.tech}) "
                    "FOREACH (_ IN CASE WHEN t IS NULL THEN [] ELSE [1] END | "
                    "  MERGE (a)-[:MAPPED_TO]->(t)) "
                    "RETURN r.tech AS tech, t IS NULL AS missing", rows=tech_links)
        missing = sorted({r["tech"] for r in res if r["missing"]})
        s.run("UNWIND $rows AS r "
              "MATCH (u:User {username:r.user}), (h:Host {hostname:r.host}) "
              "MERGE (u)-[:LOGGED_INTO]->(h)", rows=login_links)
        counts = {k: s.run(q).single()["c"] for k, q in {
            "Alert": "MATCH (n:Alert) RETURN count(n) AS c",
            "Host": "MATCH (n:Host) RETURN count(n) AS c",
            "IP": "MATCH (n:IP) RETURN count(n) AS c",
            "User": "MATCH (n:User) RETURN count(n) AS c",
            "TRIGGERED_ON": "MATCH ()-[r:TRIGGERED_ON]->() RETURN count(r) AS c",
            "INVOLVES": "MATCH ()-[r:INVOLVES]->() RETURN count(r) AS c",
            "MAPPED_TO": "MATCH ()-[r:MAPPED_TO]->() RETURN count(r) AS c",
            "LOGGED_INTO": "MATCH ()-[r:LOGGED_INTO]->() RETURN count(r) AS c",
        }.items()}
    driver.close()
    print("Dans Neo4j :", ", ".join(f"{k}={v}" for k, v in counts.items()))
    if missing:
        print("Techniques absentes du graphe ATT&CK (aucun lien MAPPED_TO créé) :", missing)


if __name__ == "__main__":
    main()