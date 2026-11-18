import requests
from config import get_driver

URL = ("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
       "master/enterprise-attack/enterprise-attack.json")


def ext_id(obj):
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")


def main():
    print("Téléchargement d'ATT&CK...")
    objects = requests.get(URL, timeout=120).json()["objects"]
    active = [o for o in objects
              if not o.get("revoked") and not o.get("x_mitre_deprecated")]

    tactics = [{"sn": o["x_mitre_shortname"], "name": o["name"], "id": ext_id(o)}
               for o in active if o["type"] == "x-mitre-tactic"]

    techniques, links, stix_to_node = [], [], {}
    for o in active:
        if o["type"] == "attack-pattern":
            tid = ext_id(o)
            techniques.append({"id": tid, "name": o["name"],
                               "desc": o.get("description", ""), "stix": o["id"]})
            stix_to_node[o["id"]] = ("Technique", "attack_id", tid)
            for p in o.get("kill_chain_phases", []):
                links.append({"id": tid, "sn": p["phase_name"]})

    malwares, groups = [], []
    for o in active:
        if o["type"] == "malware":
            malwares.append({"name": o["name"], "desc": o.get("description", "")})
            stix_to_node[o["id"]] = ("Malware", "name", o["name"])
        elif o["type"] == "intrusion-set":
            groups.append({"name": o["name"], "desc": o.get("description", "")})
            stix_to_node[o["id"]] = ("IntrusionSet", "name", o["name"])

    sub, uses = [], []
    for o in active:
        if o["type"] != "relationship":
            continue
        s, t = stix_to_node.get(o["source_ref"]), stix_to_node.get(o["target_ref"])
        if not s or not t:
            continue
        if o["relationship_type"] == "subtechnique-of":
            sub.append({"a": s[2], "b": t[2]})
        elif o["relationship_type"] == "uses" and t[0] == "Technique":
            uses.append({"label": s[0], "key": s[2], "tech": t[2]})

    driver = get_driver()
    with driver.session() as session:
        session.run("UNWIND $rows AS r MERGE (t:Tactic {shortname:r.sn}) "
                    "SET t.name=r.name, t.attack_id=r.id", rows=tactics)
        session.run("UNWIND $rows AS r MERGE (t:Technique {attack_id:r.id}) "
                    "SET t.name=r.name, t.description=r.desc, t.stix_id=r.stix",
                    rows=techniques)
        session.run("UNWIND $rows AS r "
                    "MATCH (t:Technique {attack_id:r.id}), (c:Tactic {shortname:r.sn}) "
                    "MERGE (t)-[:PART_OF]->(c)", rows=links)
        session.run("UNWIND $rows AS r "
                    "MATCH (x:Technique {attack_id:r.a}), (y:Technique {attack_id:r.b}) "
                    "MERGE (x)-[:SUBTECHNIQUE_OF]->(y)", rows=sub)
        session.run("UNWIND $rows AS r MERGE (m:Malware {name:r.name}) "
                    "SET m.description=r.desc", rows=malwares)
        session.run("UNWIND $rows AS r MERGE (g:IntrusionSet {name:r.name}) "
                    "SET g.description=r.desc", rows=groups)
        session.run("UNWIND $rows AS r "
                    "MATCH (m:Malware {name:r.key}), (t:Technique {attack_id:r.tech}) "
                    "MERGE (m)-[:USES]->(t)",
                    rows=[u for u in uses if u["label"] == "Malware"])
        session.run("UNWIND $rows AS r "
                    "MATCH (g:IntrusionSet {name:r.key}), (t:Technique {attack_id:r.tech}) "
                    "MERGE (g)-[:USES]->(t)",
                    rows=[u for u in uses if u["label"] == "IntrusionSet"])
    driver.close()
    print(f"OK : {len(tactics)} tactiques, {len(techniques)} techniques, "
          f"{len(malwares)} malwares, {len(groups)} groupes.")


if __name__ == "__main__":
    main()