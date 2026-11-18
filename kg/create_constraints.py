from config import get_driver

CONSTRAINTS = [
    "CREATE CONSTRAINT tech_id IF NOT EXISTS FOR (t:Technique) REQUIRE t.attack_id IS UNIQUE",
    "CREATE CONSTRAINT tactic_id IF NOT EXISTS FOR (t:Tactic) REQUIRE t.shortname IS UNIQUE",
    "CREATE CONSTRAINT cve_id IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.cve_id IS UNIQUE",
    "CREATE CONSTRAINT cwe_id IF NOT EXISTS FOR (w:Weakness) REQUIRE w.cwe_id IS UNIQUE",
    "CREATE CONSTRAINT alert_id IF NOT EXISTS FOR (a:Alert) REQUIRE a.alert_id IS UNIQUE",
    "CREATE CONSTRAINT host_name IF NOT EXISTS FOR (h:Host) REQUIRE h.hostname IS UNIQUE",
    "CREATE CONSTRAINT ip_addr IF NOT EXISTS FOR (i:IP) REQUIRE i.address IS UNIQUE",
    "CREATE CONSTRAINT malware_name IF NOT EXISTS FOR (m:Malware) REQUIRE m.name IS UNIQUE",
    "CREATE CONSTRAINT intrusion_name IF NOT EXISTS FOR (i:IntrusionSet) REQUIRE i.name IS UNIQUE",
    "CREATE CONSTRAINT user_name IF NOT EXISTS FOR (u:User) REQUIRE u.username IS UNIQUE",
]

if __name__ == "__main__":
    driver = get_driver()
    with driver.session() as s:
        for c in CONSTRAINTS:
            s.run(c)
    driver.close()
    print(f"{len(CONSTRAINTS)} contraintes créées.")