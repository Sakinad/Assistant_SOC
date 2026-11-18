# Schéma du Knowledge Graph

## Nœuds
| Label | Clé unique | Propriétés |
|---|---|---|
| Alert | alert_id | severity, rule_id, rule_desc, timestamp |
| Host | hostname | os, criticality |
| IP | address | is_internal |
| User | username | |
| Vulnerability | cve_id | cvss, description |
| Weakness | cwe_id | name |
| Technique | attack_id | name, description |
| Tactic | shortname | name |
| Malware | name | description |
| IntrusionSet | name | description |

## Relations
(Alert)-[:TRIGGERED_ON]->(Host)
(Alert)-[:INVOLVES]->(IP)
(Alert)-[:INVOLVES]->(User)
(Alert)-[:MAPPED_TO]->(Technique)
(Technique)-[:PART_OF]->(Tactic)
(Technique)-[:SUBTECHNIQUE_OF]->(Technique)
(Host)-[:HAS_VULNERABILITY]->(Vulnerability)
(Vulnerability)-[:CAUSED_BY]->(Weakness)
(Malware)-[:USES]->(Technique)
(IntrusionSet)-[:USES]->(Technique)
(User)-[:LOGGED_INTO]->(Host)

## Exemple de requête
MATCH (a:Alert)-[:MAPPED_TO]->(t:Technique)-[:PART_OF]->(c:Tactic)
RETURN a.alert_id, t.name, c.name
