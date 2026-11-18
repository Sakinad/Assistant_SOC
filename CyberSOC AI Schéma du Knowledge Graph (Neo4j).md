# CyberSOC AI : Schéma du Knowledge Graph (Neo4j)

**Auteure :** Karima (responsable Knowledge Graph et front-end) **Projet :** CyberSOC AI, équipe de 5 personnes **Date :** 8 novembre 2026 **Version :** 1.0 (livrable de la semaine 1)

## 1. Objectif

Le Knowledge Graph (KG) relie les alertes de sécurité collectées par Wazuh aux connaissances de référence (MITRE ATT&CK, CVE, CWE). Il permet de répondre à des questions comme : quelle technique d'attaque correspond à cette alerte, quels hôtes sont vulnérables, quels malwares ou groupes d'attaquants utilisent cette technique. Il alimente le Graph-RAG, les agents (Investigation, Threat Intelligence) et le dashboard React.

Ce document sert de contrat entre les modules : tous les membres de l'équipe utilisent les mêmes noms de nœuds, de propriétés et de relations.

## 2. Nœuds

| Label | Clé unique | Propriétés principales | Source |
| --- | --- | --- | --- |
| Alert | alert\_id | severity, rule\_id, rule\_desc, timestamp | Wazuh (JSON normalisé) |
| Host | hostname | os, criticality | Wazuh |
| IP | address | is\_internal | Wazuh |
| User | username |  | Wazuh |
| Vulnerability | cve\_id | cvss, description | NVD (CVE) |
| Weakness | cwe\_id | name | MITRE (CWE) |
| Technique | attack\_id | name, description, stix\_id | MITRE ATT&CK |
| Tactic | shortname | name, attack\_id | MITRE ATT&CK |
| Malware | name | description | MITRE ATT&CK |
| IntrusionSet | name | description | MITRE ATT&CK |

## 3. Relations

| Relation | Sens |
| --- | --- |
| TRIGGERED\_ON | (Alert) → (Host) |
| INVOLVES | (Alert) → (IP) et (Alert) → (User) |
| MAPPED\_TO | (Alert) → (Technique) |
| PART\_OF | (Technique) → (Tactic) |
| SUBTECHNIQUE\_OF | (Technique) → (Technique) |
| HAS\_VULNERABILITY | (Host) → (Vulnerability) |
| CAUSED\_BY | (Vulnerability) → (Weakness) |
| USES | (Malware) → (Technique) et (IntrusionSet) → (Technique) |
| LOGGED\_INTO | (User) → (Host) |

## 4. Contraintes d'unicité (Cypher)

```cypher
CREATE CONSTRAINT tech_id IF NOT EXISTS FOR (t:Technique) REQUIRE t.attack_id IS UNIQUE;
CREATE CONSTRAINT tactic_id IF NOT EXISTS FOR (t:Tactic) REQUIRE t.shortname IS UNIQUE;
CREATE CONSTRAINT cve_id IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.cve_id IS UNIQUE;
CREATE CONSTRAINT cwe_id IF NOT EXISTS FOR (w:Weakness) REQUIRE w.cwe_id IS UNIQUE;
CREATE CONSTRAINT alert_id IF NOT EXISTS FOR (a:Alert) REQUIRE a.alert_id IS UNIQUE;
CREATE CONSTRAINT host_name IF NOT EXISTS FOR (h:Host) REQUIRE h.hostname IS UNIQUE;
CREATE CONSTRAINT ip_addr IF NOT EXISTS FOR (i:IP) REQUIRE i.address IS UNIQUE;
```

## 5. Exemples de requêtes

Technique et tactique associées à chaque alerte :

```cypher
MATCH (a:Alert)-[:MAPPED_TO]->(t:Technique)-[:PART_OF]->(c:Tactic)
RETURN a.alert_id, t.name, c.name;
```

Hôtes touchés par une alerte de gravité élevée :

```cypher
MATCH (a:Alert {severity:'high'})-[:TRIGGERED_ON]->(h:Host)
RETURN h.hostname, count(a) AS nb_alertes ORDER BY nb_alertes DESC;
```

Malwares utilisant une technique donnée :

```cypher
MATCH (m:Malware)-[:USES]->(t:Technique {attack_id:'T1110'})
RETURN m.name;
```

## 6. Données attendues de Sakina (alertes normalisées)

Pour peupler le KG en semaine 3, chaque alerte JSON doit contenir : alert\_id, timestamp, severity, rule\_id, rule\_desc, hostname, IP source, IP destination, user, technique MITRE (attack\_id).

## 7. Plan de réalisation

| Semaine | Tâche | Statut |
| --- | --- | --- |
| S1 | Installation de Neo4j, modélisation du schéma | En cours de finalisation |
| S2 | Import MITRE ATT&CK, script d'import CVE/CWE | À faire |
| S3 | Peuplement avec les alertes Wazuh, requêtes Cypher de base | À faire |
| S4 | Graph-RAG : traversée du graphe, génération de requêtes Cypher | À faire |
| S5 | Agent Threat Intelligence, évaluation du Graph-RAG | À faire |
| S6-S7 | Hybrid RAG avec Maroua, dashboard React | À faire |

## 8. Remarques

- Neo4j est installé en local sur le poste de Karima. Les scripts d'import seront versionnés dans le dépôt commun afin que le graphe soit reproductible par n'importe quel membre.
- Aucun mot de passe n'est stocké dans le code : les identifiants sont placés dans un fichier .env exclu du dépôt.
- Le schéma peut évoluer (par exemple ajout d'un nœud Process) ; toute modification sera documentée dans ce fichier.
