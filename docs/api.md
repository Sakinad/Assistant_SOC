# Format JSON des alertes normalisées

Chaque alerte Wazuh est transformée dans ce format avant stockage, pour que les autres modules (agents, Knowledge Graph, dashboard) travaillent avec un schéma unique.

Échantillon actuel : 100 alertes, 8 techniques MITRE (T1110.001, T1078, T1548.003, T1531, T1136, T1110, T1565.001, T1562.001), généré à partir de 3 jours de simulation (11, 17 et 19 novembre 2026).

## Schéma

| Champ | Type | Description |
|---|---|---|
| alert_id | string | Identifiant unique de l'alerte Wazuh |
| timestamp | string (ISO 8601) | Date et heure de l'alerte |
| severity | integer | Niveau de sévérité (0-15) |
| rule_id | string | ID de la règle Wazuh |
| rule_desc | string | Description lisible de l'alerte |
| hostname | string | Nom de la machine ayant généré l'alerte |
| src_ip | string \| null | IP source (attaquant) |
| dst_ip | string \| null | IP de la machine ciblée |
| user | string \| null | Utilisateur concerné |
| mitre_technique | string \| null | Technique MITRE ATT&CK principale |

## Exemples

### Brute force SSH
```json
{
  "alert_id": "1794430113.2408712",
  "timestamp": "2026-11-11T20:48:33.136+0000",
  "severity": 5,
  "rule_id": "5760",
  "rule_desc": "sshd: authentication failed.",
  "hostname": "victime-ubuntu",
  "src_ip": "192.168.56.20",
  "dst_ip": "192.168.56.11",
  "user": "root",
  "mitre_technique": "T1110.001"
}
```

### Création d'utilisateur
```json
{
  "alert_id": "1794430169.2412930",
  "timestamp": "2026-11-11T20:49:29.452+0000",
  "severity": 8,
  "rule_id": "5902",
  "rule_desc": "New user added to the system.",
  "hostname": "victime-ubuntu",
  "src_ip": null,
  "dst_ip": "192.168.56.11",
  "user": null,
  "mitre_technique": "T1136"
}
```

### Évasion de défense (agent Wazuh arrêté)
```json
{
  "alert_id": "1794430353.2418043",
  "timestamp": "2026-11-11T20:52:33.941+0000",
  "severity": 3,
  "rule_id": "506",
  "rule_desc": "Wazuh agent stopped.",
  "hostname": "victime-ubuntu",
  "src_ip": null,
  "dst_ip": "192.168.56.11",
  "user": null,
  "mitre_technique": "T1562.001"
}
```
