# Format JSON des alertes normalisées

Chaque alerte Wazuh est transformée dans ce format avant stockage, pour que les autres modules (agents, dashboard) travaillent avec un schéma unique quelle que soit la source.

## Schéma

| Champ | Type | Description |
|---|---|---|
| id | string | Identifiant unique de l'alerte Wazuh |
| timestamp | string (ISO 8601) | Date et heure de l'alerte |
| source | string | Toujours "wazuh" pour le moment |
| host | string | Nom de la machine ayant généré l'alerte |
| rule_id | string | ID de la règle Wazuh |
| rule_description | string | Description lisible de l'alerte |
| severity | integer | Niveau de sévérité (0-15) |
| mitre_ids | array[string] | Techniques MITRE ATT&CK associées |
| src_ip | string \| null | IP source si applicable |
| raw_log | string | Log brut original |
| label | string \| null | Étiquette manuelle (non utilisée pour l'instant) |

## Exemples

### Brute force SSH
```json
{
  "id": "1794430113.2408712",
  "timestamp": "2026-11-11T20:48:33.136+0000",
  "source": "wazuh",
  "host": "victime-ubuntu",
  "rule_id": "5760",
  "rule_description": "sshd: authentication failed.",
  "severity": 5,
  "mitre_ids": ["T1110.001", "T1021.004"],
  "src_ip": "192.168.56.20",
  "raw_log": "Nov 11 20:48:30 machine2 sshd[18644]: Failed password for root from 192.168.56.20 port 41480 ssh2",
  "label": null
}
```

### Création d'utilisateur
```json
{
  "id": "1794430169.2412930",
  "timestamp": "2026-11-11T20:49:29.452+0000",
  "source": "wazuh",
  "host": "victime-ubuntu",
  "rule_id": "5902",
  "rule_description": "New user added to the system.",
  "severity": 8,
  "mitre_ids": ["T1136"],
  "src_ip": null,
  "raw_log": "Nov 11 20:49:27 machine2 useradd[18756]: new user: name=hacker, UID=1003, GID=1003, home=/home/hacker, shell=/bin/sh, from=/dev/pts/1",
  "label": null
}
```

### Évasion de défense (agent Wazuh arrêté)
```json
{
  "id": "1794430353.2418043",
  "timestamp": "2026-11-11T20:52:33.941+0000",
  "source": "wazuh",
  "host": "victime-ubuntu",
  "rule_id": "506",
  "rule_description": "Wazuh agent stopped.",
  "severity": 3,
  "mitre_ids": ["T1562.001"],
  "src_ip": null,
  "raw_log": "ossec: Agent stopped: 'victime-ubuntu->any'.",
  "label": null
}
```
