# Journal des attaques simulées

Environnement : manager Wazuh (192.168.56.10), agent `victime-ubuntu`,
attaques lancées depuis Kali Linux et sur la machine cible elle-même.

## Tableau des alertes

| Date  | Attaque                        | Règle | Niveau | Technique MITRE |
|-------|---------------------------------|-------|--------|------------------|
| 11/11 | Compte suspect (création)      | 5902  | 8      | T1136            |
| 11/11 | Compte suspect (suppression)   | 5903  | 3      | T1136            |
| 11/11 | Sudo (succès)                   | 5402  | 3      | T1548            |
| 11/11 | Modification de fichier (FIM)   | 550   | 7      | T1565            |
| 11/11 | Brute force SSH (échecs)        | 5760  | 5      | T1110            |

## Détail des attaques

### Brute force SSH (T1110)
Commande (depuis Kali) :
\`\`\`bash
hydra -l root -P mots.txt -t 4 ssh://<IP-cible>
\`\`\`
Résultat : alertes répétées "sshd: authentication failed" (règle 5760)
et "PAM: User login failed" (règle 5503).

### Compte suspect (T1136)
\`\`\`bash
sudo useradd hacker
sudo userdel hacker
\`\`\`
Résultat : "New user added to the system" (5902) puis
"Group (or user) deleted from the system" (5903).

### Sudo réussi (T1548)
\`\`\`bash
sudo ls
\`\`\`
Résultat : "Successful sudo to ROOT executed" (5402).

### Intégrité de fichier / FIM (T1565)
Modification d'un fichier surveillé par syscheck.
Résultat : "Integrity checksum changed" (550), niveau 7 — alerte la
plus élevée observée.
