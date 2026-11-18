# Évaluation des SLM : jeu de test cyber et scripts

Ce dossier contient le jeu de test cyber et le script d'évaluation (semaine 2, Fati).

## Contenu
| Fichier | Rôle |
|---|---|
| `data/qa_cyber.jsonl` | 30 QCM de culture cyber (MITRE ATT&CK, CVE/CWE, réseau, Windows, sécurité des LLM) |
| `data/alerts_cyber.jsonl` | 40 alertes SOC annotées : catégorie (8 classes, 5 alertes par classe), sévérité, technique(s) MITRE acceptée(s) |
| `evaluate.py` | Évalue un modèle et écrit les résultats dans `results/` |

## Format des données
- QCM : `{"id", "question", "options" (4), "answer" (A-D)}`
- Alerte : `{"id", "alert", "category", "severity", "mitre" (liste des IDs acceptés)}`
- Catégories : brute_force, port_scan, sql_injection, phishing, ransomware, data_exfiltration, privilege_escalation, benign
- Sévérités : low, medium, high, critical

## Métriques calculées
- QCM : accuracy, latence (moyenne, médiane, p95), tokens/s
- Alertes : accuracy et macro-F1 de la catégorie (avec précision, rappel et F1 par classe), accuracy de la sévérité, accuracy de la technique MITRE, taux de sortie au format invalide, latence, tokens/s
- Mémoire : pic de VRAM

## Lancer
```bash
pip install -U transformers accelerate     # sur Colab avec GPU T4
python evaluation/evaluate.py --model Qwen/Qwen2.5-3B-Instruct --tag qwen2.5-3b_fp16
python evaluation/evaluate.py --model microsoft/Phi-3.5-mini-instruct --tag phi3.5-mini_fp16
```
Test du script sans GPU : `python evaluation/evaluate.py --mock --tag mock`

Sorties : `results/eval_<tag>.json` (métriques) et `results/eval_<tag>_predictions.jsonl` (réponse brute du modèle pour chaque exemple, utile pour l'analyse d'erreurs).

## Limites
- Jeu de test de petite taille (30 + 40 exemples) : les écarts de quelques points entre deux modèles ne sont pas significatifs.
- Les réponses sont générées en mode déterministe (sans échantillonnage).
- Le taux d'hallucination complet sera mesuré en semaine 3 ; ici on suit seulement le taux de format invalide.
