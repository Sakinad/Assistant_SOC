# Benchmark et fine-tuning des SLM (Fati, semaines 2 à 4)

Ce dossier contient les jeux de test cyber, le script de benchmark et le script de comparaison.

## Contenu
| Fichier | Rôle |
|---|---|
| `data/qa_cyber.jsonl` | 30 QCM de culture cyber (MITRE ATT&CK, CVE/CWE, réseau, Windows, sécurité des LLM) |
| `data/alerts_cyber.jsonl` | 40 alertes SOC rédigées à la main (Fati) : 8 catégories, 5 alertes par catégorie, sévérité, technique(s) MITRE acceptée(s) |
| `data/alerts_soc_logs.jsonl` | 40 alertes issues de flux réseau et de logs (Sakina), même format |
| `data/mitre_attack_ids.txt` | IDs ATT&CK Enterprise valides (techniques et sous-techniques), extraits de la base officielle MITRE, pour détecter les techniques inventées |
| `evaluate.py` | Évalue un modèle et écrit `results/benchmark_<tag>.json` et `results/benchmark_<tag>_predictions.jsonl` |
| `compare.py` | Compare deux modèles et écrit `results/benchmark_comparison.md` |
| `build_finetune_data.py` | Génère le dataset de fine-tuning dans `data/finetune/` (train.jsonl, val.jsonl, stats.json) |
| `finetune_qlora.py` | Fine-tuning LoRA / QLoRA ; écrit l'adaptateur (hors dépôt) et `results/finetune_<tag>.json` |

## Format des données
- QCM : `{"id", "question", "options" (4), "answer" (A-D)}`
- Alerte : `{"id", "alert", "category", "severity", "mitre"}` (`mitre` : un ID ou une liste d'IDs acceptés)
- Catégories : brute_force, port_scan, sql_injection, phishing, ransomware, data_exfiltration, privilege_escalation, benign
- Sévérités : low, medium, high, critical

## Métriques
- **Accuracy et F1** : QCM (accuracy) ; alertes (accuracy et macro-F1 de la catégorie, accuracy de la sévérité et de la technique MITRE). Intervalles de confiance à 95 % (Wilson) et test de McNemar pour savoir si l'écart entre deux modèles est significatif.
- **Hallucination** (mesure opérationnelle, appliquée aux alertes) :
  - *technique MITRE inexistante* : l'ID proposé n'existe pas dans ATT&CK ;
  - *entités inventées* : l'explication cite une adresse IP, un CVE ou un nom de machine absent de l'alerte ;
  - *taux global* : au moins l'un des deux cas ci-dessus ;
  - *format invalide* : la réponse n'est pas un JSON avec une catégorie et une sévérité autorisées.
- **Latence** : moyenne, médiane, p95 (requête unique), tokens/s.
- **Débit** : tokens/s et alertes/s avec des lots de 1, 4 et 8 prompts (génération Hugging Face, sans vLLM).
- **Mémoire** : VRAM après chargement, pic en requête unique, pic par taille de lot ; temps de chargement.

## Lancer
```bash
pip install -U transformers accelerate        # sur Colab avec GPU T4
python evaluation/evaluate.py --model Qwen/Qwen2.5-3B-Instruct --tag qwen2.5-3b_fp16
python evaluation/evaluate.py --model microsoft/Phi-3.5-mini-instruct --tag phi3.5-mini_fp16
python evaluation/compare.py --a qwen2.5-3b_fp16 --b phi3.5-mini_fp16
```
Test du script sans GPU : `python evaluation/evaluate.py --mock --tag mock`

## Limites
- Petits jeux de test (30 + 40 + 40 exemples) : les écarts de quelques points ne sont pas significatifs (voir les intervalles de confiance et la p-value).
- `alerts_soc_logs.jsonl` : les 20 premières alertes (flux réseau) citent le type d'attaque dans leur texte (par exemple « SQL injection web attack pattern ») ; la tâche y est donc plus facile. Les deux jeux d'alertes sont toujours rapportés séparément, jamais moyennés.
- La mesure d'hallucination est un indicateur approché : elle ne détecte que les techniques inexistantes et les entités (IP, CVE, noms de machines) inventées, pas les erreurs de raisonnement.
- Décodage déterministe (sans échantillonnage) ; une seule exécution par modèle.

## Fine-tuning LoRA / QLoRA (semaine 4)

**Objectif** : spécialiser un SLM dans le triage d'alertes SOC (catégorie, sévérité, technique MITRE, explication courte, en JSON).

**Dataset** (`build_finetune_data.py`, graine 42) :
- 1 200 exemples d'entraînement (150 par catégorie) et 120 de validation (15 par catégorie), au format conversation (system / user / assistant) avec exactement le prompt du benchmark ;
- généré à partir de 80 gabarits (8 catégories × 10) avec des valeurs aléatoires (IP, machines, comptes, compteurs) ; les formats varient (journaux système, règles SIEM, alertes EDR, phrases libres) ;
- les explications ne citent que des éléments présents dans l'alerte, pour entraîner le modèle à ne rien inventer ;
- 2 gabarits par catégorie sont réservés à la validation (formulations jamais vues à l'entraînement) ;
- toute alerte trop proche d'une alerte des jeux de test (similarité de Jaccard ≥ 0,6) est supprimée : aucune alerte de test n'est dans les données d'entraînement ni de validation ;
- le script vérifie aussi que chaque ID MITRE existe dans ATT&CK.

**Entraînement** (`finetune_qlora.py`) : QLoRA (modèle de base gelé en 4 bits NF4, adaptateurs LoRA de rang 16, alpha 32, sur toutes les couches linéaires), 3 époques, taux d'apprentissage 2e-4, taille de lot effective 16, FP16, perte calculée uniquement sur la réponse de l'assistant. L'adaptateur est stocké hors du dépôt (Google Drive).

**Limites**
- Données synthétiques à gabarits : le modèle peut apprendre les formulations. La validation sur gabarits inédits et, surtout, l'évaluation sur `alerts_soc_logs.jsonl` (autre auteur, autre format) servent à vérifier la généralisation.
- La sévérité est une convention : elle suit les règles du jeu `alerts_cyber.jsonl` et peut différer de celle d'autres jeux (par exemple `alerts_soc_logs.jsonl`).
- La comparaison Base vs Fine-tuned (semaine 5) utilise les jeux de test du benchmark, jamais vus à l'entraînement.
