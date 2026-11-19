# Benchmark Qwen/Qwen2.5-3B-Instruct vs microsoft/Phi-3.5-mini-instruct

Précision FP16, décodage déterministe, prompt `v2-explanation`, GPU Tesla T4. Les intervalles [min-max] sont des intervalles de confiance à 95 % (Wilson).

## QCM de culture cyber

| Métrique | Qwen/Qwen2.5-3B-Instruct | microsoft/Phi-3.5-mini-instruct |
|---|---|---|
| Accuracy | 86.7 % [70-95] | 83.3 % [66-93] |
| Réponses non interprétées | 0 | 0 |
| Latence moyenne (s) | 0.091 | 0.211 |

## Classification d'alertes : alerts_cyber (40 alertes)

| Métrique | Qwen/Qwen2.5-3B-Instruct | microsoft/Phi-3.5-mini-instruct |
|---|---|---|
| Accuracy de la catégorie | 92.5 % [80-97] | 87.5 % [74-94] |
| Macro-F1 de la catégorie | 0.926 | 0.876 |
| Accuracy de la sévérité | 57.5 % | 60.0 % |
| Accuracy de la technique MITRE | 22.5 % | 30.0 % |
| Format de sortie invalide | 0.0 % | 0.0 % |
| Technique MITRE inexistante | 5.0 % | 22.5 % |
| Entités inventées dans l'explication | 0.0 % | 0.0 % |
| **Taux d'hallucination (global)** | 5.0 % | 22.5 % |
| Latence moyenne / p95 (s) | 2.226 / 2.914 | 3.563 / 5.816 |
| Tokens/s (requête unique) | 23.2 | 24.6 |

## Classification d'alertes : alerts_soc_logs (40 alertes)

| Métrique | Qwen/Qwen2.5-3B-Instruct | microsoft/Phi-3.5-mini-instruct |
|---|---|---|
| Accuracy de la catégorie | 92.5 % [80-97] | 92.5 % [80-97] |
| Macro-F1 de la catégorie | 0.914 | 0.917 |
| Accuracy de la sévérité | 32.5 % | 25.0 % |
| Accuracy de la technique MITRE | 25.0 % | 30.0 % |
| Format de sortie invalide | 0.0 % | 0.0 % |
| Technique MITRE inexistante | 10.0 % | 20.0 % |
| Entités inventées dans l'explication | 0.0 % | 0.0 % |
| **Taux d'hallucination (global)** | 10.0 % | 20.0 % |
| Latence moyenne / p95 (s) | 2.302 / 2.694 | 3.457 / 5.741 |
| Tokens/s (requête unique) | 23.3 | 24.7 |

## Mémoire et débit

| Métrique | Qwen/Qwen2.5-3B-Instruct | microsoft/Phi-3.5-mini-instruct |
|---|---|---|
| Temps de chargement (s) | 34.2 | 31.4 |
| VRAM après chargement (Go) | 5.75 | 7.12 |
| VRAM pic, requête unique (Go) | 5.78 | 7.27 |
| Débit, batch 1 (tokens/s) | 23.2 | 24.5 |
| Débit, batch 1 (alertes/s) | 0.44 | 0.41 |
| VRAM pic, batch 1 (Go) | 5.78 | 7.24 |
| Débit, batch 4 (tokens/s) | 69.5 | 74.5 |
| Débit, batch 4 (alertes/s) | 1.32 | 1.24 |
| VRAM pic, batch 4 (Go) | 5.85 | 7.56 |
| Débit, batch 8 (tokens/s) | 121.8 | 121.9 |
| Débit, batch 8 (alertes/s) | 2.32 | 2.03 |
| VRAM pic, batch 8 (Go) | 5.95 | 8.0 |

## Écarts statistiquement significatifs ?

Test exact de McNemar sur les exemples bien classés (QCM : bonne lettre ; alertes : bonne catégorie).

| Jeu de test | Réussis par A seulement | Réussis par B seulement | p-value |
|---|---|---|---|
| alerts_cyber | 3 | 1 | 0.625 |
| alerts_soc_logs | 0 | 0 | 1.000 |
| qa_cyber | 3 | 2 | 1.000 |

Une p-value supérieure à 0,05 signifie que l'écart observé peut être dû au hasard (jeu de test de petite taille).
