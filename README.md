# CyberSOC AI — assistant SOC intelligent

Projet Master : assistant de Security Operations Center basé sur des SLM (Qwen, Phi),
un RAG hybride (vecteurs + Knowledge Graph) et des agents LangGraph.
Livrable final : 25 décembre 2026 (dépôt au plus tard le 30 décembre).

## État de la semaine 1 (jalon J1)

| Membre | Livrable | Fichiers |
|---|---|---|
| Fati | Environnement GPU, chargement et inférence de base Qwen2.5-3B / Phi-3.5-mini | `notebooks/week1_env_models/`, `results/week1_baseline_results.json` |
| **Maroua** | Choix de la base vectorielle et des embeddings, socle RAG, structure Python | `docs/week1_rag_choix_techniques.md`, `src/cybersoc/`, `tests/` |
| Karima | Schéma du Knowledge Graph (Neo4j) | à venir |
| Chayma | Workflow LangGraph et état partagé | à venir |
| Sakina | Wazuh opérationnel, attaques simulées, choix des datasets | `wazuh/attack-log.md`, `docs/datasets.md` |

## Choix techniques actés

- **Base vectorielle : Chroma** — persistante, embarquée, filtres metadata et CRUD natifs, sans serveur.
- **Embeddings : `BAAI/bge-small-en-v1.5`** — 384 dimensions, fenêtre 512 tokens, CPU.
- Justification complète : [`docs/week1_rag_choix_techniques.md`](docs/week1_rag_choix_techniques.md).

## Structure du dépôt

```
data/                     # datasets et index locaux (non versionnés)
docs/                     # choix techniques, datasets
notebooks/                # expériences Colab / Kaggle
results/                  # mesures et sorties d'expériences
scripts/check_env.py      # test de fumée de l'environnement
src/cybersoc/
├── config.py             # configuration (.env)
└── rag/                  # chunking, embeddings, vector store, ingestion
tests/                    # tests unitaires du socle RAG
wazuh/                    # journal des attaques simulées
```

## Installation

```bash
python -m venv .venv
.venv\Scripts\Activate.ps1          # Linux / macOS : source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
pip install -e .
copy .env.example .env              # puis renseigner les valeurs
```

## Vérification

```bash
python scripts/check_env.py         # environnement prêt
pytest -q                           # tests du socle RAG
```

## Ingestion de la base de connaissances

```bash
python -m cybersoc.rag.ingest --source data/processed --rebuild
```

## Données et modèles

- Datasets de référence : Drive partagé de l'équipe.
- Poids de modèles : Hugging Face Hub privé ou Drive.
- Aucun secret, dataset, index ou poids de modèle dans Git (voir `.gitignore`).

## Équipe et organisation

Fati (SLM, optimisation) · **Maroua (RAG, LLMOps)** · Karima (Knowledge Graph, front-end) ·
Chayma (agents, réponse) · Sakina (Wazuh, backend, sécurité LLM).

Une branche par personne (`feature/rag`, `feature/slm`, `feature/kg`, `feature/agents`,
`feature/backend`), pull request relue avant fusion dans `main`.
