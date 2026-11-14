# Semaine 1 — choix techniques du socle RAG (Maroua)

> Périmètre : base de données vectorielle et modèle d'embeddings, plus la structure Python du socle RAG.
> Fichiers purement additionnels : aucun document, notebook ou résultat existant n'a été modifié.

## 1. Base de données vectorielle : Chroma

| Critère | FAISS | **Chroma** | Qdrant |
|---|---|---|---|
| Filtres metadata natifs | non | oui | oui |
| Persistance / CRUD | manuelle | oui | oui |
| Infrastructure | aucune | aucune (embarquée) | serveur (Docker) |
| Performance à notre échelle (~2·10⁵ chunks) | excellente | suffisante | excellente |
| Passage à l'échelle (>10⁶) | oui | non | oui |

**Décision : Chroma**, en mode persistant, métrique cosinus, embeddings fournis explicitement.

- Il offre nativement les trois fonctions qui coûteraient le plus cher à développer : filtrage par
  métadonnées, persistance, mise à jour incrémentale de la KB.
- FAISS est une librairie d'index, pas une base : il faudrait réécrire la couche métadonnées et le CRUD.
- Qdrant impose un service (Docker) que l'environnement de l'équipe ne fournit pas ; son atout
  (quantization) ne sert qu'au-delà de plusieurs millions de vecteurs.

**Bascule vers Qdrant** si : index > 10⁶ chunks, accès concurrents multiples, latence p95 > 300 ms,
ou besoin de quantization. Le retrieval passe par `VectorStore.query`, donc la migration ne touche
qu'une classe.

## 2. Embeddings : BAAI/bge-small-en-v1.5

| Modèle | Dim. | Fenêtre | Limite |
|---|---|---|---|
| all-MiniLM-L6-v2 | 384 | 256 tokens | tronque nos chunks de 800 caractères |
| **bge-small-en-v1.5** | 384 | 512 tokens | anglais uniquement |
| e5-small-v2 | 384 | 512 tokens | sensible à l'oubli des préfixes `query:`/`passage:` |
| bge-base-en-v1.5 | 768 | 512 tokens | index 2× plus gros, ~3× plus lent sur CPU |

**Décision : `bge-small-en-v1.5`**, 384 dimensions, vecteurs normalisés L2, cosinus, CPU.

- Fenêtre de 512 tokens : un chunk de 800 caractères n'est jamais coupé (256 tokens de MiniLM le
  feraient silencieusement, ce qui fausserait l'évaluation).
- 33 M paramètres : indexation et requêtes sur CPU, sans GPU.
- 384 dimensions : index 4× plus compact qu'en 768, indispensable pour 2·10⁵ chunks sur Colab.
- Modèle **figé** pendant l'expérience Base vs Fine-tuned (S4), pour ne pas polluer la comparaison.

**Paramètres** : instruction de requête BGE appliquée aux requêtes uniquement, documents sans préfixe,
`normalize_embeddings=True`.

**Vérification prévue** : comparer bge-small / e5-small / MiniLM sur notre corpus en Recall@5 et MRR@10
(S3–S4). Si l'écart est inférieur à 3 points, conserver bge-small.

## 3. Chunking

Paragraphe → phrase → découpe dure, 800 caractères, chevauchement 120, métadonnées par chunk
(`doc_id`, `chunk_index`, `source_type`) et identifiants déterministes `<doc_id>::0000` pour que la
ré-ingestion soit idempotente.
