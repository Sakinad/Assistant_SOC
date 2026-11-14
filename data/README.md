# `data/` — datasets et index locaux (non versionnés)

```
raw/        corpus téléchargés tels quels (ATT&CK, CVE, CTI)
processed/  documents normalisés, prêts pour le chunking (JSONL : {"id", "text", ...})
indexes/    index Chroma persistant
```

Reconstruire l'index :

```bash
python -m cybersoc.rag.ingest --source data/processed --rebuild
```

Copies de référence sur le Drive partagé. Rien de tout cela ne va dans Git.
