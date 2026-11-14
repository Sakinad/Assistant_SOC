"""Corpus ingestion CLI: files -> chunks -> embeddings -> Chroma.

Usage (from the repository root)::

    python -m cybersoc.rag.ingest --source data/raw --dry-run
    python -m cybersoc.rag.ingest --source data/raw --rebuild
    python -m cybersoc.rag.ingest --source data/raw --top-k 3 --query "T1059 powershell"

Supported inputs: ``.md``, ``.txt`` and ``.jsonl`` (one JSON object per line with
an ``id`` and a ``text`` field; other fields become metadata).

The corpus itself (MITRE ATT&CK, CVE/CWE, threat intel) is collected in week 2;
this CLI is the single entry point that will ingest it.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from cybersoc.config import get_settings
from cybersoc.rag.chunking import chunks_from_records
from cybersoc.rag.embeddings import DeterministicHashEmbedder, SentenceTransformerEmbedder
from cybersoc.rag.vectorstore import VectorStore

LOGGER = logging.getLogger("cybersoc.rag.ingest")

SUPPORTED_SUFFIXES = {".md", ".txt", ".jsonl"}


def _infer_source_type(path: Path, root: Path) -> str:
    """Infer the source type from the first sub-directory.

    ``raw/mitre_attack/`` becomes ``mitre_attack``.
    """
    try:
        relative = path.relative_to(root)
    except ValueError:
        return "unknown"
    return relative.parts[0] if len(relative.parts) > 1 else "unknown"


def iter_records(source: Path) -> Iterator[dict[str, Any]]:
    """Yield ``{"id", "text", <metadata>}`` records from a file or directory."""
    files = [source] if source.is_file() else sorted(source.rglob("*"))
    for path in files:
        if not path.is_file() or path.suffix.lower() not in SUPPORTED_SUFFIXES:
            continue

        root = source if source.is_dir() else source.parent
        base_meta = {
            "source_file": str(path.relative_to(root)).replace("\\", "/"),
            "source_type": _infer_source_type(path, root),
        }

        if path.suffix.lower() == ".jsonl":
            with path.open("r", encoding="utf-8") as handle:
                for line_no, line in enumerate(handle, start=1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        LOGGER.warning("skipping malformed JSON at %s:%s", path, line_no)
                        continue
                    text = record.get("text") or record.get("content")
                    if not text:
                        LOGGER.warning("skipping record without text at %s:%s", path, line_no)
                        continue
                    doc_id = str(record.get("id") or f"{path.stem}-{line_no}")
                    extra = {
                        k: v
                        for k, v in record.items()
                        if k not in {"id", "text", "content"}
                    }
                    yield {"id": doc_id, "text": text, **base_meta, **extra}
            continue

        text = path.read_text(encoding="utf-8", errors="replace").strip()
        if not text:
            continue
        yield {"id": path.stem, "text": text, **base_meta}


def build_embedder(use_hash: bool = False):
    """Return the production embedder, or the offline hash embedder for smoke tests."""
    settings = get_settings()
    if use_hash:
        return DeterministicHashEmbedder(dimension=settings.embedding_dim)
    return SentenceTransformerEmbedder(
        settings.embedding_model,
        device=settings.embedding_device,
        batch_size=settings.embedding_batch_size,
        dimension=settings.embedding_dim,
    )


def run_ingest(
    source: Path,
    *,
    dry_run: bool = False,
    rebuild: bool = False,
    use_hash: bool = False,
    query: str | None = None,
    top_k: int | None = None,
) -> dict[str, Any]:
    """Ingest ``source`` into the vector store and return a small summary."""
    settings = get_settings()
    settings.ensure_dirs()

    records = list(iter_records(source))
    if not records:
        raise SystemExit(
            f"No supported document found in {source} (expected {sorted(SUPPORTED_SUFFIXES)})"
        )

    chunks = chunks_from_records(
        records,
        chunk_size=settings.chunk_size,
        overlap=settings.chunk_overlap,
    )
    summary: dict[str, Any] = {
        "documents": len(records),
        "chunks": len(chunks),
        "source": str(source),
    }

    if dry_run:
        summary["dry_run"] = True
        summary["sample"] = [
            {"chunk_id": c.chunk_id, "chars": len(c.text)} for c in chunks[:3]
        ]
        return summary

    embedder = build_embedder(use_hash=use_hash)
    store = VectorStore(
        path=settings.chroma_path,
        collection=settings.chroma_collection,
        embedder=embedder,
    )
    if rebuild:
        store.reset()

    store.add_chunks(chunks)
    summary["collection_count"] = store.count()

    if query:
        hits = store.query(query, top_k=top_k or settings.top_k)
        summary["query"] = query
        summary["hits"] = [
            {"chunk_id": h.chunk_id, "score": round(h.score, 4)} for h in hits
        ]

    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Ingest a corpus into the Chroma vector store.")
    parser.add_argument("--source", type=Path, required=True, help="file or directory to ingest")
    parser.add_argument("--dry-run", action="store_true", help="chunk only, do not touch the store")
    parser.add_argument("--rebuild", action="store_true", help="drop the collection first")
    parser.add_argument("--hash-embedder", action="store_true", help="offline test embedder")
    parser.add_argument("--query", type=str, default=None, help="smoke-test query after ingestion")
    parser.add_argument("--top-k", type=int, default=None, help="number of results per query")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )

    if not args.source.exists():
        parser.error(f"source not found: {args.source}")

    summary = run_ingest(
        args.source,
        dry_run=args.dry_run,
        rebuild=args.rebuild,
        use_hash=args.hash_embedder,
        query=args.query,
        top_k=args.top_k,
    )
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
