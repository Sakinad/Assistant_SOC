"""Chroma-backed vector store (decision recorded in ADR-0001).

Why a wrapper instead of using the Chroma client directly?

* **Single retrieval entry point** — agents (Chayma) and Graph-RAG (Karima) call
  :meth:`VectorStore.query`, so switching to Qdrant later means rewriting one class.
* **Explicit embeddings** — the collection never uses Chroma's implicit embedding
  function, so the encoder is always the one described in ADR-0002.
* **Stable result type** — :class:`RetrievedChunk` with a cosine *score* in ``[0, 1]``
  instead of a raw distance that changes meaning with the metric.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import chromadb
from chromadb.config import Settings as ChromaSettings

from cybersoc.rag.chunking import Chunk
from cybersoc.rag.embeddings import Embedder


@dataclass(frozen=True)
class RetrievedChunk:
    """A retrieved passage, ready to be injected in a prompt."""

    chunk_id: str
    text: str
    score: float
    metadata: dict[str, Any] = field(default_factory=dict)


class VectorStore:
    """Persistent Chroma collection with cosine similarity.

    Args:
        path: directory holding the persistent store (created if missing).
        collection: collection name.
        embedder: encoder used for documents and queries. Required for
            :meth:`add_chunks` and text queries.
        batch_size: number of vectors pushed per ``upsert`` call.
    """

    def __init__(
        self,
        path: str | Path = "data/indexes/chroma",
        collection: str = "soc_kb",
        embedder: Embedder | None = None,
        *,
        batch_size: int = 128,
    ) -> None:
        self.path = Path(path).expanduser()
        self.path.mkdir(parents=True, exist_ok=True)
        self.collection_name = collection
        self.embedder = embedder
        self.batch_size = batch_size

        self._client = chromadb.PersistentClient(
            path=str(self.path),
            settings=ChromaSettings(anonymized_telemetry=False),
        )
        self._collection = self._client.get_or_create_collection(
            name=collection,
            embedding_function=None,  # embeddings are always supplied explicitly
            metadata={"hnsw:space": "cosine"},
        )

    # -- introspection ----------------------------------------------------
    def count(self) -> int:
        """Number of chunks in the collection."""
        return int(self._collection.count())

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"VectorStore(path={str(self.path)!r}, collection={self.collection_name!r})"

    # -- write ------------------------------------------------------------
    def add_chunks(self, chunks: Sequence[Chunk], *, batch_size: int | None = None) -> int:
        """Upsert chunks (idempotent: re-ingesting the same ids overwrites them).

        Returns:
            Number of chunks submitted.
        """
        if self.embedder is None:
            raise RuntimeError("VectorStore.embedder is required to add chunks")
        chunks = list(chunks)
        if not chunks:
            return 0

        step = batch_size or self.batch_size
        for start in range(0, len(chunks), step):
            batch = chunks[start : start + step]
            vectors = self.embedder.embed_documents([c.text for c in batch])
            if len(vectors) != len(batch):
                raise RuntimeError(
                    f"embedder returned {len(vectors)} vectors for {len(batch)} chunks"
                )
            self._collection.upsert(
                ids=[c.chunk_id for c in batch],
                documents=[c.text for c in batch],
                embeddings=vectors,
                metadatas=[_clean_metadata(c.metadata) for c in batch],
            )
        return len(chunks)

    def delete(self, where: Mapping[str, Any] | None = None) -> None:
        """Delete chunks matching a metadata filter (all chunks if ``where`` is None)."""
        if where is None:
            self._delete_all()
            return
        self._collection.delete(where=dict(where))

    def _delete_all(self) -> None:
        existing = self._collection.get(include=[])
        ids = existing.get("ids") or []
        if ids:
            self._collection.delete(ids=list(ids))

    def reset(self) -> None:
        """Drop and recreate the collection."""
        self._client.delete_collection(self.collection_name)
        self._collection = self._client.get_or_create_collection(
            name=self.collection_name,
            embedding_function=None,
            metadata={"hnsw:space": "cosine"},
        )

    # -- read -------------------------------------------------------------
    def query(
        self,
        text: str | None = None,
        *,
        embedding: Sequence[float] | None = None,
        top_k: int = 5,
        where: Mapping[str, Any] | None = None,
    ) -> list[RetrievedChunk]:
        """Return the ``top_k`` closest chunks, best first.

        Args:
            text: query string (encoded with the embedder, instruction included).
            embedding: pre-computed query vector; mutually exclusive with ``text``.
            top_k: number of results.
            where: Chroma metadata filter, e.g. ``{"source_type": "mitre_attack"}``.

        Raises:
            ValueError: if neither or both of ``text`` / ``embedding`` are given.
        """
        if (text is None) == (embedding is None):
            raise ValueError("provide exactly one of 'text' or 'embedding'")
        if top_k <= 0:
            raise ValueError("top_k must be positive")
        if self.count() == 0:
            return []

        if embedding is None:
            if self.embedder is None:
                raise RuntimeError("VectorStore.embedder is required for text queries")
            embedding = self.embedder.embed_query(str(text))

        result = self._collection.query(
            query_embeddings=[list(embedding)],
            n_results=min(top_k, self.count()),
            where=dict(where) if where else None,
            include=["documents", "metadatas", "distances"],
        )

        ids = (result.get("ids") or [[]])[0]
        documents = (result.get("documents") or [[]])[0]
        metadatas = (result.get("metadatas") or [[]])[0]
        distances = (result.get("distances") or [[]])[0]

        retrieved: list[RetrievedChunk] = []
        for chunk_id, document, metadata, distance in zip(
            ids, documents, metadatas, distances, strict=False
        ):
            retrieved.append(
                RetrievedChunk(
                    chunk_id=str(chunk_id),
                    text=str(document or ""),
                    score=_distance_to_score(distance),
                    metadata=dict(metadata or {}),
                )
            )
        return retrieved


def _distance_to_score(distance: float | None) -> float:
    """Convert a cosine distance to a similarity score in ``[0, 1]``."""
    if distance is None:
        return 0.0
    return max(0.0, min(1.0, 1.0 - float(distance)))


def _clean_metadata(metadata: Mapping[str, Any]) -> dict[str, Any]:
    """Chroma metadata values must be str / int / float / bool (no None, no list)."""
    cleaned: dict[str, Any] = {}
    for key, value in metadata.items():
        if value is None:
            continue
        if isinstance(value, (str, int, float, bool)):
            cleaned[str(key)] = value
        elif isinstance(value, (list, tuple)):
            cleaned[str(key)] = ",".join(str(item) for item in value)
        else:
            cleaned[str(key)] = str(value)
    return cleaned
