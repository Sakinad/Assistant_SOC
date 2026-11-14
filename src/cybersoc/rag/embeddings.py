"""Embedding backends.

Two implementations share the same :class:`Embedder` protocol:

* :class:`SentenceTransformerEmbedder` — the production backend
  (``BAAI/bge-small-en-v1.5``, see ADR-0002).
* :class:`DeterministicHashEmbedder` — a dependency-free, deterministic embedder
  used by the unit tests so that CI and offline machines can exercise the full
  pipeline without downloading model weights.

The model is loaded **lazily**: importing this module never triggers a download.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Sequence
from typing import Any, Protocol, runtime_checkable

import numpy as np

#: Instruction prefix recommended by the BGE family for retrieval queries.
#: It must be applied to the *query* only, never to the indexed documents.
BGE_QUERY_INSTRUCTION = "Represent this sentence for searching relevant passages: "

_TOKEN_RE = re.compile(r"[a-z0-9_]+")


@runtime_checkable
class Embedder(Protocol):
    """Minimal embedding interface used by the vector store."""

    dimension: int

    def embed_documents(self, texts: Sequence[str]) -> list[list[float]]:
        """Encode documents (no query instruction)."""

    def embed_query(self, text: str) -> list[float]:
        """Encode a single query (with the retrieval instruction if required)."""


class SentenceTransformerEmbedder:
    """``sentence-transformers`` backend, CPU by default.

    Args:
        model_name: Hugging Face model id, e.g. ``BAAI/bge-small-en-v1.5``.
        device: ``cpu``, ``cuda`` or ``mps``.
        batch_size: encoding batch size.
        dimension: expected dimension; a mismatch raises at first use.
        query_instruction: prefix applied by :meth:`embed_query`.
    """

    def __init__(
        self,
        model_name: str = "BAAI/bge-small-en-v1.5",
        *,
        device: str = "cpu",
        batch_size: int = 32,
        dimension: int | None = 384,
        query_instruction: str = BGE_QUERY_INSTRUCTION,
        model_kwargs: dict[str, Any] | None = None,
    ) -> None:
        self.model_name = model_name
        self.device = device
        self.batch_size = batch_size
        self._declared_dimension = dimension
        self.query_instruction = query_instruction
        self._model_kwargs = model_kwargs or {}
        self._model: Any | None = None
        self._dimension: int | None = dimension

    # -- internal ---------------------------------------------------------
    @property
    def model(self) -> Any:
        """The underlying ``SentenceTransformer`` (downloaded on first access)."""
        if self._model is None:
            from sentence_transformers import SentenceTransformer

            self._model = SentenceTransformer(
                self.model_name, device=self.device, **self._model_kwargs
            )
            actual = int(self._model.get_sentence_embedding_dimension())
            if self._declared_dimension is not None and actual != self._declared_dimension:
                raise ValueError(
                    f"Embedding dimension mismatch: {self.model_name} produces {actual} "
                    f"dimensions but {self._declared_dimension} was configured "
                    "(check EMBEDDING_DIM in .env)"
                )
            self._dimension = actual
        return self._model

    def _encode(self, texts: Sequence[str]) -> list[list[float]]:
        if not texts:
            return []
        vectors = self.model.encode(
            list(texts),
            batch_size=self.batch_size,
            normalize_embeddings=True,  # dot product == cosine similarity
            convert_to_numpy=True,
            show_progress_bar=False,
        )
        return np.asarray(vectors, dtype=np.float32).tolist()

    # -- protocol ---------------------------------------------------------
    @property
    def dimension(self) -> int:
        if self._dimension is None:
            _ = self.model  # triggers loading, which sets the dimension
        return int(self._dimension or 0)

    def embed_documents(self, texts: Sequence[str]) -> list[list[float]]:
        return self._encode([t for t in texts if t and t.strip()])

    def embed_query(self, text: str) -> list[float]:
        if not text or not text.strip():
            raise ValueError("query text must be non-empty")
        return self._encode([f"{self.query_instruction}{text.strip()}"])[0]

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return (
            f"SentenceTransformerEmbedder(model_name={self.model_name!r}, "
            f"device={self.device!r})"
        )


class DeterministicHashEmbedder:
    """Bag-of-words hashed embedder, L2-normalised and fully deterministic.

    Not a semantic model — it only captures lexical overlap. It exists so the
    vector-store tests run offline and fast.
    """

    def __init__(self, dimension: int = 64) -> None:
        if dimension <= 0:
            raise ValueError("dimension must be positive")
        self.dimension = dimension

    def _embed(self, text: str) -> list[float]:
        vector = np.zeros(self.dimension, dtype=np.float32)
        for token in _TOKEN_RE.findall(text.lower()):
            digest = hashlib.blake2b(token.encode("utf-8"), digest_size=8).digest()
            vector[int.from_bytes(digest, "big") % self.dimension] += 1.0
        norm = float(np.linalg.norm(vector))
        if norm > 0:
            vector /= norm
        return vector.tolist()

    def embed_documents(self, texts: Sequence[str]) -> list[list[float]]:
        return [self._embed(t) for t in texts]

    def embed_query(self, text: str) -> list[float]:
        return self._embed(text)
