"""Structure-aware chunking for cybersecurity knowledge bases.

Strategy: split on the *largest* natural boundary that fits, in this order —
paragraph, sentence, then a hard slice. This preserves the local context of a
technique description or a CVE entry, which naive fixed-size slicing destroys.

Every produced chunk is at most ``chunk_size`` characters. Consecutive chunks
carry an ``overlap`` prefix from the previous chunk **when the next unit is small
enough to fit**; for very long units the overlap is dropped rather than emitting
an oversized chunk (the size guarantee wins).
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

_PARAGRAPH_SEP = re.compile(r"\n\s*\n")
_SENTENCE_SEP = re.compile(r"(?<=[.!?])\s+")


@dataclass(frozen=True)
class Chunk:
    """A chunk ready to be embedded and stored."""

    chunk_id: str
    text: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.chunk_id:
            raise ValueError("chunk_id must be a non-empty string")
        if not self.text.strip():
            raise ValueError(f"chunk {self.chunk_id!r} has empty text")


def _hard_slice(text: str, size: int) -> list[str]:
    return [text[i : i + size] for i in range(0, len(text), size)]


def _split_sentences(paragraph: str) -> list[str]:
    return [part.strip() for part in _SENTENCE_SEP.split(paragraph) if part.strip()]


def _units(text: str, max_len: int) -> list[str]:
    """Break the text into atomic units, each at most ``max_len`` characters."""
    units: list[str] = []
    for paragraph in _PARAGRAPH_SEP.split(text):
        paragraph = paragraph.strip()
        if not paragraph:
            continue
        if len(paragraph) <= max_len:
            units.append(paragraph)
            continue
        for sentence in _split_sentences(paragraph):
            if len(sentence) <= max_len:
                units.append(sentence)
            else:
                units.extend(_hard_slice(sentence, max_len))
    return units


def _overlap_tail(text: str, overlap: int) -> str:
    """Return the last ``overlap`` characters of ``text``, snapped to a word start."""
    if overlap <= 0 or not text:
        return ""
    tail = text[-overlap:]
    space = tail.find(" ")
    if space != -1:
        tail = tail[space + 1 :]
    return tail.strip()


def chunk_text(text: str, chunk_size: int = 800, overlap: int = 120) -> list[str]:
    """Split ``text`` into chunks of at most ``chunk_size`` characters.

    Args:
        text: input document.
        chunk_size: maximum number of characters per chunk.
        overlap: number of characters repeated from the previous chunk.

    Returns:
        The list of chunks (empty if the input is blank).

    Raises:
        ValueError: if ``chunk_size`` is not positive or ``overlap`` is out of range.
    """
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")
    if overlap < 0 or overlap >= chunk_size:
        raise ValueError("overlap must satisfy 0 <= overlap < chunk_size")

    text = (text or "").strip()
    if not text:
        return []

    chunks: list[str] = []
    current = ""

    for unit in _units(text, chunk_size):
        candidate = f"{current}\n\n{unit}" if current else unit
        if len(candidate) <= chunk_size:
            current = candidate
            continue

        if current:
            chunks.append(current)

        tail = _overlap_tail(current, overlap)
        combined = f"{tail}\n\n{unit}" if tail else unit
        current = combined if len(combined) <= chunk_size else unit

    if current:
        chunks.append(current)

    return chunks


def chunk_document(
    doc_id: str,
    text: str,
    metadata: Mapping[str, Any] | None = None,
    chunk_size: int = 800,
    overlap: int = 120,
) -> list[Chunk]:
    """Chunk a document and attach deterministic ids and metadata.

    Chunk ids follow ``<doc_id>::<index:04d>``, which keeps re-ingestion idempotent.
    """
    if not doc_id:
        raise ValueError("doc_id must be a non-empty string")

    base = dict(metadata or {})
    base.setdefault("doc_id", doc_id)

    pieces = chunk_text(text, chunk_size=chunk_size, overlap=overlap)
    chunks: list[Chunk] = []
    for index, piece in enumerate(pieces):
        chunk_meta = {**base, "chunk_index": index, "n_chunks": len(pieces)}
        chunks.append(Chunk(chunk_id=f"{doc_id}::{index:04d}", text=piece, metadata=chunk_meta))
    return chunks


def chunks_from_records(
    records: Sequence[Mapping[str, Any]],
    *,
    text_field: str = "text",
    id_field: str = "id",
    chunk_size: int = 800,
    overlap: int = 120,
) -> list[Chunk]:
    """Chunk a list of records (``{"id": ..., "text": ..., <metadata>}``)."""
    result: list[Chunk] = []
    for record in records:
        doc_id = str(record[id_field])
        text = str(record[text_field])
        meta = {k: v for k, v in record.items() if k not in (id_field, text_field)}
        result.extend(
            chunk_document(doc_id, text, meta, chunk_size=chunk_size, overlap=overlap)
        )
    return result
