"""Tests for the Chroma vector store.

The deterministic hash embedder keeps these tests offline and fast: no model
download, no network. Behaviour under the real embedder is checked by
``python scripts/check_env.py --model``.
"""

from __future__ import annotations

import pytest

chromadb = pytest.importorskip("chromadb", reason="chromadb is required for vector store tests")

from cybersoc.rag.chunking import Chunk, chunk_document  # noqa: E402
from cybersoc.rag.embeddings import DeterministicHashEmbedder  # noqa: E402
from cybersoc.rag.vectorstore import VectorStore, _clean_metadata  # noqa: E402


@pytest.fixture()
def embedder() -> DeterministicHashEmbedder:
    return DeterministicHashEmbedder(dimension=64)


@pytest.fixture()
def store(tmp_path, embedder) -> VectorStore:
    return VectorStore(path=tmp_path / "chroma", collection="test_kb", embedder=embedder)


@pytest.fixture()
def chunks() -> list[Chunk]:
    return [
        Chunk("c1", "PowerShell execution of encoded commands T1059.001",
              {"source_type": "mitre_attack", "doc_id": "T1059.001"}),
        Chunk("c2", "Apache Log4j remote code execution via JNDI lookup CVE-2021-44228",
              {"source_type": "cve", "doc_id": "CVE-2021-44228"}),
        Chunk("c3", "Brute force authentication attempts against RDP T1110",
              {"source_type": "mitre_attack", "doc_id": "T1110"}),
    ]


def test_add_and_count(store: VectorStore, chunks: list[Chunk]) -> None:
    assert store.count() == 0
    assert store.add_chunks(chunks) == 3
    assert store.count() == 3


def test_add_is_idempotent(store: VectorStore, chunks: list[Chunk]) -> None:
    store.add_chunks(chunks)
    store.add_chunks(chunks)
    assert store.count() == 3


def test_query_returns_best_match_first(store: VectorStore, chunks: list[Chunk]) -> None:
    store.add_chunks(chunks)
    hits = store.query("PowerShell encoded command", top_k=3)
    assert hits
    assert hits[0].chunk_id == "c1"
    assert 0.0 <= hits[0].score <= 1.0
    assert hits[0].metadata["source_type"] == "mitre_attack"


def test_query_rejects_empty_store(store: VectorStore) -> None:
    assert store.query("anything", top_k=3) == []


def test_metadata_filter(store: VectorStore, chunks: list[Chunk]) -> None:
    store.add_chunks(chunks)
    hits = store.query("execution", top_k=5, where={"source_type": "cve"})
    assert hits
    assert all(hit.metadata["source_type"] == "cve" for hit in hits)


def test_top_k_is_capped_by_collection_size(store: VectorStore, chunks: list[Chunk]) -> None:
    store.add_chunks(chunks)
    assert len(store.query("execution", top_k=10)) == 3


def test_persistence_across_reopen(tmp_path, embedder) -> None:
    path = tmp_path / "chroma"
    first = VectorStore(path=path, collection="persist", embedder=embedder)
    first.add_chunks([Chunk("p1", "persistent vector store chunk", {"source_type": "cti"})])
    assert first.count() == 1

    second = VectorStore(path=path, collection="persist", embedder=embedder)
    assert second.count() == 1
    assert second.query("persistent chunk", top_k=1)[0].chunk_id == "p1"


def test_reset_clears_collection(store: VectorStore, chunks: list[Chunk]) -> None:
    store.add_chunks(chunks)
    store.reset()
    assert store.count() == 0


def test_delete_by_metadata(store: VectorStore, chunks: list[Chunk]) -> None:
    store.add_chunks(chunks)
    store.delete(where={"source_type": "cve"})
    assert store.count() == 2


def test_query_requires_text_xor_embedding(store: VectorStore, chunks: list[Chunk]) -> None:
    store.add_chunks(chunks)
    with pytest.raises(ValueError):
        store.query()
    with pytest.raises(ValueError):
        store.query("text", embedding=[0.0] * 64)


def test_chunk_document_feeds_store(store: VectorStore) -> None:
    text = "T1110 Brute Force\n\nAdversaries may use brute force techniques to gain access."
    store.add_chunks(chunk_document("T1110", text, {"source_type": "mitre_attack"}, 60, 10))
    assert store.count() >= 1
    hits = store.query("brute force", top_k=1)
    assert hits[0].metadata["doc_id"] == "T1110"


def test_metadata_cleaner_drops_none_and_flattens_lists() -> None:
    cleaned = _clean_metadata({"a": None, "b": ["x", "y"], "c": 3, "d": True})
    assert cleaned == {"b": "x,y", "c": 3, "d": True}
