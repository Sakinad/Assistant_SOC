"""Tests for the chunking module (no third-party dependency)."""

from __future__ import annotations

import pytest

from cybersoc.rag.chunking import Chunk, chunk_document, chunk_text, chunks_from_records

PARAGRAPHS = (
    "T1059.001 Command and Scripting Interpreter: PowerShell.\n\n"
    "Adversaries may abuse PowerShell commands and scripts for execution. "
    "PowerShell is a powerful interactive command-line interface and scripting "
    "environment included in the Windows operating system.\n\n"
    "CVE-2021-44228: Apache Log4j2 JNDI features do not protect against attacker "
    "controlled LDAP and other JNDI related endpoints, leading to remote code execution.\n\n"
    "T1110 Brute Force: adversaries may use brute force techniques to gain access to accounts."
)


def test_empty_text_returns_no_chunk() -> None:
    assert chunk_text("") == []
    assert chunk_text("   \n\n  ") == []


def test_chunks_never_exceed_chunk_size() -> None:
    chunks = chunk_text(PARAGRAPHS, chunk_size=120, overlap=20)
    assert chunks
    assert all(len(chunk) <= 120 for chunk in chunks)


def test_full_document_round_trip_without_overlap() -> None:
    text = "First paragraph here.\n\nSecond paragraph here.\n\nThird paragraph here."
    chunks = chunk_text(text, chunk_size=25, overlap=0)
    assert len(chunks) == 3
    assert chunks[0] == "First paragraph here."


def test_overlap_is_present_between_consecutive_chunks() -> None:
    text = "aaa bbb ccc ddd. eee fff ggg hhh. iii jjj kkk lll. mmm nnn ooo ppp."
    chunks = chunk_text(text, chunk_size=40, overlap=10)
    assert len(chunks) >= 2
    # every chunk after the first starts with a tail of the previous chunk
    for previous, current in zip(chunks, chunks[1:], strict=False):
        head = current.split("\n\n")[0]
        assert head, "expected an overlap prefix"
        assert head in previous


def test_no_overlap_without_configured_overlap() -> None:
    text = "aaa bbb ccc ddd. eee fff ggg hhh. iii jjj kkk lll. mmm nnn ooo ppp."
    chunks = chunk_text(text, chunk_size=40, overlap=0)
    assert len(chunks) >= 2
    for previous, current in zip(chunks, chunks[1:], strict=False):
        assert current[:8] not in previous


def test_long_single_word_is_hard_sliced() -> None:
    text = "x" * 350
    chunks = chunk_text(text, chunk_size=100, overlap=0)
    assert [len(c) for c in chunks] == [100, 100, 100, 50]


def test_paragraph_boundary_preferred_over_sentence() -> None:
    text = "Short one.\n\nShort two.\n\nShort three."
    chunks = chunk_text(text, chunk_size=200, overlap=10)
    assert chunks == ["Short one.\n\nShort two.\n\nShort three."]


@pytest.mark.parametrize(
    ("chunk_size", "overlap"),
    [(0, 0), (-5, 0), (100, -1), (100, 100), (100, 150)],
)
def test_invalid_parameters_raise(chunk_size: int, overlap: int) -> None:
    with pytest.raises(ValueError):
        chunk_text("some text", chunk_size=chunk_size, overlap=overlap)


def test_chunk_document_builds_ids_and_metadata() -> None:
    chunks = chunk_document("mitre-T1059", PARAGRAPHS, {"source_type": "mitre_attack"}, 150, 20)
    assert chunks
    assert all(isinstance(chunk, Chunk) for chunk in chunks)
    assert chunks[0].chunk_id == "mitre-T1059::0000"
    assert [c.chunk_id for c in chunks] == [f"mitre-T1059::{i:04d}" for i in range(len(chunks))]
    assert chunks[0].metadata["source_type"] == "mitre_attack"
    assert chunks[0].metadata["doc_id"] == "mitre-T1059"
    assert chunks[0].metadata["chunk_index"] == 0
    assert chunks[0].metadata["n_chunks"] == len(chunks)


def test_chunks_from_records_preserves_extra_fields() -> None:
    records = [
        {"id": "a", "text": "first document body", "severity": "high"},
        {"id": "b", "text": "second document body", "severity": "low"},
    ]
    chunks = chunks_from_records(records, chunk_size=100, overlap=0)
    assert len(chunks) == 2
    assert {c.metadata["severity"] for c in chunks} == {"high", "low"}
    assert chunks[0].metadata["doc_id"] == "a"


def test_chunk_rejects_empty_text() -> None:
    with pytest.raises(ValueError):
        Chunk(chunk_id="x", text="   ")
