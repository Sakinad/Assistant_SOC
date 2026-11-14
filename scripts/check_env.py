"""Environment smoke test — run this first after installing dependencies.

    python scripts/check_env.py            # fast, offline (hash embedder)
    python scripts/check_env.py --model     # also loads the real embedding model

Checks, in order:
  1. Python version
  2. availability of the key third-party packages
  3. settings resolution (``.env`` / environment variables)
  4. a full round-trip on a throw-away collection: upsert -> query -> clean up
"""

from __future__ import annotations

import argparse
import importlib.util
import platform
import sys
import tempfile
from pathlib import Path

# Allow running the script without installing the package.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

REQUIRED = [
    ("pydantic", "pydantic"),
    ("pydantic_settings", "pydantic-settings"),
    ("numpy", "numpy"),
    ("chromadb", "chromadb"),
    ("sentence_transformers", "sentence-transformers"),
]

OK = "[ OK ]"
MISSING = "[MISS]"


def check_python() -> bool:
    version = platform.python_version()
    supported = sys.version_info >= (3, 11)
    print(f"{OK if supported else '[WARN]'} Python {version} (requires >= 3.11)")
    return supported


def check_packages() -> dict[str, bool]:
    status: dict[str, bool] = {}
    for module, package in REQUIRED:
        available = importlib.util.find_spec(module) is not None
        status[package] = available
        print(f"{OK if available else MISSING} {package}")
    return status


def check_settings() -> None:
    from cybersoc.config import get_settings

    settings = get_settings()
    print(f"{OK} settings loaded (env={settings.env})")
    print(f"       vector db      : {settings.vector_db} -> {settings.chroma_path}")
    print(f"       collection     : {settings.chroma_collection}")
    print(f"       embedding      : {settings.embedding_model} ({settings.embedding_dim} dims, "
          f"{settings.embedding_device})")
    print(f"       chunking       : size={settings.chunk_size}, overlap={settings.chunk_overlap}")
    print(f"       top_k          : {settings.top_k}")


def check_roundtrip(use_model: bool) -> bool:
    from cybersoc.rag.chunking import chunk_document
    from cybersoc.rag.embeddings import DeterministicHashEmbedder, SentenceTransformerEmbedder
    from cybersoc.rag.vectorstore import VectorStore

    sample = (
        "T1059.001 Command and Scripting Interpreter: PowerShell.\n\n"
        "Adversaries may abuse PowerShell commands and scripts for execution. "
        "PowerShell is a powerful interactive command-line interface and scripting "
        "environment included in the Windows operating system.\n\n"
        "CVE-2024-0000: a sample vulnerability description used only for this smoke test."
    )
    chunks = chunk_document(
        "smoke", sample, {"source_type": "smoke_test"}, chunk_size=200, overlap=40
    )
    if not chunks:
        print("[FAIL] chunking produced no chunk")
        return False

    if use_model:
        from cybersoc.config import get_settings

        settings = get_settings()
        embedder = SentenceTransformerEmbedder(
            settings.embedding_model,
            device=settings.embedding_device,
            dimension=settings.embedding_dim,
        )
        label = "real model"
    else:
        embedder = DeterministicHashEmbedder(dimension=64)
        label = "hash embedder (offline)"

    # ignore_cleanup_errors: Chroma keeps the HNSW file open on Windows
    with tempfile.TemporaryDirectory(prefix="cybersoc-smoke-", ignore_cleanup_errors=True) as tmp:
        store = VectorStore(path=tmp, collection="smoke", embedder=embedder)
        store.add_chunks(chunks)
        hits = store.query("PowerShell execution", top_k=2)
        count = store.count()
        del store  # release the HNSW file handle before cleanup (Windows)

    if not hits:
        print("[FAIL] round-trip returned no result")
        return False

    print(f"{OK} round-trip with {label}: {count} chunks, best score {hits[0].score:.3f}")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description="CyberSOC AI environment check")
    parser.add_argument("--model", action="store_true", help="also load the real embedding model")
    args = parser.parse_args()

    print("=== CyberSOC AI — environment check ===\n")
    check_python()
    print()
    packages = check_packages()
    print()

    if not packages["chromadb"]:
        print("Install dependencies first:  pip install -r requirements.txt")
        return 1

    check_settings()
    print()

    if args.model and not packages["sentence-transformers"]:
        print("[SKIP] --model requested but sentence-transformers is not installed")
        return check_roundtrip(use_model=False) and 0

    if not check_roundtrip(use_model=args.model):
        return 1

    print("\nEnvironment ready.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
