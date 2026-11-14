"""Centralised configuration, loaded from environment variables / ``.env``."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

#: Repository root (``src/cybersoc/config.py`` -> ``parents[2]``).
PROJECT_ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    """Application settings.

    Every field maps to an environment variable of the same (upper-cased) name,
    for example ``CHUNK_SIZE=800``. See ``.env.example`` for the full reference.
    """

    model_config = SettingsConfigDict(
        env_file=PROJECT_ROOT / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # --- Runtime ---------------------------------------------------------
    env: Literal["dev", "test", "prod"] = "dev"

    # --- Vector store (ADR-0001) -----------------------------------------
    vector_db: Literal["chroma"] = "chroma"
    chroma_path: Path = PROJECT_ROOT / "data" / "indexes" / "chroma"
    chroma_collection: str = "soc_kb"

    # --- Embeddings (ADR-0002) -------------------------------------------
    embedding_model: str = "BAAI/bge-small-en-v1.5"
    embedding_dim: int = Field(default=384, gt=0)
    embedding_device: str = "cpu"
    embedding_batch_size: int = Field(default=32, gt=0)

    # --- Chunking / retrieval --------------------------------------------
    chunk_size: int = Field(default=800, gt=0)
    chunk_overlap: int = Field(default=120, ge=0)
    top_k: int = Field(default=5, gt=0)

    # --- Knowledge graph --------------------------------------------------
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "change-me"

    # --- SLM / LLMOps -----------------------------------------------------
    slm_model_id: str = "Qwen/Qwen2.5-1.5B-Instruct"
    mlflow_tracking_uri: str = "file:./mlruns"

    @property
    def data_dir(self) -> Path:
        """Root folder for datasets and indexes (git-ignored)."""
        return PROJECT_ROOT / "data"

    def ensure_dirs(self) -> None:
        """Create the directories required at runtime."""
        self.chroma_path.expanduser().resolve().mkdir(parents=True, exist_ok=True)
        (self.data_dir / "raw").mkdir(parents=True, exist_ok=True)
        (self.data_dir / "processed").mkdir(parents=True, exist_ok=True)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide settings instance (cached)."""
    return Settings()
