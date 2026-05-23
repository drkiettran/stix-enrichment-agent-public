"""Configuration loaded from environment / .env file."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()


@dataclass(frozen=True)
class Config:
    ollama_host: str
    ollama_model: str
    max_agent_steps: int
    log_level: str
    inbox_dir: Path
    outbox_dir: Path
    mock_data_dir: Path

    @classmethod
    def from_env(cls, project_root: Path | None = None) -> "Config":
        root = project_root or Path(__file__).resolve().parent.parent

        def _path(env_var: str, default: str) -> Path:
            raw = os.getenv(env_var, default)
            p = Path(raw)
            return p if p.is_absolute() else (root / p).resolve()

        return cls(
            ollama_host=os.getenv("OLLAMA_HOST", "http://localhost:11434"),
            ollama_model=os.getenv("OLLAMA_MODEL", "llama3.1:8b"),
            max_agent_steps=int(os.getenv("MAX_AGENT_STEPS", "12")),
            log_level=os.getenv("LOG_LEVEL", "INFO").upper(),
            inbox_dir=_path("INBOX_DIR", "./inbox"),
            outbox_dir=_path("OUTBOX_DIR", "./outbox"),
            mock_data_dir=_path("MOCK_DATA_DIR", "./data/mock"),
        )
