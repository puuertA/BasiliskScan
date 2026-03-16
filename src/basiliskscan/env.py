"""Carregamento simples de variáveis de ambiente a partir de `.env`."""

from __future__ import annotations

import os
from pathlib import Path
from threading import Lock
from typing import Optional


_LOADED_ENV_FILES: set[Path] = set()
_ENV_LOCK = Lock()


def find_dotenv(search_from: Optional[Path] = None) -> Optional[Path]:
    """Localiza o arquivo `.env` mais próximo subindo a hierarquia de diretórios."""
    start_path = Path(search_from or Path.cwd()).resolve()
    if start_path.is_file():
        start_path = start_path.parent

    for directory in [start_path, *start_path.parents]:
        candidate = directory / ".env"
        if candidate.is_file():
            return candidate

    return None


def load_dotenv(search_from: Optional[Path] = None, override: bool = False) -> Optional[Path]:
    """Carrega variáveis do arquivo `.env` encontrado, sem sobrescrever por padrão."""
    env_path = find_dotenv(search_from)
    if not env_path:
        return None

    resolved_path = env_path.resolve()

    with _ENV_LOCK:
        if resolved_path in _LOADED_ENV_FILES and not override:
            return resolved_path

        for raw_line in resolved_path.read_text(encoding="utf-8").splitlines():
            parsed = _parse_env_line(raw_line)
            if not parsed:
                continue

            key, value = parsed
            if override or key not in os.environ:
                os.environ[key] = value

        _LOADED_ENV_FILES.add(resolved_path)

    return resolved_path


def _parse_env_line(line: str) -> Optional[tuple[str, str]]:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None

    if stripped.startswith("export "):
        stripped = stripped[7:].strip()

    if "=" not in stripped:
        return None

    key, value = stripped.split("=", 1)
    key = key.strip()
    value = value.strip()

    if not key:
        return None

    if value and value[0] == value[-1] and value[0] in {'"', "'"}:
        value = value[1:-1]
    elif " #" in value:
        value = value.split(" #", 1)[0].rstrip()

    return key, value