# src/basiliskscan/config.py
"""Configurações e constantes globais do BasiliskScan."""

from datetime import datetime
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
import re
from typing import Set


def get_default_output_filename() -> str:
    """
    Gera nome do arquivo de report com timestamp.
    
    Returns:
        Nome do arquivo no formato basiliskscan-report-YYYYMMDD-HHMMSS.html
    """
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return f"basiliskscan-report-{timestamp}.html"


def _read_pyproject_version() -> str | None:
    project_root = Path(__file__).resolve().parents[2]
    pyproject_path = project_root / "pyproject.toml"

    if not pyproject_path.exists():
        return None

    content = pyproject_path.read_text(encoding="utf-8")
    match = re.search(r'^version\s*=\s*"([^\"]+)"', content, re.MULTILINE)
    if not match:
        return None

    return match.group(1)


def _resolve_app_version() -> str:
    pyproject_version = _read_pyproject_version()
    if pyproject_version:
        return pyproject_version

    try:
        return version("basiliskscan")
    except PackageNotFoundError:
        return "0.0.0"


# Informações da aplicação
APP_NAME = "BasiliskScan"
APP_VERSION = _resolve_app_version()
APP_DESCRIPTION = "🛡️ Ferramenta Avançada de Análise de Dependências"

# Diretórios ignorados durante a varredura
IGNORED_DIRS: Set[str] = {
    "node_modules",
    ".git", 
    ".venv",
    "venv",
    "__pycache__",
    "dist", 
    "build",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    "coverage",
    ".coverage",
    "htmlcov",
    ".env",
    "target",  # Maven
    ".gradle"  # Gradle
}

# Arquivos de dependências suportados
SUPPORTED_FILES: Set[str] = {
    "package.json",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pom.xml",
    "build.xml",
    "build.gradle",
    "build.gradle.kts",
    "gradle.lockfile",
}

# Configurações de output padrão
DEFAULT_OUTPUT_FILE = get_default_output_filename()

# Mapeamento de ecossistemas para emojis
ECOSYSTEM_EMOJIS = {
    "npm": "📦",
    "ionic": "⚡",
    "maven": "☕",
    "gradle": "🐘",
    "ant": "🐜"
}