# src/basiliskscan/config.py
"""Configurações e constantes globais do BasiliskScan."""

from typing import Set

# Informações da aplicação
APP_NAME = "BasiliskScan"
APP_VERSION = "0.0.1"
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
    ".env"
}

# Arquivos de dependências suportados
SUPPORTED_FILES: Set[str] = {
    "package.json",
    "requirements.txt"
}

# Configurações de output padrão
DEFAULT_OUTPUT_FILE = "basiliskscan-report.html"

# Mapeamento de ecossistemas para emojis
ECOSYSTEM_EMOJIS = {
    "npm": "📦",
    "pypi": "🐍", 
    "unknown": "❓"
}

# Seções de dependências do package.json
NPM_DEPENDENCY_SECTIONS = (
    "dependencies",
    "devDependencies", 
    "peerDependencies"
)