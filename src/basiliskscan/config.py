# src/basiliskscan/config.py
"""Configurações e constantes globais do BasiliskScan."""

from datetime import datetime
from typing import Set


def get_default_output_filename() -> str:
    """
    Gera nome do arquivo de report com timestamp.
    
    Returns:
        Nome do arquivo no formato basiliskscan-report-YYYYMMDD-HHMMSS.html
    """
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return f"basiliskscan-report-{timestamp}.html"


# Informações da aplicação
APP_NAME = "BasiliskScan"
APP_VERSION = "1.0.0"
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
    "pom.xml",
    "build.xml",
    "build.gradle",
    "build.gradle.kts"
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