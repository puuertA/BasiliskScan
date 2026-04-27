"""Utilitários para geração de Package URL (PURL) padrão."""

from typing import Optional
from urllib.parse import quote


def clean_version_for_purl(version_spec: Optional[str]) -> Optional[str]:
    """Normaliza uma versão para uso em PURL, quando possível."""
    if version_spec is None:
        return None

    version = str(version_spec).strip().strip('"').strip("'")
    if not version:
        return None

    for prefix in ("<=", ">=", "==", "~=", "^", "~", "<", ">", "="):
        if version.startswith(prefix):
            version = version[len(prefix) :].strip()

    if not version:
        return None

    invalid_tokens = (" ", "||", ",", "*", "${", "$", "workspace:", "file:")
    if any(token in version for token in invalid_tokens):
        return None

    return version


def build_purl(ecosystem: str, name: str, version_spec: Optional[str]) -> Optional[str]:
    """Gera PURL padrão para ecossistemas suportados."""
    if not ecosystem or not name:
        return None

    version = clean_version_for_purl(version_spec)
    ecosystem_normalized = ecosystem.strip().lower()

    if ecosystem_normalized in {"npm", "ionic"}:
        purl_name = _build_npm_name(name)
        purl = f"pkg:npm/{purl_name}"
    elif ecosystem_normalized in {"maven", "gradle"}:
        if ":" not in name:
            return None
        group_id, artifact_id = name.split(":", 1)
        purl = f"pkg:maven/{quote(group_id, safe='')}/{quote(artifact_id, safe='')}"
    elif ecosystem_normalized == "composer":
        purl = f"pkg:composer/{quote(name, safe='/')}"
    elif ecosystem_normalized == "ant":
        purl = f"pkg:generic/{quote(name, safe='')}"
    else:
        purl = f"pkg:generic/{quote(name, safe='')}"

    if version:
        return f"{purl}@{quote(version, safe='')}"

    return purl


def _build_npm_name(name: str) -> str:
    """Gera o segmento de nome PURL para pacotes npm com ou sem escopo."""
    normalized_name = name.strip()
    if not normalized_name:
        return quote(name, safe="")

    if normalized_name.startswith("@") and "/" in normalized_name:
        scope, package = normalized_name.split("/", 1)
        return f"{quote(scope, safe='')}/{quote(package, safe='')}"

    return quote(normalized_name, safe="")
