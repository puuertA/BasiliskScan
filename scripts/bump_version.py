"""Atualiza a versão do projeto em arquivos relevantes.

Uso:
    python scripts/bump_version.py patch
    python scripts/bump_version.py minor
    python scripts/bump_version.py major
    python scripts/bump_version.py set 1.2.3
"""

from __future__ import annotations

import argparse
from pathlib import Path
import re


SEMVER_PATTERN = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
PROJECT_ROOT = Path(__file__).resolve().parents[1]
PYPROJECT_PATH = PROJECT_ROOT / "pyproject.toml"
README_PATH = PROJECT_ROOT / "README.md"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Faz bump da versão do BasiliskScan")
    parser.add_argument("action", choices=["patch", "minor", "major", "set"])
    parser.add_argument("value", nargs="?", help="Versão alvo quando action=set (ex: 1.2.3)")
    return parser.parse_args()


def validate_semver(version: str) -> None:
    if not SEMVER_PATTERN.match(version):
        raise ValueError(f"Versão inválida: {version}. Use formato MAJOR.MINOR.PATCH")


def read_project_version() -> str:
    content = PYPROJECT_PATH.read_text(encoding="utf-8")
    match = re.search(r'^version\s*=\s*"([^\"]+)"', content, re.MULTILINE)
    if not match:
        raise RuntimeError("Não foi possível localizar a chave version no pyproject.toml")
    return match.group(1)


def next_version(current: str, action: str) -> str:
    major, minor, patch = [int(part) for part in current.split(".")]

    if action == "patch":
        patch += 1
    elif action == "minor":
        minor += 1
        patch = 0
    elif action == "major":
        major += 1
        minor = 0
        patch = 0

    return f"{major}.{minor}.{patch}"


def replace_in_file(file_path: Path, pattern: str, replacement: str, description: str) -> bool:
    content = file_path.read_text(encoding="utf-8")
    new_content, count = re.subn(pattern, replacement, content, flags=re.MULTILINE)

    if count == 0:
        return False

    file_path.write_text(new_content, encoding="utf-8")
    print(f"✅ {description} atualizado em {file_path.name}")
    return True


def update_pyproject(version: str) -> None:
    updated = replace_in_file(
        PYPROJECT_PATH,
        r'^version\s*=\s*"[^\"]+"',
        f'version = "{version}"',
        "Versão do pacote",
    )
    if not updated:
        raise RuntimeError("Falha ao atualizar versão no pyproject.toml")


def update_readme_badge(version: str) -> None:
    replaced = replace_in_file(
        README_PATH,
        r"\[!\[Version\]\(https://img\.shields\.io/badge/version-[^-]+-red\.svg\)\]\(https://github\.com/PuertA/basiliskscan\)",
        f"[![Version](https://img.shields.io/badge/version-{version}-red.svg)](https://github.com/PuertA/basiliskscan)",
        "Badge de versão",
    )

    if not replaced:
        print("ℹ️ Badge de versão não encontrada no README.md (sem alterações).")


def main() -> None:
    args = parse_args()
    current_version = read_project_version()

    if args.action == "set":
        if not args.value:
            raise ValueError("Informe a versão com action=set. Exemplo: set 1.2.3")
        target_version = args.value
    else:
        target_version = next_version(current_version, args.action)

    validate_semver(target_version)

    update_pyproject(target_version)
    update_readme_badge(target_version)

    print(f"\n🎉 Versão atualizada: {current_version} -> {target_version}")
    print("Dica: rode 'bscan --version' após reinstalar em modo editável se necessário.")


if __name__ == "__main__":
    main()
