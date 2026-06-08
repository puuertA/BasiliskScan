#!/usr/bin/env python3
"""Prepara o banco offline seed para empacotamento no GitHub/PyPI."""

from __future__ import annotations

import shutil
import sqlite3
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_DB = PROJECT_ROOT / "resources" / "offline" / "offline_vulnerabilities.db"
PACKAGE_DB = PROJECT_ROOT / "src" / "basiliskscan" / "data" / "offline" / "offline_vulnerabilities.db"
MIN_COMPONENTS = 4346
MIN_VULNERABILITIES = 1277


def read_counts(db_path: Path) -> tuple[int, int]:
    if not db_path.exists():
        raise FileNotFoundError(f"Banco offline nao encontrado: {db_path}")

    with sqlite3.connect(str(db_path)) as connection:
        cursor = connection.cursor()
        cursor.execute("SELECT COUNT(*) FROM components")
        components = int(cursor.fetchone()[0])
        cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
        vulnerabilities = int(cursor.fetchone()[0])

    return components, vulnerabilities


def main() -> None:
    components, vulnerabilities = read_counts(SOURCE_DB)
    if components < MIN_COMPONENTS or vulnerabilities < MIN_VULNERABILITIES:
        raise RuntimeError(
            "Banco offline abaixo do esperado: "
            f"{components} componentes, {vulnerabilities} vulnerabilidades "
            f"(minimo: {MIN_COMPONENTS}/{MIN_VULNERABILITIES})"
        )

    PACKAGE_DB.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(SOURCE_DB, PACKAGE_DB)

    packaged_components, packaged_vulnerabilities = read_counts(PACKAGE_DB)
    print(
        "Seed offline pronto para empacotamento: "
        f"{packaged_components} componentes, "
        f"{packaged_vulnerabilities} vulnerabilidades"
    )


if __name__ == "__main__":
    main()
