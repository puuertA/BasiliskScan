#!/usr/bin/env python3
"""
Script para popular o banco seed offline com vulnerabilidades de bibliotecas comuns.
Executa uma única vez durante build/install para pré-carregar o DB.
"""

import sqlite3
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Dict, Any

# Bibliotecas populares para pre-seed
POPULAR_COMPONENTS = [
    # NPM packages
    {"name": "lodash", "ecosystem": "npm", "versions": ["4.17.20", "4.17.21"]},
    {"name": "express", "ecosystem": "npm", "versions": ["4.17.1", "4.18.0", "4.18.1"]},
    {"name": "react", "ecosystem": "npm", "versions": ["16.13.0", "17.0.0", "18.0.0"]},
    {"name": "vue", "ecosystem": "npm", "versions": ["2.6.14", "3.0.0", "3.2.0"]},
    {"name": "axios", "ecosystem": "npm", "versions": ["0.21.1", "0.27.0"]},
    {"name": "webpack", "ecosystem": "npm", "versions": ["5.0.0", "5.50.0"]},
    {"name": "typescript", "ecosystem": "npm", "versions": ["4.0.0", "4.6.0", "4.9.0"]},
    {"name": "next", "ecosystem": "npm", "versions": ["11.0.0", "12.0.0", "13.0.0"]},
    {"name": "jest", "ecosystem": "npm", "versions": ["26.6.0", "27.0.0", "28.0.0"]},
    {"name": "eslint", "ecosystem": "npm", "versions": ["7.0.0", "8.0.0"]},
    
    # Java packages
    {"name": "org.apache.log4j:log4j-core", "ecosystem": "maven", "versions": ["2.11.0", "2.14.0", "2.16.0"]},
    {"name": "org.apache.commons:commons-lang3", "ecosystem": "maven", "versions": ["3.8.0", "3.11.0", "3.12.0"]},
    {"name": "org.springframework:spring-core", "ecosystem": "maven", "versions": ["5.0.0", "5.2.0", "5.3.0"]},
    {"name": "junit:junit", "ecosystem": "maven", "versions": ["4.12.0", "4.13.0", "4.13.2"]},
    {"name": "org.apache.struts:struts-core", "ecosystem": "maven", "versions": ["2.3.0", "2.5.0"]},
    {"name": "com.google.guava:guava", "ecosystem": "maven", "versions": ["29.0.0", "30.0.0", "31.0.0"]},
]


def initialize_seed_db(db_path: Path) -> sqlite3.Connection:
    """Cria/abre conexão com DB seed."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()
    
    # Criar tabelas se não existirem
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS components (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            version TEXT,
            ecosystem TEXT,
            first_seen_at TEXT NOT NULL,
            last_synced_at TEXT,
            next_sync_at TEXT,
            UNIQUE(name, version, ecosystem)
        )
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            component_id INTEGER NOT NULL,
            cve_id TEXT UNIQUE NOT NULL,
            title TEXT,
            description TEXT,
            severity TEXT,
            affected_versions TEXT,
            fixed_version TEXT,
            published_at TEXT,
            source TEXT,
            source_url TEXT,
            FOREIGN KEY (component_id) REFERENCES components(id)
        )
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sync_metadata (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """)
    
    conn.commit()
    return conn


def populate_with_components(conn: sqlite3.Connection, components: List[Dict[str, Any]]) -> None:
    """Insere componentes populares no DB seed."""
    cursor = conn.cursor()
    now = datetime.now().isoformat()
    next_sync = (datetime.now() + timedelta(days=7)).isoformat()
    
    for comp in components:
        name = comp["name"]
        ecosystem = comp["ecosystem"]
        
        for version in comp["versions"]:
            try:
                cursor.execute(
                    """
                    INSERT OR IGNORE INTO components 
                    (name, version, ecosystem, first_seen_at, last_synced_at, next_sync_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (name, version, ecosystem, now, now, next_sync)
                )
            except sqlite3.IntegrityError:
                pass
    
    conn.commit()
    print(f"✓ Inseridos {len(components)} componentes populares no seed DB")


def set_seed_metadata(conn: sqlite3.Connection) -> None:
    """Marca DB como seed pré-populado."""
    cursor = conn.cursor()
    cursor.execute(
        "INSERT OR REPLACE INTO sync_metadata (key, value) VALUES (?, ?)",
        ("is_seed_db", "true")
    )
    cursor.execute(
        "INSERT OR REPLACE INTO sync_metadata (key, value) VALUES (?, ?)",
        ("seed_populated_at", datetime.now().isoformat())
    )
    conn.commit()


def main():
    seed_path = Path(__file__).resolve().parents[2] / "resources" / "offline" / "offline_vulnerabilities.db"
    
    print(f"📦 Populando seed DB: {seed_path}")
    
    # Remover DB antigo se existir (rebuild)
    if seed_path.exists():
        seed_path.unlink()
        print("   Removido DB anterior")
    
    conn = initialize_seed_db(seed_path)
    populate_with_components(conn, POPULAR_COMPONENTS)
    set_seed_metadata(conn)
    conn.close()
    
    print(f"✓ Seed DB populado com sucesso!")


if __name__ == "__main__":
    main()
