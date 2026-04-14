"""Banco local offline de vulnerabilidades consolidado por componente."""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional


class OfflineVulnerabilityDB:
    """Armazena vulnerabilidades normalizadas para uso offline e sincronização periódica."""

    DEFAULT_DB_DIR = Path(__file__).resolve().parents[3] / "resources" / "offline"
    DEFAULT_DB_FILE = "offline_vulnerabilities.db"

    @classmethod
    def _resolve_default_db_dir(cls) -> Path:
        env_dir = os.getenv("BASILISKSCAN_OFFLINE_DB_DIR")
        if env_dir:
            return Path(env_dir).expanduser().resolve()
        return cls.DEFAULT_DB_DIR

    def __init__(
        self,
        db_dir: Optional[Path] = None,
        db_file: str = DEFAULT_DB_FILE,
        refresh_interval_days: int = 7,
    ):
        self.db_dir = db_dir or self._resolve_default_db_dir()
        self.db_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.db_dir / db_file
        self.refresh_interval_days = int(refresh_interval_days)
        self._local = threading.local()
        self._initialize_database()

    def _get_connection(self) -> sqlite3.Connection:
        if not hasattr(self._local, "connection"):
            self._local.connection = sqlite3.connect(str(self.db_path), check_same_thread=False)
            self._local.connection.row_factory = sqlite3.Row
        return self._local.connection

    def _initialize_database(self):
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
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
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                component_id INTEGER NOT NULL,
                vulnerability_id TEXT NOT NULL,
                source TEXT,
                title TEXT,
                description TEXT,
                severity TEXT,
                score REAL,
                published TEXT,
                modified TEXT,
                fixed_version TEXT,
                aliases_json TEXT,
                sources_json TEXT,
                references_json TEXT,
                affected_products_json TEXT,
                cwe_json TEXT,
                raw_data_json TEXT,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(component_id) REFERENCES components(id)
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS sync_metadata (
                key TEXT PRIMARY KEY,
                value TEXT
            )
            """
        )

        cursor.execute("CREATE INDEX IF NOT EXISTS idx_components_tuple ON components(name, version, ecosystem)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_components_next_sync ON components(next_sync_at)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_vuln_component ON vulnerabilities(component_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_vuln_id ON vulnerabilities(vulnerability_id)")

        conn.commit()

    @staticmethod
    def _normalize_component_values(
        name: str,
        version: Optional[str] = None,
        ecosystem: Optional[str] = None,
    ) -> tuple[str, str, str]:
        return (
            str(name or "").strip(),
            str(version or "").strip(),
            str(ecosystem or "").strip().lower(),
        )

    def upsert_component(
        self,
        name: str,
        version: Optional[str] = None,
        ecosystem: Optional[str] = None,
    ) -> int:
        comp_name, comp_version, comp_ecosystem = self._normalize_component_values(name, version, ecosystem)
        if not comp_name:
            raise ValueError("Componente inválido: nome vazio")

        now = datetime.now().isoformat()
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT OR IGNORE INTO components(name, version, ecosystem, first_seen_at)
            VALUES (?, ?, ?, ?)
            """,
            (comp_name, comp_version, comp_ecosystem, now),
        )

        cursor.execute(
            """
            SELECT id FROM components
            WHERE name = ? AND version = ? AND ecosystem = ?
            """,
            (comp_name, comp_version, comp_ecosystem),
        )
        row = cursor.fetchone()
        conn.commit()
        if not row:
            raise RuntimeError("Falha ao obter componente após upsert")
        return int(row["id"])

    def save_component_vulnerabilities(
        self,
        name: str,
        vulnerabilities: List[Dict[str, Any]],
        version: Optional[str] = None,
        ecosystem: Optional[str] = None,
        refresh_interval_days: Optional[int] = None,
    ):
        component_id = self.upsert_component(name, version, ecosystem)

        now = datetime.now()
        interval_days = int(refresh_interval_days or self.refresh_interval_days)
        next_sync = now + timedelta(days=max(interval_days, 1))

        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute("DELETE FROM vulnerabilities WHERE component_id = ?", (component_id,))

        for vuln in vulnerabilities:
            cursor.execute(
                """
                INSERT INTO vulnerabilities(
                    component_id,
                    vulnerability_id,
                    source,
                    title,
                    description,
                    severity,
                    score,
                    published,
                    modified,
                    fixed_version,
                    aliases_json,
                    sources_json,
                    references_json,
                    affected_products_json,
                    cwe_json,
                    raw_data_json,
                    updated_at
                )
                VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    component_id,
                    str(vuln.get("id", "UNKNOWN")),
                    str(vuln.get("source", "")),
                    str(vuln.get("title", "")),
                    str(vuln.get("description", "")),
                    str(vuln.get("severity", "UNKNOWN")),
                    float(vuln.get("score") or 0.0),
                    vuln.get("published"),
                    vuln.get("modified"),
                    vuln.get("fixed_version"),
                    json.dumps(vuln.get("aliases", []), ensure_ascii=False),
                    json.dumps(vuln.get("sources", []), ensure_ascii=False),
                    json.dumps(vuln.get("references", []), ensure_ascii=False),
                    json.dumps(vuln.get("affected_products", []), ensure_ascii=False),
                    json.dumps(vuln.get("cwe", []), ensure_ascii=False),
                    json.dumps(vuln.get("raw_data", {}), ensure_ascii=False),
                    now.isoformat(),
                ),
            )

        cursor.execute(
            """
            UPDATE components
            SET last_synced_at = ?, next_sync_at = ?
            WHERE id = ?
            """,
            (now.isoformat(), next_sync.isoformat(), component_id),
        )

        conn.commit()

    def get_component_vulnerabilities(
        self,
        name: str,
        version: Optional[str] = None,
        ecosystem: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        comp_name, comp_version, comp_ecosystem = self._normalize_component_values(name, version, ecosystem)
        if not comp_name:
            return []

        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT id FROM components
            WHERE name = ? AND version = ? AND ecosystem = ?
            """,
            (comp_name, comp_version, comp_ecosystem),
        )
        component_row = cursor.fetchone()

        if not component_row and comp_ecosystem:
            cursor.execute(
                """
                SELECT id FROM components
                WHERE name = ? AND ecosystem = ?
                ORDER BY
                    CASE WHEN version = ? THEN 0 ELSE 1 END,
                    COALESCE(last_synced_at, first_seen_at) DESC,
                    id DESC
                LIMIT 1
                """,
                (comp_name, comp_ecosystem, comp_version),
            )
            component_row = cursor.fetchone()

        if not component_row:
            cursor.execute(
                """
                SELECT id FROM components
                WHERE name = ?
                ORDER BY
                    CASE WHEN ecosystem = ? THEN 0 ELSE 1 END,
                    CASE WHEN version = ? THEN 0 ELSE 1 END,
                    COALESCE(last_synced_at, first_seen_at) DESC,
                    id DESC
                LIMIT 1
                """,
                (comp_name, comp_ecosystem, comp_version),
            )
            component_row = cursor.fetchone()

        if not component_row:
            return []

        cursor.execute(
            """
            SELECT * FROM vulnerabilities
            WHERE component_id = ?
            ORDER BY score DESC, vulnerability_id ASC
            """,
            (int(component_row["id"]),),
        )
        rows = cursor.fetchall()

        vulnerabilities: List[Dict[str, Any]] = []
        for row in rows:
            vulnerability = {
                "id": row["vulnerability_id"],
                "source": row["source"],
                "title": row["title"],
                "description": row["description"],
                "severity": row["severity"],
                "score": row["score"],
                "published": row["published"],
                "modified": row["modified"],
                "fixed_version": row["fixed_version"],
                "aliases": json.loads(row["aliases_json"] or "[]"),
                "sources": json.loads(row["sources_json"] or "[]"),
                "references": json.loads(row["references_json"] or "[]"),
                "affected_products": json.loads(row["affected_products_json"] or "[]"),
                "cwe": json.loads(row["cwe_json"] or "[]"),
                "raw_data": json.loads(row["raw_data_json"] or "{}"),
            }
            vulnerabilities.append(vulnerability)

        return vulnerabilities

    def get_all_components(self) -> List[Dict[str, Any]]:
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, name, version, ecosystem, first_seen_at, last_synced_at, next_sync_at
            FROM components
            ORDER BY name ASC
            """
        )
        rows = cursor.fetchall()
        return [dict(row) for row in rows]

    def get_components_due_for_sync(self) -> List[Dict[str, Any]]:
        now = datetime.now().isoformat()
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, name, version, ecosystem, first_seen_at, last_synced_at, next_sync_at
            FROM components
            WHERE next_sync_at IS NULL OR next_sync_at <= ?
            ORDER BY COALESCE(next_sync_at, first_seen_at) ASC
            """,
            (now,),
        )
        return [dict(row) for row in cursor.fetchall()]

    def set_last_full_sync(self, sync_time: Optional[datetime] = None):
        moment = (sync_time or datetime.now()).isoformat()
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO sync_metadata(key, value)
            VALUES('last_full_sync_at', ?)
            ON CONFLICT(key) DO UPDATE SET value=excluded.value
            """,
            (moment,),
        )
        conn.commit()

    def get_last_full_sync(self) -> Optional[datetime]:
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT value FROM sync_metadata WHERE key = 'last_full_sync_at'")
        row = cursor.fetchone()
        if not row or not row["value"]:
            return None
        try:
            return datetime.fromisoformat(str(row["value"]))
        except ValueError:
            return None

    def needs_weekly_sync(self, days: int = 7) -> bool:
        last_sync = self.get_last_full_sync()
        if not last_sync:
            return True
        return (datetime.now() - last_sync) >= timedelta(days=max(int(days), 1))

    def clear(self):
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM vulnerabilities")
        cursor.execute("DELETE FROM components")
        cursor.execute("DELETE FROM sync_metadata")
        conn.commit()

    def get_stats(self) -> Dict[str, Any]:
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) AS total FROM components")
        total_components = int(cursor.fetchone()["total"])

        cursor.execute("SELECT COUNT(*) AS total FROM vulnerabilities")
        total_vulnerabilities = int(cursor.fetchone()["total"])

        cursor.execute(
            """
            SELECT severity, COUNT(*) AS count
            FROM vulnerabilities
            GROUP BY severity
            """
        )
        by_severity = {row["severity"]: int(row["count"]) for row in cursor.fetchall()}

        cursor.execute(
            """
            SELECT source, COUNT(*) AS count
            FROM vulnerabilities
            GROUP BY source
            """
        )
        by_source = {row["source"]: int(row["count"]) for row in cursor.fetchall()}

        last_sync = self.get_last_full_sync()

        return {
            "db_path": str(self.db_path),
            "refresh_interval_days": self.refresh_interval_days,
            "total_components": total_components,
            "total_vulnerabilities": total_vulnerabilities,
            "by_severity": by_severity,
            "by_source": by_source,
            "last_full_sync_at": last_sync.isoformat() if last_sync else None,
        }

    def close(self):
        if hasattr(self._local, "connection"):
            try:
                self._local.connection.close()
            finally:
                delattr(self._local, "connection")
