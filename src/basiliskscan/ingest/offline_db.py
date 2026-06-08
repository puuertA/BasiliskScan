"""Banco local offline de vulnerabilidades consolidado por componente."""

from __future__ import annotations

import json
import os
import sqlite3
import shutil
import threading
from datetime import datetime, timedelta
from importlib import resources
from pathlib import Path
from typing import Any, Dict, List, Optional


class OfflineVulnerabilityDB:
    """Armazena vulnerabilidades normalizadas para uso offline e sincronização periódica."""

    DEFAULT_DB_DIR = Path.home() / ".basiliskscan" / "offline"
    LEGACY_DB_DIR = Path(__file__).resolve().parents[3] / "resources" / "offline"
    PACKAGED_DB_PATH = Path("data") / "offline" / "offline_vulnerabilities.db"
    DEFAULT_DB_FILE = "offline_vulnerabilities.db"
    SEED_FORCE_ENV = "BASILISKSCAN_SEED_FORCE"
    SEED_REFRESH_ENV = "BASILISKSCAN_SEED_REFRESH"
    _SEED_REFRESH_RATIO = 1.10
    _SEED_REFRESH_MIN_DIFF = 50

    @classmethod
    def _resolve_default_db_dir(cls) -> Path:
        env_dir = os.getenv("BASILISKSCAN_OFFLINE_DB_DIR")
        if env_dir:
            return Path(env_dir).expanduser().resolve()

        if cls.LEGACY_DB_DIR.exists():
            return cls.LEGACY_DB_DIR

        return cls.DEFAULT_DB_DIR

    @classmethod
    def _get_packaged_seed_path(cls) -> Optional[Path]:
        try:
            packaged = resources.files("basiliskscan").joinpath(str(cls.PACKAGED_DB_PATH).replace("\\", "/"))
            if packaged.is_file():
                return Path(str(packaged))
        except Exception:
            return None
        return None

    def _seed_database_if_missing(self) -> None:
        if self.db_path.name != self.DEFAULT_DB_FILE:
            return

        seed_candidates = [
            self._get_packaged_seed_path(),
            self.LEGACY_DB_DIR / self.DEFAULT_DB_FILE,
        ]

        seed_path = next((path for path in seed_candidates if path and path.exists()), None)
        if not seed_path:
            return

        if not self.db_path.exists():
            shutil.copy2(seed_path, self.db_path)
            return

        if self._should_refresh_seed(self.db_path, seed_path):
            self._merge_seed_database(seed_path)

    def _should_refresh_seed(self, local_path: Path, seed_path: Path) -> bool:
        if self._is_seed_force_enabled():
            return True

        local_stats = self._read_seed_stats(local_path)
        seed_stats = self._read_seed_stats(seed_path)

        if not seed_stats:
            return False

        if local_stats:
            local_components = local_stats.get("total_components", 0)
            seed_components = seed_stats.get("total_components", 0)
            local_vulnerabilities = local_stats.get("total_vulnerabilities", 0)
            seed_vulnerabilities = seed_stats.get("total_vulnerabilities", 0)
            local_sync = local_stats.get("last_full_sync_at")
            seed_sync = seed_stats.get("last_full_sync_at")

            if seed_components <= local_components and seed_vulnerabilities <= local_vulnerabilities:
                if not seed_sync or (local_sync and seed_sync <= local_sync):
                    return False

            ratio = seed_components / max(local_components, 1)
            component_diff = seed_components - local_components
            vulnerability_diff = seed_vulnerabilities - local_vulnerabilities
            if seed_sync and (not local_sync or seed_sync > local_sync):
                return True

            if ratio < self._SEED_REFRESH_RATIO and component_diff < self._SEED_REFRESH_MIN_DIFF:
                return False

        return True

    def _merge_seed_database(self, seed_path: Path) -> None:
        local_conn = None
        seed_conn = None
        try:
            local_conn = sqlite3.connect(str(self.db_path))
            local_conn.row_factory = sqlite3.Row
            seed_conn = sqlite3.connect(str(seed_path))
            seed_conn.row_factory = sqlite3.Row

            local_cursor = local_conn.cursor()
            seed_cursor = seed_conn.cursor()

            seed_cursor.execute(
                """
                SELECT id, name, version, ecosystem, first_seen_at, last_synced_at, next_sync_at
                FROM components
                """
            )
            seed_components = seed_cursor.fetchall()

            for seed_component in seed_components:
                local_cursor.execute(
                    """
                    SELECT id, last_synced_at
                    FROM components
                    WHERE name = ? AND version = ? AND ecosystem = ?
                    """,
                    (
                        seed_component["name"],
                        seed_component["version"],
                        seed_component["ecosystem"],
                    ),
                )
                local_component = local_cursor.fetchone()
                should_replace_vulnerabilities = True

                if local_component:
                    local_component_id = int(local_component["id"])
                    local_synced_at = str(local_component["last_synced_at"] or "")
                    seed_synced_at = str(seed_component["last_synced_at"] or "")
                    if local_synced_at and seed_synced_at and local_synced_at > seed_synced_at:
                        should_replace_vulnerabilities = False
                    else:
                        local_cursor.execute(
                            """
                            UPDATE components
                            SET first_seen_at = ?, last_synced_at = ?, next_sync_at = ?
                            WHERE id = ?
                            """,
                            (
                                seed_component["first_seen_at"],
                                seed_component["last_synced_at"],
                                seed_component["next_sync_at"],
                                local_component_id,
                            ),
                        )
                else:
                    local_cursor.execute(
                        """
                        INSERT INTO components(name, version, ecosystem, first_seen_at, last_synced_at, next_sync_at)
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            seed_component["name"],
                            seed_component["version"],
                            seed_component["ecosystem"],
                            seed_component["first_seen_at"],
                            seed_component["last_synced_at"],
                            seed_component["next_sync_at"],
                        ),
                    )
                    local_component_id = int(local_cursor.lastrowid)

                if not should_replace_vulnerabilities:
                    continue

                local_cursor.execute("DELETE FROM vulnerabilities WHERE component_id = ?", (local_component_id,))
                seed_cursor.execute(
                    """
                    SELECT vulnerability_id, source, title, description, severity, score, published, modified,
                           fixed_version, aliases_json, sources_json, references_json, affected_products_json,
                           cwe_json, raw_data_json, updated_at
                    FROM vulnerabilities
                    WHERE component_id = ?
                    """,
                    (int(seed_component["id"]),),
                )
                for vulnerability in seed_cursor.fetchall():
                    local_cursor.execute(
                        """
                        INSERT INTO vulnerabilities(
                            component_id, vulnerability_id, source, title, description, severity, score,
                            published, modified, fixed_version, aliases_json, sources_json, references_json,
                            affected_products_json, cwe_json, raw_data_json, updated_at
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            local_component_id,
                            vulnerability["vulnerability_id"],
                            vulnerability["source"],
                            vulnerability["title"],
                            vulnerability["description"],
                            vulnerability["severity"],
                            vulnerability["score"],
                            vulnerability["published"],
                            vulnerability["modified"],
                            vulnerability["fixed_version"],
                            vulnerability["aliases_json"],
                            vulnerability["sources_json"],
                            vulnerability["references_json"],
                            vulnerability["affected_products_json"],
                            vulnerability["cwe_json"],
                            vulnerability["raw_data_json"],
                            vulnerability["updated_at"],
                        ),
                    )

            seed_cursor.execute("SELECT key, value FROM sync_metadata")
            for metadata in seed_cursor.fetchall():
                local_cursor.execute(
                    """
                    INSERT INTO sync_metadata(key, value)
                    VALUES(?, ?)
                    ON CONFLICT(key) DO UPDATE SET value=excluded.value
                    """,
                    (metadata["key"], metadata["value"]),
                )

            local_conn.commit()
        except Exception:
            backup_path = self.db_path.with_suffix(f"{self.db_path.suffix}.bak")
            try:
                shutil.copy2(self.db_path, backup_path)
            except Exception:
                pass
            shutil.copy2(seed_path, self.db_path)
        finally:
            if local_conn:
                local_conn.close()
            if seed_conn:
                seed_conn.close()

    def _is_seed_force_enabled(self) -> bool:
        value = os.getenv(self.SEED_FORCE_ENV, "").strip().lower()
        return value in {"1", "true", "yes", "on"}

    def _is_seed_refresh_enabled(self) -> bool:
        value = os.getenv(self.SEED_REFRESH_ENV, "").strip().lower()
        return value in {"1", "true", "yes", "on"}

    def _read_seed_stats(self, db_path: Path) -> Optional[Dict[str, Any]]:
        try:
            conn = sqlite3.connect(str(db_path))
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute("SELECT COUNT(*) AS total FROM components")
            total_components = int(cursor.fetchone()["total"])

            cursor.execute("SELECT COUNT(*) AS total FROM vulnerabilities")
            total_vulnerabilities = int(cursor.fetchone()["total"])

            cursor.execute("SELECT value FROM sync_metadata WHERE key = 'last_full_sync_at'")
            last_full_sync = cursor.fetchone()
            last_full_sync_at = str(last_full_sync["value"]) if last_full_sync and last_full_sync["value"] else None

            conn.close()
            return {
                "total_components": total_components,
                "total_vulnerabilities": total_vulnerabilities,
                "last_full_sync_at": last_full_sync_at,
            }
        except Exception:
            return None

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
        self._seed_database_if_missing()
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
