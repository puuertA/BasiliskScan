"""Testes para banco e sincronização offline de vulnerabilidades."""

from __future__ import annotations

import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from basiliskscan.ingest.offline_db import OfflineVulnerabilityDB
from basiliskscan.ingest.offline_sync import OfflineSyncService


class _FakeAggregator:
    def fetch_vulnerabilities(self, component, version=None, ecosystem=None, parallel=True):
        return [
            {
                "id": f"CVE-TEST-{component.upper()}",
                "source": "test",
                "title": f"Falha em {component}",
                "description": "Descrição de teste",
                "severity": "HIGH",
                "score": 8.1,
                "references": ["https://example.org"],
            }
        ]


class TestOfflineSync(unittest.TestCase):
    def test_ingest_and_offline_lookup(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = OfflineVulnerabilityDB(db_dir=Path(tmp), db_file="offline_test.db")
            service = OfflineSyncService(db=db, aggregator=_FakeAggregator())

            components = [{"name": "lodash", "version": "4.17.0", "ecosystem": "npm"}]
            vulns = {
                "lodash": [
                    {
                        "id": "CVE-TEST-LODASH",
                        "source": "test",
                        "title": "Teste",
                        "description": "Teste",
                        "severity": "MEDIUM",
                        "score": 5.0,
                    }
                ]
            }

            summary = service.ingest_scan_results(components, vulns)
            self.assertEqual(summary["saved_components"], 1)
            self.assertEqual(summary["saved_vulnerabilities"], 1)

            offline_result = service.get_vulnerabilities_for_components(components)
            self.assertIn("lodash", offline_result)
            self.assertEqual(len(offline_result["lodash"]), 1)

            service.close()

    def test_force_sync_updates_tracked_components(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = OfflineVulnerabilityDB(db_dir=Path(tmp), db_file="offline_test.db")
            service = OfflineSyncService(db=db, aggregator=_FakeAggregator())

            db.save_component_vulnerabilities(
                name="requests",
                version="2.25.0",
                ecosystem="pypi",
                vulnerabilities=[],
            )

            summary = service.sync_due_components(force=True)
            self.assertEqual(summary["processed"], 1)
            self.assertEqual(summary["synced"], 1)
            self.assertEqual(summary["errors"], 0)
            self.assertEqual(summary["total_vulnerabilities"], 1)

            stats = db.get_stats()
            self.assertIsNotNone(stats["last_full_sync_at"])

            service.close()

    def test_offline_lookup_falls_back_when_version_differs(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = OfflineVulnerabilityDB(db_dir=Path(tmp), db_file="offline_test.db")
            service = OfflineSyncService(db=db, aggregator=_FakeAggregator())

            db.save_component_vulnerabilities(
                name="jsonwebtoken",
                version="9.0.2",
                ecosystem="npm",
                vulnerabilities=[
                    {
                        "id": "CVE-TEST-JWT",
                        "source": "test",
                        "title": "JWT test",
                        "description": "desc",
                        "severity": "HIGH",
                        "score": 7.5,
                    }
                ],
            )

            lookup_components = [
                {
                    "name": "jsonwebtoken",
                    "version": "9.0.1",
                    "ecosystem": "npm",
                }
            ]
            offline_result = service.get_vulnerabilities_for_components(lookup_components)

            self.assertIn("jsonwebtoken", offline_result)
            self.assertEqual(len(offline_result["jsonwebtoken"]), 1)
            self.assertEqual(offline_result["jsonwebtoken"][0]["id"], "CVE-TEST-JWT")

            service.close()

    def test_existing_local_db_is_upgraded_from_new_packaged_seed(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            local_dir = tmp_path / "local"
            seed_dir = tmp_path / "seed"
            seed_path = seed_dir / OfflineVulnerabilityDB.DEFAULT_DB_FILE

            original_get_seed = OfflineVulnerabilityDB._get_packaged_seed_path
            original_legacy_dir = OfflineVulnerabilityDB.LEGACY_DB_DIR
            upgraded_db = None
            try:
                OfflineVulnerabilityDB._get_packaged_seed_path = classmethod(lambda cls: None)
                OfflineVulnerabilityDB.LEGACY_DB_DIR = tmp_path / "missing-legacy"

                local_db = OfflineVulnerabilityDB(db_dir=local_dir, db_file=OfflineVulnerabilityDB.DEFAULT_DB_FILE)
                local_db.save_component_vulnerabilities(
                    name="lodash",
                    version="4.17.20",
                    ecosystem="npm",
                    vulnerabilities=[],
                )
                local_db.save_component_vulnerabilities(
                    name="private-lib",
                    version="1.0.0",
                    ecosystem="npm",
                    vulnerabilities=[
                        {
                            "id": "CVE-USER-PRIVATE",
                            "source": "user",
                            "title": "User synced vuln",
                            "description": "desc",
                            "severity": "LOW",
                            "score": 2.0,
                        }
                    ],
                )
                local_db.set_last_full_sync(datetime(2026, 4, 1))
                local_db.close()

                seed_db = OfflineVulnerabilityDB(db_dir=seed_dir, db_file=OfflineVulnerabilityDB.DEFAULT_DB_FILE)
                seed_db.save_component_vulnerabilities(
                    name="lodash",
                    version="4.17.20",
                    ecosystem="npm",
                    vulnerabilities=[
                        {
                            "id": "CVE-SEED-LODASH",
                            "source": "seed",
                            "title": "Seed vuln",
                            "description": "desc",
                            "severity": "HIGH",
                            "score": 8.0,
                        }
                    ],
                )
                seed_db.save_component_vulnerabilities(
                    name="express",
                    version="4.18.0",
                    ecosystem="npm",
                    vulnerabilities=[],
                )
                seed_db.set_last_full_sync(datetime(2026, 5, 1))
                seed_db.close()

                OfflineVulnerabilityDB._get_packaged_seed_path = classmethod(lambda cls: seed_path)
                upgraded_db = OfflineVulnerabilityDB(db_dir=local_dir)
                stats = upgraded_db.get_stats()

                self.assertEqual(stats["total_components"], 3)
                self.assertEqual(stats["total_vulnerabilities"], 2)
                self.assertEqual(
                    upgraded_db.get_component_vulnerabilities("lodash", "4.17.20", "npm")[0]["id"],
                    "CVE-SEED-LODASH",
                )
                self.assertEqual(
                    upgraded_db.get_component_vulnerabilities("private-lib", "1.0.0", "npm")[0]["id"],
                    "CVE-USER-PRIVATE",
                )
            finally:
                if upgraded_db:
                    upgraded_db.close()
                OfflineVulnerabilityDB.LEGACY_DB_DIR = original_legacy_dir
                OfflineVulnerabilityDB._get_packaged_seed_path = original_get_seed


if __name__ == "__main__":
    unittest.main()
