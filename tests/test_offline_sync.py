"""Testes para banco e sincronização offline de vulnerabilidades."""

from __future__ import annotations

import tempfile
import unittest
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


if __name__ == "__main__":
    unittest.main()
