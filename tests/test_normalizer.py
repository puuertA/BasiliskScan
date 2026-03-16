"""Testes focados para o normalizador de vulnerabilidades."""

import unittest

from basiliskscan.ingest.normalizer import VulnerabilityNormalizer


class TestNormalizer(unittest.TestCase):
    """Valida campos derivados úteis para o relatório."""

    def test_normalize_osv_extracts_fixed_version(self):
        osv_data = {
            "id": "GHSA-test-1234",
            "summary": "Test advisory",
            "affected": [
                {
                    "package": {
                        "ecosystem": "npm",
                        "name": "lodash"
                    },
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [
                                {"introduced": "0"},
                                {"fixed": "4.17.21"}
                            ]
                        }
                    ],
                    "versions": ["4.17.20"]
                }
            ]
        }

        normalized = VulnerabilityNormalizer.normalize_osv_vulnerability(osv_data)

        self.assertEqual(normalized["fixed_version"], "4.17.21")


if __name__ == "__main__":
    unittest.main()