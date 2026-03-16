"""Testes focados para o normalizador de vulnerabilidades."""

import unittest

from basiliskscan.ingest.normalizer import Severity, VulnerabilityNormalizer


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

    def test_normalize_nvd_vulnerability_prefers_cvss_v4(self):
        nvd_data = {
            "cve": {
                "id": "CVE-2025-68428",
                "descriptions": [{"lang": "en", "value": "jsPDF path traversal"}],
                "metrics": {
                    "cvssMetricV40": [
                        {
                            "cvssData": {
                                "version": "4.0",
                                "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:H/SI:N/SA:N",
                                "baseScore": 9.2,
                                "baseSeverity": "CRITICAL",
                            }
                        }
                    ],
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                                "baseScore": 7.5,
                                "baseSeverity": "HIGH",
                            }
                        }
                    ],
                },
                "references": [],
                "weaknesses": [],
                "configurations": [],
            }
        }

        normalized = VulnerabilityNormalizer.normalize_nvd_vulnerability(nvd_data)

        self.assertEqual(normalized["score"], 9.2)
        self.assertEqual(normalized["severity"], Severity.CRITICAL.value)
        self.assertEqual(normalized["cvss"]["version"], "4.0")

    def test_merge_vulnerabilities_prefers_non_zero_score_same_severity(self):
        vuln1 = {
            "id": "CVE-2025-68428",
            "source": "OSV",
            "severity": Severity.CRITICAL.value,
            "score": 0.0,
            "cvss": {"version": "3.1", "vector": "CVSS:3.1/...", "score": 0.0},
            "references": [],
            "affected_products": [],
        }

        vuln2 = {
            "id": "CVE-2025-68428",
            "source": "NVD",
            "severity": Severity.CRITICAL.value,
            "score": 9.2,
            "cvss": {"version": "4.0", "vector": "CVSS:4.0/...", "score": 9.2},
            "references": [],
            "affected_products": [],
        }

        merged = VulnerabilityNormalizer.merge_vulnerabilities([vuln1, vuln2])

        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["score"], 9.2)
        self.assertEqual(merged[0]["cvss"]["version"], "4.0")


if __name__ == "__main__":
    unittest.main()