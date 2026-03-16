"""Testes do agregador com OSV + NVD."""

import unittest
from unittest.mock import patch

from basiliskscan.ingest.aggregator import VulnerabilityAggregator


class TestVulnerabilityAggregatorSources(unittest.TestCase):
    """Verifica a mesclagem de vulnerabilidades vindas de múltiplas fontes."""

    @patch("basiliskscan.ingest.aggregator.NVDClient.fetch_vulnerabilities")
    @patch("basiliskscan.ingest.aggregator.OSVClient.fetch_vulnerabilities")
    def test_aggregator_merges_osv_and_nvd_results(self, mock_osv_fetch, mock_nvd_fetch):
        mock_osv_fetch.return_value = [
            {
                "id": "GHSA-test-0001",
                "aliases": ["CVE-2021-44228"],
                "summary": "Log4Shell",
                "details": "RCE in log4j",
                "severity": [],
                "database_specific": {"severity": "CRITICAL"},
                "references": [],
                "affected": [],
            }
        ]
        mock_nvd_fetch.return_value = [
            {
                "cve": {
                    "id": "CVE-2021-44228",
                    "descriptions": [{"lang": "en", "value": "Apache Log4j2 RCE vulnerability"}],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "version": "3.1",
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                                    "baseScore": 10.0,
                                    "baseSeverity": "CRITICAL",
                                }
                            }
                        ]
                    },
                    "references": [],
                    "weaknesses": [],
                    "configurations": [],
                }
            }
        ]

        aggregator = VulnerabilityAggregator()
        vulnerabilities = aggregator.fetch_vulnerabilities("log4j", version="2.14.1", ecosystem="maven", parallel=False)

        self.assertEqual(len(vulnerabilities), 1)
        self.assertEqual(vulnerabilities[0]["id"], "CVE-2021-44228")
        self.assertIn("OSV", vulnerabilities[0]["sources"])
        self.assertIn("NVD", vulnerabilities[0]["sources"])

    @patch("basiliskscan.ingest.aggregator.NVDClient.fetch_vulnerabilities")
    @patch("basiliskscan.ingest.aggregator.OSVClient.fetch_vulnerabilities")
    def test_fetch_multiple_components_reports_progress(self, mock_osv_fetch, mock_nvd_fetch):
        mock_osv_fetch.return_value = []
        mock_nvd_fetch.return_value = []

        aggregator = VulnerabilityAggregator()
        progress_updates = []

        aggregator.fetch_multiple_components(
            [{"name": "express", "version": "4.17.1", "ecosystem": "npm"}],
            parallel=False,
            progress_callback=progress_updates.append,
        )

        self.assertEqual(progress_updates, ["express"])