"""Testes focados para o cliente NVD."""

import unittest
from unittest.mock import Mock, patch

from basiliskscan.ingest.nvd import NVDClient


class TestNVDClient(unittest.TestCase):
    """Valida integração do cliente NVD com configuração e filtros."""

    @patch("basiliskscan.ingest.nvd.get_config")
    def test_initialization_uses_api_key_from_config(self, mock_get_config):
        config = Mock()
        config.get_nvd_api_key.return_value = "configured-api-key"
        mock_get_config.return_value = config

        client = NVDClient()

        self.assertEqual(client.api_key, "configured-api-key")
        self.assertEqual(client.request_interval, client.REQUEST_INTERVAL_WITH_KEY)
        self.assertEqual(client.session.headers["apiKey"], "configured-api-key")

    @patch("basiliskscan.ingest.nvd.requests.Session.get")
    def test_fetch_vulnerabilities_returns_matching_entries(self, mock_get):
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2021-44228",
                        "descriptions": [{"lang": "en", "value": "Apache Log4j issue"}],
                        "configurations": [
                            {
                                "nodes": [
                                    {
                                        "cpeMatch": [
                                            {
                                                "vulnerable": True,
                                                "criteria": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
                                            }
                                        ]
                                    }
                                ]
                            }
                        ],
                        "references": [],
                    }
                },
                {
                    "cve": {
                        "id": "CVE-2022-0001",
                        "descriptions": [{"lang": "en", "value": "Other component issue"}],
                        "configurations": [],
                        "references": [],
                    }
                },
            ]
        }
        mock_get.return_value = mock_response

        client = NVDClient(api_key="test-key")
        vulnerabilities = client.fetch_vulnerabilities("log4j", version="2.14.1", ecosystem="maven")

        self.assertEqual(len(vulnerabilities), 1)
        self.assertEqual(vulnerabilities[0]["cve"]["id"], "CVE-2021-44228")

    @patch("basiliskscan.ingest.nvd.requests.Session.get")
    def test_fetch_vulnerabilities_excludes_outlook_express_for_npm_express(self, mock_get):
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-FAKE-OUTLOOK",
                        "descriptions": [{"lang": "en", "value": "Microsoft Outlook Express vulnerable component"}],
                        "configurations": [
                            {
                                "nodes": [
                                    {
                                        "cpeMatch": [
                                            {
                                                "vulnerable": True,
                                                "criteria": "cpe:2.3:a:microsoft:outlook_express:*:*:*:*:*:*:*:*",
                                            }
                                        ]
                                    }
                                ]
                            }
                        ],
                        "references": [],
                    }
                },
                {
                    "cve": {
                        "id": "CVE-FAKE-EXPRESS",
                        "descriptions": [{"lang": "en", "value": "The express package before 4.18.0 allows something"}],
                        "configurations": [
                            {
                                "nodes": [
                                    {
                                        "cpeMatch": [
                                            {
                                                "vulnerable": True,
                                                "criteria": "cpe:2.3:a:expressjs:express:*:*:*:*:node.js:*:*:*",
                                            }
                                        ]
                                    }
                                ]
                            }
                        ],
                        "references": [{"url": "https://www.npmjs.com/package/express"}],
                    }
                },
            ]
        }
        mock_get.return_value = mock_response

        client = NVDClient(api_key="test-key")
        vulnerabilities = client.fetch_vulnerabilities("express", version="4.17.1", ecosystem="npm")

        self.assertEqual(len(vulnerabilities), 1)
        self.assertEqual(vulnerabilities[0]["cve"]["id"], "CVE-FAKE-EXPRESS")

    @patch("basiliskscan.ingest.nvd.requests.Session.get")
    def test_fetch_cve_by_id_returns_single_entry(self, mock_get):
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "vulnerabilities": [{"cve": {"id": "CVE-2021-44228", "descriptions": [], "references": []}}]
        }
        mock_get.return_value = mock_response

        client = NVDClient(api_key="test-key")
        cve = client.fetch_cve_by_id("CVE-2021-44228")

        self.assertIsNotNone(cve)
        self.assertEqual(cve["cve"]["id"], "CVE-2021-44228")