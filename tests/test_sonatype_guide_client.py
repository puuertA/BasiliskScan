"""Testes focados para o cliente Sonatype Guide."""

import unittest
from unittest.mock import Mock, patch

from basiliskscan.ingest.sonatype_guide import SonatypeGuideClient


class TestSonatypeGuideClient(unittest.TestCase):
    """Valida comportamento de consulta e mapeamento do client Sonatype."""

    @patch("basiliskscan.ingest.sonatype_guide.get_config")
    def test_fetch_returns_empty_without_credentials(self, mock_get_config):
        config = Mock()
        config.get_oss_index_credentials.return_value = (None, None)
        mock_get_config.return_value = config

        client = SonatypeGuideClient()
        vulnerabilities = client.fetch_vulnerabilities("express", version="4.17.1", ecosystem="npm")

        self.assertEqual(vulnerabilities, [])
        self.assertFalse(client.is_available())

    @patch("basiliskscan.ingest.sonatype_guide.requests.Session.get")
    @patch("basiliskscan.ingest.sonatype_guide.get_config")
    def test_fetch_builds_purl_and_uses_bearer_token(self, mock_get_config, mock_get):
        config = Mock()
        config.get_oss_index_credentials.return_value = ("john", "token-123")
        mock_get_config.return_value = config

        response = Mock()
        response.raise_for_status.return_value = None
        response.status_code = 200
        response.content = b"{\"hits\": []}"
        response.json.return_value = {
            "hits": [
                {
                    "vulnId": "CVE-2021-1234",
                    "aliases": [],
                    "summary": "desc",
                    "cvssSeverity": 7.5,
                    "cwes": ["CWE-20"],
                }
            ]
        }
        mock_get.return_value = response

        client = SonatypeGuideClient()
        vulnerabilities = client.fetch_vulnerabilities("express", version="4.17.1", ecosystem="npm")

        self.assertEqual(len(vulnerabilities), 1)
        self.assertTrue(client.is_available())
        mock_get.assert_called_once()
        _, kwargs = mock_get.call_args
        self.assertEqual(kwargs["params"], {"purl": "pkg:npm/express@4.17.1"})
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer token-123")


if __name__ == "__main__":
    unittest.main()
