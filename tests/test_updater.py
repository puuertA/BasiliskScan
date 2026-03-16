"""Testes para o serviço de atualização de dependências."""

import unittest
from unittest.mock import Mock, patch

from basiliskscan.updater import DependencyUpdateService


class TestDependencyUpdateService(unittest.TestCase):
    """Valida preenchimento de latest_version."""

    @patch("basiliskscan.updater.requests.Session.get")
    def test_enrich_npm_dependency_with_latest_version(self, mock_get):
        response = Mock()
        response.raise_for_status.return_value = None
        response.json.return_value = {"version": "5.0.0"}
        mock_get.return_value = response

        service = DependencyUpdateService()
        deps = [
            {"ecosystem": "npm", "name": "express", "version_spec": "4.17.1"},
            {"ecosystem": "ant", "name": "commons-io", "version_spec": "2.11.0"},
        ]

        enriched = service.enrich_with_latest_versions(deps)

        self.assertEqual(enriched[0].get("latest_version"), "5.0.0")
        self.assertIsNone(enriched[1].get("latest_version"))

    @patch("basiliskscan.updater.requests.Session.get")
    def test_enrich_handles_registry_error(self, mock_get):
        mock_get.side_effect = Exception("network")

        service = DependencyUpdateService()
        deps = [{"ecosystem": "npm", "name": "lodash", "version_spec": "4.17.21"}]

        enriched = service.enrich_with_latest_versions(deps)

        self.assertIsNone(enriched[0].get("latest_version"))


if __name__ == "__main__":
    unittest.main()
