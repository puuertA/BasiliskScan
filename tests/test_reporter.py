"""Testes para helpers do relatório."""

import unittest

from basiliskscan.reporter import ReportGenerator


class TestReporter(unittest.TestCase):
    """Valida a exibição de status e upgrade no relatório."""

    def setUp(self):
        self.reporter = ReportGenerator()

    def test_build_dependency_status_with_fixed_version(self):
        dep = {"name": "lodash", "version_spec": "4.17.20"}
        vulns = [{"id": "CVE-1", "fixed_version": "4.17.21"}]

        status = self.reporter._build_dependency_status(dep, vulns)

        self.assertTrue(status["is_vulnerable"])
        self.assertTrue(status["has_update"])
        self.assertEqual(status["recommended_version"], "4.17.21")
        labels = [badge["label"] for badge in status["badges"]]
        self.assertIn("Vulnerável", labels)
        self.assertIn("Atualização disponível", labels)

    def test_build_dependency_status_without_fixed_version(self):
        dep = {"name": "legacy-lib", "version_spec": "1.0.0"}
        vulns = [{"id": "CVE-1"}]

        status = self.reporter._build_dependency_status(dep, vulns)

        self.assertTrue(status["is_vulnerable"])
        self.assertFalse(status["has_update"])
        self.assertIsNone(status["recommended_version"])
        labels = [badge["label"] for badge in status["badges"]]
        self.assertEqual(labels, ["Vulnerável"])

    def test_build_dependency_status_secure_with_update(self):
        dep = {"name": "safe-lib", "version_spec": "1.0.0", "latest_version": "1.1.0"}

        status = self.reporter._build_dependency_status(dep, [])

        self.assertFalse(status["is_vulnerable"])
        self.assertTrue(status["has_update"])
        labels = [badge["label"] for badge in status["badges"]]
        self.assertIn("Seguro", labels)
        self.assertIn("Atualização disponível", labels)


if __name__ == "__main__":
    unittest.main()