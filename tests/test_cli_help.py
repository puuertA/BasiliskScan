"""Testes para os textos de ajuda da CLI."""

import unittest

from click.testing import CliRunner

from basiliskscan.cli import cli


class TestCLIHelp(unittest.TestCase):
    def setUp(self):
        self.runner = CliRunner()

    def test_root_help_mentions_current_supported_ecosystems_and_sources(self):
        result = self.runner.invoke(cli, ["--help"], prog_name="bscan")

        self.assertEqual(result.exit_code, 0)
        self.assertIn("package-lock.json", result.output)
        self.assertIn("pom.xml", result.output)
        self.assertIn("build.gradle", result.output)
        self.assertIn("OSV + NVD + Sonatype Guide", result.output)
        self.assertIn("NVD_API_KEY", result.output)
        self.assertIn("sonatype-guide-key", result.output)

    def test_scan_help_mentions_new_flags_and_report_behavior(self):
        result = self.runner.invoke(cli, ["scan", "--help"], prog_name="bscan")

        self.assertEqual(result.exit_code, 0)
        self.assertIn("--skip-vulns", result.output)
        self.assertIn("--include-transitive", result.output)
        self.assertIn("reports/", result.output)
        self.assertIn("OSV + NVD + Sonatype Guide", result.output)
        self.assertIn("Node.js/Ionic e Java", result.output)


if __name__ == "__main__":
    unittest.main()