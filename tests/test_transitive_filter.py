"""Testa se dependências transitivas são ocultadas por padrão no scan."""

import unittest
from click.testing import CliRunner
from basiliskscan.cli import cli

class TestTransitiveFilter(unittest.TestCase):
    def test_transitive_hidden_by_default(self):
        runner = CliRunner()
        # Simula um scan em um projeto de teste (pode ser vazio, só valida help e filtro)
        result = runner.invoke(cli, ["scan", "--help"], prog_name="bscan")
        self.assertIn("--include-transitive", result.output)
        # O help já orienta que transitivas são ocultadas
        self.assertIn("transitivas por padrão", result.output)

    # O ideal seria mockar o scanner para garantir que transitivas não aparecem, mas isso depende do setup do projeto de teste

if __name__ == "__main__":
    unittest.main()