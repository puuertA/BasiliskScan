"""Testes da CLI para comandos relacionados ao NVD."""

import os
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from click.testing import CliRunner

from basiliskscan.auth.credential_manager import CredentialRecord, CredentialSource
from basiliskscan.cli import cli


class TestNVDCommands(unittest.TestCase):
    def setUp(self):
        self.runner = CliRunner()

    @patch("basiliskscan.commands.nvd.CredentialManager")
    def test_nvd_key_set(self, manager_cls):
        manager = manager_cls.return_value

        result = self.runner.invoke(
            cli,
            ["nvd-key", "--set", "test-api-key-12345678"],
            prog_name="bscan",
        )

        self.assertEqual(result.exit_code, 0)
        manager.set_credentials.assert_called_once_with(
            "nvd",
            {"api_key": "test-api-key-12345678"},
            save_to_keyring=False,
        )
        self.assertIn("API key do NVD configurada com sucesso", result.output)

    @patch("basiliskscan.commands.nvd.CredentialManager")
    def test_nvd_key_show_without_credentials(self, manager_cls):
        manager = manager_cls.return_value
        manager.discover_credentials.return_value = None

        result = self.runner.invoke(cli, ["nvd-key", "--show"], prog_name="bscan")

        self.assertEqual(result.exit_code, 0)
        self.assertIn("Nenhuma API key do NVD configurada", result.output)
        self.assertIn("bscan nvd-register-guide", result.output)

    @patch("basiliskscan.commands.nvd.CredentialManager")
    def test_nvd_key_show_with_credentials(self, manager_cls):
        manager = manager_cls.return_value
        manager.discover_credentials.return_value = CredentialRecord(
            provider="nvd",
            data={"api_key": "abcd1234efgh5678"},
            source=CredentialSource.FILE,
        )

        result = self.runner.invoke(cli, ["nvd-key", "--show"], prog_name="bscan")

        self.assertEqual(result.exit_code, 0)
        self.assertIn("API key do NVD encontrada", result.output)
        self.assertIn("abcd", result.output)
        self.assertIn("5678", result.output)
        self.assertIn("file", result.output)

    def test_nvd_register_guide(self):
        result = self.runner.invoke(cli, ["nvd-register-guide"], prog_name="bscan")

        self.assertEqual(result.exit_code, 0)
        self.assertIn("Guia rápido de cadastro no NVD", result.output)
        self.assertIn("https://nvd.nist.gov/developers/request-an-api-key", result.output)
        self.assertIn("bscan nvd-key --prompt", result.output)

    @patch("basiliskscan.commands.nvd.CredentialManager")
    def test_nvd_key_clear_removes_session_env_var(self, manager_cls):
        os.environ["NVD_API_KEY"] = "env-key-123456"

        try:
            result = self.runner.invoke(cli, ["nvd-key", "--clear"], prog_name="bscan")
        finally:
            os.environ.pop("NVD_API_KEY", None)

        self.assertEqual(result.exit_code, 0)
        manager_cls.return_value.clear_stored_credentials.assert_called_once_with("nvd")
        self.assertIn("Variável NVD_API_KEY removida da sessão atual", result.output)

    @patch("basiliskscan.commands.nvd.CredentialManager")
    def test_nvd_key_clear_removes_key_from_dotenv(self, manager_cls):
        with tempfile.TemporaryDirectory() as temp_dir:
            dotenv_path = Path(temp_dir) / ".env"
            dotenv_path.write_text("NVD_API_KEY=test-key\nOTHER_VAR=1\n", encoding="utf-8")

            with self.runner.isolated_filesystem(temp_dir=temp_dir):
                result = self.runner.invoke(cli, ["nvd-key", "--clear"], prog_name="bscan")

            self.assertEqual(result.exit_code, 0)
            self.assertIn("Chave removida de", result.output)
            updated_content = dotenv_path.read_text(encoding="utf-8")
            self.assertNotIn("NVD_API_KEY=", updated_content)
            self.assertIn("OTHER_VAR=1", updated_content)


if __name__ == "__main__":
    unittest.main()
