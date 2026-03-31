"""Testes da CLI para comandos relacionados à Sonatype Guide."""

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

from basiliskscan.auth.credential_manager import CredentialRecord, CredentialSource
from basiliskscan.cli import cli


class TestSonatypeGuideCommands(unittest.TestCase):
    def setUp(self):
        self.runner = CliRunner()

    @patch("basiliskscan.commands.sonatype_guide.CredentialManager")
    def test_sonatype_guide_key_set(self, manager_cls):
        manager = manager_cls.return_value

        result = self.runner.invoke(
            cli,
            ["sonatype-guide-key", "--username", "john", "--token", "secret-token-12345"],
            prog_name="bscan",
        )

        self.assertEqual(result.exit_code, 0)
        manager.set_credentials.assert_called_once_with(
            "oss_index",
            {"username": "john", "token": "secret-token-12345"},
            save_to_keyring=False,
        )
        self.assertIn("Credenciais da Sonatype Guide configuradas com sucesso", result.output)

    @patch("basiliskscan.commands.sonatype_guide.CredentialManager")
    def test_sonatype_guide_key_show_without_credentials(self, manager_cls):
        manager = manager_cls.return_value
        manager.discover_credentials.return_value = None

        result = self.runner.invoke(cli, ["sonatype-guide-key", "--show"], prog_name="bscan")

        self.assertEqual(result.exit_code, 0)
        self.assertIn("Nenhuma credencial da Sonatype Guide configurada", result.output)
        self.assertIn("bscan sonatype-guide-register-guide", result.output)

    @patch("basiliskscan.commands.sonatype_guide.CredentialManager")
    def test_sonatype_guide_key_show_with_credentials(self, manager_cls):
        manager = manager_cls.return_value
        manager.discover_credentials.return_value = CredentialRecord(
            provider="oss_index",
            data={"username": "john", "token": "abcd1234efgh5678"},
            source=CredentialSource.FILE,
        )

        result = self.runner.invoke(cli, ["sonatype-guide-key", "--show"], prog_name="bscan")

        self.assertEqual(result.exit_code, 0)
        self.assertIn("Credenciais da Sonatype Guide encontradas", result.output)
        self.assertIn("john", result.output)
        self.assertIn("abcd", result.output)
        self.assertIn("5678", result.output)
        self.assertIn("file", result.output)

    @patch("basiliskscan.commands.sonatype_guide.CredentialManager")
    def test_sonatype_guide_key_clear_removes_session_env_vars(self, manager_cls):
        os.environ["OSS_INDEX_USERNAME"] = "john"
        os.environ["OSS_INDEX_TOKEN"] = "secret-token"

        try:
            result = self.runner.invoke(cli, ["sonatype-guide-key", "--clear"], prog_name="bscan")
        finally:
            os.environ.pop("OSS_INDEX_USERNAME", None)
            os.environ.pop("OSS_INDEX_TOKEN", None)

        self.assertEqual(result.exit_code, 0)
        manager_cls.return_value.clear_stored_credentials.assert_called_once_with("oss_index")
        self.assertIn("Variáveis removidas da sessão atual", result.output)

    @patch("basiliskscan.commands.sonatype_guide.CredentialManager")
    def test_sonatype_guide_key_clear_removes_keys_from_dotenv(self, manager_cls):
        with tempfile.TemporaryDirectory() as temp_dir:
            dotenv_path = Path(temp_dir) / ".env"
            dotenv_path.write_text(
                "OSS_INDEX_USERNAME=john\nOSS_INDEX_TOKEN=secret\nOTHER_VAR=1\n",
                encoding="utf-8",
            )

            with self.runner.isolated_filesystem(temp_dir=temp_dir):
                result = self.runner.invoke(cli, ["sonatype-guide-key", "--clear"], prog_name="bscan")

            self.assertEqual(result.exit_code, 0)
            self.assertIn("Chaves removidas de", result.output)
            updated_content = dotenv_path.read_text(encoding="utf-8")
            self.assertNotIn("OSS_INDEX_USERNAME=", updated_content)
            self.assertNotIn("OSS_INDEX_TOKEN=", updated_content)
            self.assertIn("OTHER_VAR=1", updated_content)

    def test_sonatype_guide_register_guide(self):
        result = self.runner.invoke(cli, ["sonatype-guide-register-guide"], prog_name="bscan")

        self.assertEqual(result.exit_code, 0)
        self.assertIn("Guia rápido Sonatype Guide", result.output)
        self.assertIn("https://guide.sonatype.com/api", result.output)
        self.assertIn("https://guide.sonatype.com/settings/profile", result.output)
        self.assertIn("expiração never", result.output)
        self.assertIn("bscan sonatype-guide-key --prompt", result.output)
        self.assertNotIn("OSS_INDEX", result.output)


if __name__ == "__main__":
    unittest.main()
