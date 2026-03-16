"""Testes para carregamento automático de `.env`."""

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from basiliskscan.auth.credential_manager import CredentialManager
from basiliskscan.env import load_dotenv


class TestEnvLoader(unittest.TestCase):
    """Valida carregamento do `.env` para credenciais do NVD."""

    def tearDown(self):
        os.environ.pop("NVD_API_KEY", None)

    def test_load_dotenv_sets_environment_variable(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            env_path = Path(temp_dir) / ".env"
            env_path.write_text("NVD_API_KEY=test-from-env-file\n", encoding="utf-8")

            os.environ.pop("NVD_API_KEY", None)
            loaded_path = load_dotenv(Path(temp_dir), override=True)

            self.assertEqual(loaded_path.resolve(), env_path.resolve())
            self.assertEqual(os.environ.get("NVD_API_KEY"), "test-from-env-file")

    def test_credential_manager_reads_key_from_dotenv(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            env_path = Path(temp_dir) / ".env"
            env_path.write_text("NVD_API_KEY=test-from-manager\n", encoding="utf-8")

            os.environ.pop("NVD_API_KEY", None)

            with patch("basiliskscan.auth.credential_manager.load_dotenv") as mocked_loader:
                mocked_loader.side_effect = lambda: load_dotenv(Path(temp_dir), override=True)
                manager = CredentialManager(credentials_file=Path(temp_dir) / "credentials.toml")

            self.assertEqual(manager.get_nvd_api_key(), "test-from-manager")