"""Testes unitários para camada de credenciais."""

import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from basiliskscan.auth.credential_manager import (
    CredentialManager,
    CredentialRecord,
    CredentialSource,
)


class FakeKeyring:
    """Implementação simples de keyring para testes."""

    def __init__(self):
        self._store = {}

    def get_password(self, service_name: str, username: str):
        return self._store.get((service_name, username))

    def set_password(self, service_name: str, username: str, password: str):
        self._store[(service_name, username)] = password

    def delete_password(self, service_name: str, username: str):
        key = (service_name, username)
        if key in self._store:
            del self._store[key]


class TestCredentialManager(unittest.TestCase):
    """Valida ordem de descoberta e uso de credenciais."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.credentials_path = Path(self.temp_dir.name) / "credentials.toml"
        self.fake_keyring = FakeKeyring()
        self.manager = CredentialManager(
            credentials_file=self.credentials_path,
            keyring_module=self.fake_keyring,
        )

    def tearDown(self):
        self.temp_dir.cleanup()
        for env_name in [
            "NVD_API_KEY",
            "OSS_INDEX_USERNAME",
            "OSS_INDEX_TOKEN",
            "NVD_CREDENTIALS_EXPIRES_AT",
            "OSS_INDEX_CREDENTIALS_EXPIRES_AT",
        ]:
            os.environ.pop(env_name, None)

    def test_discovery_priority_environment_over_keyring_and_file(self):
        self.manager.set_credentials("nvd", {"api_key": "file-api-key-12345"})
        self.fake_keyring.set_password("basiliskscan", "nvd.api_key", "keyring-api-key-12345")
        os.environ["NVD_API_KEY"] = "env-api-key-12345"

        record = self.manager.discover_credentials("nvd")

        self.assertIsNotNone(record)
        self.assertEqual(record.source, CredentialSource.ENVIRONMENT)
        self.assertEqual(record.data["api_key"], "env-api-key-12345")

    def test_discovery_priority_keyring_over_file(self):
        self.manager.set_credentials(
            "oss_index",
            {"username": "user-file", "token": "token-file"},
        )
        self.fake_keyring.set_password("basiliskscan", "oss_index.username", "user-keyring")
        self.fake_keyring.set_password("basiliskscan", "oss_index.token", "token-keyring")

        record = self.manager.discover_credentials("oss_index")

        self.assertIsNotNone(record)
        self.assertEqual(record.source, CredentialSource.KEYRING)
        self.assertEqual(record.data["username"], "user-keyring")
        self.assertEqual(record.data["token"], "token-keyring")

    def test_discovery_from_file_when_no_env_and_keyring(self):
        self.manager.set_credentials(
            "oss_index",
            {"username": "user-file", "token": "token-file"},
        )

        record = self.manager.discover_credentials("oss_index")

        self.assertIsNotNone(record)
        self.assertEqual(record.source, CredentialSource.FILE)
        self.assertEqual(record.data["username"], "user-file")

    def test_no_prompt_in_default_discovery(self):
        called = {"value": False}

        def prompt_callback(provider: str):
            called["value"] = True
            return CredentialRecord(
                provider=provider,
                data={"api_key": "prompted-key-12345"},
                source=CredentialSource.PROMPT,
            )

        record = self.manager.discover_credentials("nvd", prompt_callback=prompt_callback)

        self.assertIsNone(record)
        self.assertFalse(called["value"])

    def test_prompt_only_when_explicitly_enabled(self):
        def prompt_callback(provider: str):
            return CredentialRecord(
                provider=provider,
                data={"api_key": "prompted-key-12345"},
                source=CredentialSource.PROMPT,
            )

        record = self.manager.discover_credentials(
            "nvd",
            allow_prompt=True,
            prompt_callback=prompt_callback,
        )

        self.assertIsNotNone(record)
        self.assertEqual(record.source, CredentialSource.PROMPT)
        self.assertEqual(record.data["api_key"], "prompted-key-12345")

    def test_renewer_is_used_when_expired(self):
        expired_at = datetime.now(timezone.utc) - timedelta(minutes=10)
        self.manager.set_credentials(
            "nvd",
            {"api_key": "old-key-12345"},
            expires_at=expired_at,
        )

        def renewer(record: CredentialRecord):
            return CredentialRecord(
                provider=record.provider,
                data={"api_key": "renewed-key-12345"},
                source=record.source,
                expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            )

        self.manager.register_renewer("nvd", renewer)
        record = self.manager.discover_credentials("nvd")

        self.assertIsNotNone(record)
        self.assertEqual(record.data["api_key"], "renewed-key-12345")

    def test_exposes_headers_and_requests_auth(self):
        self.manager.set_credentials("nvd", {"api_key": "nvd-key-12345"})
        self.manager.set_credentials(
            "oss_index",
            {"username": "john", "token": "secret-token"},
        )

        nvd_headers = self.manager.get_auth_headers("nvd")
        oss_headers = self.manager.get_auth_headers("oss_index")
        oss_auth = self.manager.get_requests_auth("oss_index")

        self.assertEqual(nvd_headers, {"apiKey": "nvd-key-12345"})
        self.assertIn("Authorization", oss_headers)
        self.assertTrue(oss_headers["Authorization"].startswith("Basic "))
        self.assertEqual(oss_auth, ("john", "secret-token"))


if __name__ == "__main__":
    unittest.main()
