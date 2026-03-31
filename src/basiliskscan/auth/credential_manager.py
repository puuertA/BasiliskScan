"""Camada única para descoberta e uso de credenciais."""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Callable, Dict, Mapping, Optional

from basiliskscan.env import load_dotenv

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib

try:
    import keyring
except ModuleNotFoundError:  # pragma: no cover
    keyring = None


class CredentialSource(str, Enum):
    """Origem da credencial descoberta."""

    ENVIRONMENT = "environment"
    KEYRING = "keyring"
    FILE = "file"
    PROMPT = "prompt"


@dataclass
class CredentialRecord:
    """Representa uma credencial carregada para uma plataforma."""

    provider: str
    data: Dict[str, str]
    source: CredentialSource
    expires_at: Optional[datetime] = None
    metadata: Dict[str, str] = field(default_factory=dict)

    def is_expired(self, now: Optional[datetime] = None) -> bool:
        """Retorna True se a credencial está expirada."""
        if not self.expires_at:
            return False

        reference = now or datetime.now(timezone.utc)
        expiry = self.expires_at
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)

        return reference >= expiry


class CredentialManager:
    """Gerencia descoberta, validação e exposição de credenciais."""

    SERVICE_NAME = "basiliskscan"
    DEFAULT_CREDENTIALS_FILE = Path.home() / ".config" / "basiliskscan" / "credentials.toml"

    PROVIDER_SCHEMAS: Dict[str, Dict[str, object]] = {
        "nvd": {
            "fields": ("api_key",),
            "env": {
                "api_key": ("NVD_API_KEY",),
            },
        },
        "oss_index": {
            "fields": ("username", "token"),
            "env": {
                "username": (
                    "OSS_INDEX_USERNAME",
                    "OSSINDEX_USERNAME",
                    "SONATYPE_GUIDE_USERNAME",
                ),
                "token": (
                    "OSS_INDEX_TOKEN",
                    "OSSINDEX_TOKEN",
                    "SONATYPE_GUIDE_TOKEN",
                ),
            },
        },
        "osv": {
            "fields": tuple(),
            "env": {},
        },
    }

    def __init__(
        self,
        credentials_file: Optional[Path] = None,
        keyring_module=None,
    ):
        load_dotenv()
        self.credentials_file = Path(credentials_file) if credentials_file else self.DEFAULT_CREDENTIALS_FILE
        self._keyring = keyring_module if keyring_module is not None else keyring
        self._renewers: Dict[str, Callable[[CredentialRecord], Optional[CredentialRecord]]] = {}

    def discover_credentials(
        self,
        provider: str,
        allow_prompt: bool = False,
        prompt_callback: Optional[Callable[[str], Optional[CredentialRecord]]] = None,
    ) -> Optional[CredentialRecord]:
        """
        Descobre credenciais seguindo a ordem padrão.

        Ordem de descoberta:
        1) Variáveis de ambiente
        2) Keyring do sistema operacional
        3) Arquivo local em ~/.config/basiliskscan/credentials.toml
        4) Prompt interativo (somente se allow_prompt=True)
        """
        normalized_provider = self._normalize_provider(provider)
        self._ensure_supported_provider(normalized_provider)

        discovery_chain = (
            self._discover_from_env,
            self._discover_from_keyring,
            self._discover_from_file,
        )

        for discover_fn in discovery_chain:
            credentials = discover_fn(normalized_provider)
            if credentials:
                credentials = self.renew_if_applicable(credentials)
                if self.validate(credentials):
                    return credentials

        if allow_prompt and prompt_callback:
            prompted = prompt_callback(normalized_provider)
            if prompted:
                prompted.provider = normalized_provider
                prompted.source = CredentialSource.PROMPT
                prompted = self.renew_if_applicable(prompted)
                if self.validate(prompted):
                    return prompted

        return None

    def validate(self, credentials: CredentialRecord) -> bool:
        """Valida credenciais por provedor."""
        provider = self._normalize_provider(credentials.provider)
        self._ensure_supported_provider(provider)

        fields = self._provider_fields(provider)
        for field_name in fields:
            value = credentials.data.get(field_name)
            if value is None or not str(value).strip():
                return False

        if provider == "nvd":
            api_key = credentials.data.get("api_key", "").strip()
            return len(api_key) >= 8

        return True

    def register_renewer(
        self,
        provider: str,
        renewer: Callable[[CredentialRecord], Optional[CredentialRecord]],
    ):
        """Registra função de renovação para um provedor."""
        normalized_provider = self._normalize_provider(provider)
        self._ensure_supported_provider(normalized_provider)
        self._renewers[normalized_provider] = renewer

    def renew_if_applicable(self, credentials: CredentialRecord) -> CredentialRecord:
        """Renova a credencial quando aplicável e expirado."""
        provider = self._normalize_provider(credentials.provider)
        if not credentials.is_expired():
            return credentials

        renewer = self._renewers.get(provider)
        if not renewer:
            return credentials

        renewed = renewer(credentials)
        if renewed and self.validate(renewed):
            return renewed

        return credentials

    def get_auth_headers(self, provider: str, credentials: Optional[CredentialRecord] = None) -> Dict[str, str]:
        """Retorna headers de autenticação para o client HTTP."""
        normalized_provider = self._normalize_provider(provider)
        self._ensure_supported_provider(normalized_provider)
        active_credentials = credentials or self.discover_credentials(normalized_provider)

        if not active_credentials:
            return {}

        if normalized_provider == "nvd":
            return {"apiKey": active_credentials.data["api_key"]}

        if normalized_provider == "oss_index":
            username = active_credentials.data["username"]
            token = active_credentials.data["token"]
            auth_raw = f"{username}:{token}".encode("utf-8")
            auth_encoded = base64.b64encode(auth_raw).decode("ascii")
            return {"Authorization": f"Basic {auth_encoded}"}

        return {}

    def get_requests_auth(self, provider: str, credentials: Optional[CredentialRecord] = None):
        """Retorna estrutura de auth compatível com requests quando aplicável."""
        normalized_provider = self._normalize_provider(provider)
        self._ensure_supported_provider(normalized_provider)
        active_credentials = credentials or self.discover_credentials(normalized_provider)

        if not active_credentials:
            return None

        if normalized_provider == "oss_index":
            return (
                active_credentials.data["username"],
                active_credentials.data["token"],
            )

        return None

    def get_nvd_api_key(self) -> Optional[str]:
        """Atalho para obter API key do NVD."""
        credentials = self.discover_credentials("nvd")
        if not credentials:
            return None
        return credentials.data.get("api_key")

    def get_oss_index_credentials(self) -> tuple[Optional[str], Optional[str]]:
        """Atalho para obter credenciais do OSS Index."""
        credentials = self.discover_credentials("oss_index")
        if not credentials:
            return (None, None)
        return (credentials.data.get("username"), credentials.data.get("token"))

    def set_credentials(
        self,
        provider: str,
        data: Mapping[str, str],
        expires_at: Optional[datetime] = None,
        save_to_keyring: bool = False,
    ):
        """Persiste credenciais no arquivo local e opcionalmente no keyring."""
        normalized_provider = self._normalize_provider(provider)
        self._ensure_supported_provider(normalized_provider)

        record = CredentialRecord(
            provider=normalized_provider,
            data={k: str(v) for k, v in data.items()},
            source=CredentialSource.FILE,
            expires_at=expires_at,
        )
        if not self.validate(record):
            raise ValueError(f"Credencial inválida para provedor '{normalized_provider}'")

        file_data = self._load_credentials_file()
        provider_data = dict(record.data)
        if expires_at:
            provider_data["expires_at"] = expires_at.isoformat()
        file_data[normalized_provider] = provider_data
        self._write_credentials_file(file_data)

        if save_to_keyring and self._keyring:
            for field_name, value in record.data.items():
                self._keyring.set_password(self.SERVICE_NAME, self._keyring_key(normalized_provider, field_name), value)
            if expires_at:
                self._keyring.set_password(
                    self.SERVICE_NAME,
                    self._keyring_key(normalized_provider, "expires_at"),
                    expires_at.isoformat(),
                )

    def clear_stored_credentials(self, provider: Optional[str] = None):
        """Remove credenciais persistidas no arquivo e keyring."""
        if provider:
            providers = [self._normalize_provider(provider)]
        else:
            providers = list(self.PROVIDER_SCHEMAS.keys())

        file_data = self._load_credentials_file()
        for item in providers:
            file_data.pop(item, None)
        self._write_credentials_file(file_data)

        if self._keyring:
            for item in providers:
                for field_name in self._provider_fields(item):
                    self._delete_keyring_item(item, field_name)
                self._delete_keyring_item(item, "expires_at")

    def _discover_from_env(self, provider: str) -> Optional[CredentialRecord]:
        values: Dict[str, str] = {}
        env_mapping: Dict[str, tuple] = self.PROVIDER_SCHEMAS[provider]["env"]

        for field_name, env_names in env_mapping.items():
            field_value = None
            for env_name in env_names:
                candidate = os.getenv(env_name)
                if candidate and candidate.strip():
                    field_value = candidate.strip()
                    break
            if field_value:
                values[field_name] = field_value

        if not values:
            return None

        expires_at = self._parse_datetime(os.getenv(f"{provider.upper()}_CREDENTIALS_EXPIRES_AT"))
        return CredentialRecord(
            provider=provider,
            data=values,
            source=CredentialSource.ENVIRONMENT,
            expires_at=expires_at,
        )

    def _discover_from_keyring(self, provider: str) -> Optional[CredentialRecord]:
        if not self._keyring:
            return None

        values = {}
        for field_name in self._provider_fields(provider):
            value = self._keyring.get_password(self.SERVICE_NAME, self._keyring_key(provider, field_name))
            if value and str(value).strip():
                values[field_name] = str(value).strip()

        if not values:
            return None

        expires_raw = self._keyring.get_password(self.SERVICE_NAME, self._keyring_key(provider, "expires_at"))
        return CredentialRecord(
            provider=provider,
            data=values,
            source=CredentialSource.KEYRING,
            expires_at=self._parse_datetime(expires_raw),
        )

    def _discover_from_file(self, provider: str) -> Optional[CredentialRecord]:
        config = self._load_credentials_file()
        provider_data = config.get(provider)
        if not isinstance(provider_data, dict):
            return None

        values = {}
        for field_name in self._provider_fields(provider):
            value = provider_data.get(field_name)
            if value and str(value).strip():
                values[field_name] = str(value).strip()

        if not values:
            return None

        return CredentialRecord(
            provider=provider,
            data=values,
            source=CredentialSource.FILE,
            expires_at=self._parse_datetime(provider_data.get("expires_at")),
        )

    def _load_credentials_file(self) -> Dict[str, Dict[str, str]]:
        if not self.credentials_file.exists():
            return {}

        try:
            with open(self.credentials_file, "rb") as file_handle:
                loaded = tomllib.load(file_handle)
        except Exception:
            return {}

        parsed: Dict[str, Dict[str, str]] = {}
        for provider, raw_data in loaded.items():
            if isinstance(raw_data, dict):
                parsed[self._normalize_provider(provider)] = {
                    str(key): str(value)
                    for key, value in raw_data.items()
                }

        return parsed

    def _write_credentials_file(self, data: Mapping[str, Mapping[str, str]]):
        self.credentials_file.parent.mkdir(parents=True, exist_ok=True)

        lines = []
        for provider in sorted(data.keys()):
            section = data[provider]
            lines.append(f"[{provider}]")
            for key in sorted(section.keys()):
                value = str(section[key]).replace("\\", "\\\\").replace('"', '\\"')
                lines.append(f"{key} = \"{value}\"")
            lines.append("")

        content = "\n".join(lines).rstrip() + "\n"
        self.credentials_file.write_text(content, encoding="utf-8")

    def _ensure_supported_provider(self, provider: str):
        if provider not in self.PROVIDER_SCHEMAS:
            supported = ", ".join(sorted(self.PROVIDER_SCHEMAS.keys()))
            raise ValueError(f"Provider '{provider}' não suportado. Use: {supported}")

    @staticmethod
    def _normalize_provider(provider: str) -> str:
        return provider.strip().lower().replace("-", "_")

    def _provider_fields(self, provider: str) -> tuple:
        return tuple(self.PROVIDER_SCHEMAS[provider]["fields"])

    @staticmethod
    def _parse_datetime(value: Optional[str]) -> Optional[datetime]:
        if not value:
            return None

        raw = value.strip()
        if not raw:
            return None

        if raw.endswith("Z"):
            raw = raw[:-1] + "+00:00"

        try:
            return datetime.fromisoformat(raw)
        except ValueError:
            return None

    @staticmethod
    def _keyring_key(provider: str, field_name: str) -> str:
        return f"{provider}.{field_name}"

    def _delete_keyring_item(self, provider: str, field_name: str):
        try:
            self._keyring.delete_password(self.SERVICE_NAME, self._keyring_key(provider, field_name))
        except Exception:
            pass
