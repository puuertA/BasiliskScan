"""Camada de autenticação e gerenciamento de credenciais."""

from .credential_manager import CredentialManager, CredentialRecord, CredentialSource

__all__ = [
    "CredentialManager",
    "CredentialRecord",
    "CredentialSource",
]
