# src/basiliskscan/ui.py
"""Compatibilidade para a camada de visualização no terminal."""

from .views.terminal_view import (
    BasiliskCommand,
    BasiliskGroup,
    UIHelper,
    handle_file_save_error,
    normalize_cli_directory_input,
    validate_target_path,
)

__all__ = [
    "BasiliskCommand",
    "BasiliskGroup",
    "UIHelper",
    "handle_file_save_error",
    "normalize_cli_directory_input",
    "validate_target_path",
]