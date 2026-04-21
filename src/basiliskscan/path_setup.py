"""Utilitários para garantir PATH de scripts no Windows."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import sysconfig


@dataclass
class PathSetupResult:
    changed: bool
    scripts_dir: str
    message: str


def _normalize_path(path: str) -> str:
    return os.path.normcase(os.path.normpath(path.strip().strip('"')))


def _split_path(path_value: str) -> list[str]:
    return [entry for entry in path_value.split(";") if entry.strip()]


def _contains_path(path_value: str, target: str) -> bool:
    normalized_target = _normalize_path(target)
    return any(_normalize_path(entry) == normalized_target for entry in _split_path(path_value))


def _append_path(path_value: str, target: str) -> str:
    if not path_value.strip():
        return target
    return f"{path_value.rstrip(';')};{target}"


def _read_user_path_windows() -> tuple[str, int]:
    import winreg

    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment", 0, winreg.KEY_READ) as key:
        try:
            value, value_type = winreg.QueryValueEx(key, "Path")
        except FileNotFoundError:
            return "", winreg.REG_EXPAND_SZ
    return value, value_type


def _write_user_path_windows(path_value: str, value_type: int) -> None:
    import winreg

    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment", 0, winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, "Path", 0, value_type, path_value)


def _broadcast_env_change_windows() -> None:
    import ctypes

    HWND_BROADCAST = 0xFFFF
    WM_SETTINGCHANGE = 0x001A
    SMTO_ABORTIFHUNG = 0x0002
    ctypes.windll.user32.SendMessageTimeoutW(
        HWND_BROADCAST,
        WM_SETTINGCHANGE,
        0,
        "Environment",
        SMTO_ABORTIFHUNG,
        1000,
        None,
    )


def ensure_windows_user_path() -> PathSetupResult:
    scripts_dir = str(Path(sysconfig.get_path("scripts")))

    if os.name != "nt":
        return PathSetupResult(False, scripts_dir, "No action needed outside Windows.")

    user_path, user_path_type = _read_user_path_windows()
    current_path = os.environ.get("PATH", "")

    changed = False

    if not _contains_path(user_path, scripts_dir):
        updated_user_path = _append_path(user_path, scripts_dir)
        _write_user_path_windows(updated_user_path, user_path_type)
        changed = True

    if not _contains_path(current_path, scripts_dir):
        os.environ["PATH"] = _append_path(current_path, scripts_dir)
        changed = True

    if changed:
        _broadcast_env_change_windows()
        return PathSetupResult(
            True,
            scripts_dir,
            f"Added Python Scripts directory to PATH: {scripts_dir}",
        )

    return PathSetupResult(False, scripts_dir, f"Python Scripts directory already in PATH: {scripts_dir}")
