"""Pacote principal do BasiliskScan."""

from importlib.metadata import PackageNotFoundError, version


def get_version() -> str:
    try:
        return version("basiliskscan")
    except PackageNotFoundError:
        return "0.0.0"


__version__ = get_version()
