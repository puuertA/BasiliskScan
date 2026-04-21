"""Execução via `python -m basiliskscan`."""

import click

from .cli import cli
from .path_setup import ensure_windows_user_path


def main() -> None:
    result = ensure_windows_user_path()
    if result.changed:
        click.echo(f"[BasiliskScan] {result.message}")
        click.echo("[BasiliskScan] Open a new terminal session for global bscan availability.")

    cli()


if __name__ == "__main__":
    main()
