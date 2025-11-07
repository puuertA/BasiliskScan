# src/basiliskscan/cli.py
"""Ponto de entrada principal do BasiliskScan CLI."""

import click

from .config import APP_VERSION, APP_NAME
from .help_text import APP_DESCRIPTION
from .ui import BasiliskGroup, UIHelper
from .commands import scan_command
@click.group(
    cls=BasiliskGroup,
    invoke_without_command=True,
    help=APP_DESCRIPTION,
    context_settings={"help_option_names": ["-h", "--help"]},
)
@click.version_option(version=APP_VERSION, prog_name=APP_NAME)
@click.pass_context
def cli(ctx):
    """🔍 BasiliskScan - Ferramenta Avançada de Análise de Dependências"""
    ui = UIHelper()
    
    # se o cara só digitou `bscan`, o Click já chamou get_help() e mostrou o logo
    if ctx.invoked_subcommand is None:
        # mostra de novo o help para ficar explícito
        click.echo(ctx.get_help())
        ui.display_quick_start_help()


# Adiciona o comando scan ao grupo principal
cli.add_command(scan_command, name="scan")


if __name__ == "__main__":
    cli()
