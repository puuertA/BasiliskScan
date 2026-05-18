# src/basiliskscan/commands/scan.py
"""Comando de varredura de dependências."""

from typing import Optional

import click

from ..config import DEFAULT_OUTPUT_FILE
from ..controllers.scan_controller import ScanController
from ..views.help_view import (
    SCAN_HELP,
    PROJECT_OPTION_HELP,
    URL_OPTION_HELP,
    OUTPUT_OPTION_HELP,
    SKIP_VULNS_OPTION_HELP,
    INCLUDE_TRANSITIVE_OPTION_HELP,
    OFFLINE_OPTION_HELP,
)
from ..views.terminal_view import BasiliskCommand


@click.command(
    cls=BasiliskCommand,
    help=SCAN_HELP,
    context_settings={"help_option_names": ["-h", "--help"]},
)
@click.option(
    "--project",
    "-p",
    "project",
    type=str,
    default=".",
    show_default=True,
    help=PROJECT_OPTION_HELP,
    metavar="<diretório>"
)
@click.option(
    "--url",
    "-u",
    "url",
    type=str,
    default=None,
    help=URL_OPTION_HELP,
    metavar="<caminho>"
)
@click.option(
    "--output",
    "-o",
    "output",
    type=str,
    default=DEFAULT_OUTPUT_FILE,
    show_default=True,
    help=OUTPUT_OPTION_HELP,
    metavar="<arquivo.html>"
)
@click.option(
    "--skip-vulns",
    is_flag=True,
    default=False,
    help=SKIP_VULNS_OPTION_HELP,
)
@click.option(
    "--include-transitive",
    is_flag=True,
    default=False,
    help=INCLUDE_TRANSITIVE_OPTION_HELP,
)
@click.option(
    "--offline",
    is_flag=True,
    default=False,
    help=OFFLINE_OPTION_HELP,
)
def scan_command(
    project: str,
    url: Optional[str],
    output: str,
    skip_vulns: bool,
    include_transitive: bool,
    offline: bool,
):
    """
    🚀 Executa uma varredura completa de dependências no projeto alvo.
    
    Analisa recursivamente o diretório especificado em busca de arquivos
    de dependências suportados (Node.js/Ionic e Java) e gera um relatório
    interativo em HTML com abas para navegação entre componentes,
    vulnerabilidades e componentes desatualizados.
    """
    controller = ScanController()
    controller.execute(project, url, output, skip_vulns, include_transitive, offline)