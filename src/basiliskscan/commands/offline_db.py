"""Comando para gerenciamento do banco local offline de vulnerabilidades."""

from __future__ import annotations

import click

from ..controllers.offline_db_controller import OfflineDBController
from ..views.terminal_view import BasiliskCommand


@click.command(
    cls=BasiliskCommand,
    name="offline-db",
    context_settings={"help_option_names": ["-h", "--help"]},
    help="Gerencia o banco offline de vulnerabilidades (status, sincronização e limpeza).",
)
@click.option(
    "--status",
    is_flag=True,
    default=False,
    help="Mostra estatísticas do banco local offline.",
)
@click.option(
    "--sync",
    is_flag=True,
    default=False,
    help="Sincroniza componentes vencidos com as APIs e atualiza o banco local.",
)
@click.option(
    "--force",
    is_flag=True,
    default=False,
    help="Força sincronização completa de todos os componentes rastreados.",
)
@click.option(
    "--clear",
    is_flag=True,
    default=False,
    help="Limpa completamente o banco offline local.",
)
@click.option(
    "--project",
    "project_path",
    type=str,
    default=None,
    help="Diretório opcional para descobrir componentes do projeto e sincronizar no banco.",
)
def offline_db_command(
    status: bool,
    sync: bool,
    force: bool,
    clear: bool,
    project_path: str | None,
):
    """Executa operações no banco offline consolidado de vulnerabilidades."""
    controller = OfflineDBController()
    controller.execute(status, sync, force, clear, project_path)
