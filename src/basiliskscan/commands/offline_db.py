"""Comando para gerenciamento do banco local offline de vulnerabilidades."""

from __future__ import annotations

from typing import Any, Dict, List

import click
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn

from ..env import load_dotenv
from ..ingest.offline_db import OfflineVulnerabilityDB
from ..ingest.offline_sync import OfflineSyncService
from ..scanner import DependencyScanner
from ..ui import BasiliskCommand, UIHelper, normalize_cli_directory_input, validate_target_path


def _build_unique_components(dependencies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    unique_components: List[Dict[str, Any]] = []

    for dependency in dependencies:
        name = dependency.get("name")
        raw_version = dependency.get("version_spec")
        version = str(raw_version).strip() if raw_version is not None else ""
        clean_version = version.lstrip("^~>=<")
        ecosystem = dependency.get("ecosystem")

        key = (name, clean_version, ecosystem)
        if not name or key in seen:
            continue

        seen.add(key)
        unique_components.append(
            {
                "name": name,
                "version": clean_version if clean_version else None,
                "ecosystem": ecosystem,
            }
        )

    return unique_components


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
    load_dotenv()
    ui = UIHelper()
    db = OfflineVulnerabilityDB()
    service = OfflineSyncService(db=db)
    normalized_project_path = None

    if project_path is not None:
        normalized_project_path = normalize_cli_directory_input(project_path)
        validate_target_path(normalized_project_path)

    try:
        if clear and (status or sync or force or normalized_project_path is not None):
            raise click.ClickException("Use --clear sozinho, sem combinar com outras opções.")

        if force and not sync and normalized_project_path is None:
            sync = True

        if clear:
            db.clear()
            ui.display_success("Banco offline limpo com sucesso.")
            ui.console.print(f"   • Arquivo: [italic]{db.db_path}[/italic]")
            return

        if status:
            stats = db.get_stats()
            ui.console.print("[bold green]📦 Status do banco offline[/bold green]")
            ui.console.print(f"   • Caminho: [italic]{stats['db_path']}[/italic]")
            ui.console.print(f"   • Componentes rastreados: [bold]{stats['total_components']}[/bold]")
            ui.console.print(f"   • Vulnerabilidades armazenadas: [bold]{stats['total_vulnerabilities']}[/bold]")
            ui.console.print(f"   • Intervalo de atualização: [bold]{stats['refresh_interval_days']}[/bold] dia(s)")
            ui.console.print(f"   • Última sync completa: [bold]{stats['last_full_sync_at'] or 'nunca'}[/bold]")

            if stats["by_severity"]:
                sev = ", ".join(f"{k}: {v}" for k, v in sorted(stats["by_severity"].items()))
                ui.console.print(f"   • Por severidade: {sev}")
            if stats["by_source"]:
                src = ", ".join(f"{k}: {v}" for k, v in sorted(stats["by_source"].items()))
                ui.console.print(f"   • Por fonte: {src}")

            if not sync and normalized_project_path is None:
                return

        components: List[Dict[str, Any]] = []
        if normalized_project_path is not None:
            ui.console.print(f"[cyan]🔎 Descobrindo dependências em {normalized_project_path}...[/cyan]")
            scanner = DependencyScanner(ui.console)
            dependencies = scanner.collect_dependencies(normalized_project_path)
            components = _build_unique_components(dependencies)
            ui.console.print(f"[dim]   Componentes únicos para sincronizar: {len(components)}[/dim]")

        if sync or normalized_project_path is not None:
            if components:
                components_to_sync = components
            elif force:
                components_to_sync = db.get_all_components()
            else:
                components_to_sync = db.get_components_due_for_sync()

            if not components_to_sync:
                ui.display_info("Nenhum componente pendente para sincronização.")
                return

            with Progress(
                SpinnerColumn(),
                BarColumn(),
                TextColumn("[bold blue]{task.description}"),
                TimeElapsedColumn(),
                console=ui.console,
            ) as progress:
                task = progress.add_task(
                    "🔄 Sincronizando componentes no banco offline...",
                    total=len(components_to_sync),
                )

                def update_sync_progress(component_name: str):
                    progress.update(task, description=f"🔄 Sincronizando {component_name}...")
                    progress.advance(task)

                summary = service.sync_components(
                    components=components_to_sync,
                    force=force,
                    progress_callback=update_sync_progress,
                )

            if summary["processed"] > 0 and (force or db.needs_weekly_sync(service.refresh_interval_days)):
                db.set_last_full_sync()

            ui.console.print("[bold green]🔄 Sincronização offline concluída[/bold green]")
            ui.console.print(f"   • Processados: [bold]{summary['processed']}[/bold]")
            ui.console.print(f"   • Sincronizados: [bold]{summary['synced']}[/bold]")
            ui.console.print(f"   • Vulnerabilidades totais: [bold]{summary['total_vulnerabilities']}[/bold]")
            if summary["errors"]:
                ui.console.print(f"   • Erros: [bold red]{summary['errors']}[/bold red]")
            return

        if not status:
            ui.display_info("Nenhuma ação selecionada.")
            ui.console.print("Use [bold]bscan offline-db --help[/bold] para ver as opções.")
    finally:
        service.close()
