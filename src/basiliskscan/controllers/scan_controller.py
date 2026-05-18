"""Controlador do fluxo de varredura de dependências."""

from __future__ import annotations

import time
from typing import Optional

import click
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn

from ..env import load_dotenv
from ..ingest.aggregator import VulnerabilityAggregator
from ..ingest.offline_sync import OfflineSyncService
from ..reports.html_reporter import ReportGenerator
from ..services.dependency_update_service import DependencyUpdateService
from ..services.scanner_service import DependencyScanner
from ..views.terminal_view import (
    UIHelper,
    validate_target_path,
    handle_file_save_error,
    normalize_cli_directory_input,
)


class ScanController:
    """Coordena o fluxo principal de varredura."""

    def __init__(
        self,
        ui: UIHelper | None = None,
        scanner: DependencyScanner | None = None,
        reporter: ReportGenerator | None = None,
        updater: DependencyUpdateService | None = None,
    ) -> None:
        self.ui = ui or UIHelper()
        self.scanner = scanner or DependencyScanner(self.ui.console)
        self.reporter = reporter or ReportGenerator(self.ui.console)
        self.updater = updater or DependencyUpdateService()

    @staticmethod
    def _is_transitive_dependency(dependency: dict) -> bool:
        if dependency.get("is_transitive") is True:
            return True

        dependency_type = str(dependency.get("dependency_type", "")).strip().lower()
        return dependency_type == "transitive"

    @classmethod
    def _filter_scan_dependencies(cls, dependencies: list[dict], include_transitive: bool) -> list[dict]:
        if include_transitive:
            return dependencies

        return [dep for dep in dependencies if not cls._is_transitive_dependency(dep)]

    @staticmethod
    def _build_unique_components_for_vuln_scan(dependencies: list[dict]) -> list[dict]:
        unique: list[dict] = []
        seen_keys: set[tuple[str, str, str]] = set()

        for dep in dependencies:
            name = str(dep.get("name", "") or "").strip()
            if not name:
                continue

            raw_version = dep.get("version_spec")
            version = str(raw_version).strip() if raw_version is not None else ""
            clean_version = version.lstrip("^~>=<")
            ecosystem = str(dep.get("ecosystem", "") or "").strip().lower()

            key = (name.lower(), clean_version, ecosystem)
            if key in seen_keys:
                continue

            seen_keys.add(key)
            unique.append(
                {
                    "name": name,
                    "version": clean_version if clean_version else None,
                    "ecosystem": ecosystem,
                }
            )

        return unique

    def execute(
        self,
        project: str,
        url: Optional[str],
        output: str,
        skip_vulns: bool,
        include_transitive: bool,
        offline: bool,
    ) -> None:
        ui = self.ui
        scanner = self.scanner
        reporter = self.reporter
        scan_started_at = time.monotonic()

        ui.display_app_header()

        if url:
            target_path = normalize_cli_directory_input(url)
            url_mode = True
        else:
            target_path = normalize_cli_directory_input(project)
            url_mode = False

        validate_target_path(target_path, url)
        load_dotenv(search_from=target_path)
        reporter.display_scan_header(target_path, output, url_mode, url)

        try:
            all_dependencies = scanner.collect_dependencies(target_path)
            dependencies = self._filter_scan_dependencies(all_dependencies, include_transitive)
            filtered_count = 0

            if not include_transitive:
                filtered_count = len(all_dependencies) - len(dependencies)
                if filtered_count > 0:
                    ui.console.print(
                        f"[dim]↪ Ignorando {filtered_count} dependência(s) transitiva(s). "
                        "Use --include-transitive para incluir.[/dim]"
                    )

            ecosystems = scanner.get_project_statistics(dependencies)

            if dependencies:
                ui.console.print("[cyan]⬆️ Verificando versões mais recentes...[/cyan]")
                try:
                    npm_candidates = {
                        dep.get("name", "")
                        for dep in dependencies
                        if dep.get("ecosystem") in {"npm", "ionic"} and dep.get("name")
                    }

                    if npm_candidates:
                        with Progress(
                            SpinnerColumn(),
                            BarColumn(),
                            TextColumn("[bold blue]{task.description}"),
                            TimeElapsedColumn(),
                            console=ui.console,
                        ) as progress:
                            task = progress.add_task(
                                "⬆️ Consultando versões no registry...",
                                total=len(npm_candidates),
                            )

                            def update_version_progress(package_name: str):
                                progress.update(task, description=f"⬆️ Verificando {package_name}...")
                                progress.advance(task)

                            dependencies = self.updater.enrich_with_latest_versions_progress(
                                dependencies,
                                progress_callback=update_version_progress,
                            )
                    else:
                        dependencies = self.updater.enrich_with_latest_versions(dependencies)
                except Exception as exc:
                    ui.console.print(f"[yellow]⚠️  Erro ao verificar atualizações: {str(exc)}[/yellow]")
                    ui.console.print("[dim]   Continuando sem dados de versão mais recente...[/dim]")

            vulnerabilities = {}
            offline_sync_service: Optional[OfflineSyncService] = None
            if not skip_vulns and dependencies:
                ui.console.print("[cyan]🔍 Buscando vulnerabilidades...[/cyan]")

                try:
                    offline_sync_service = OfflineSyncService()
                    aggregator = VulnerabilityAggregator()

                    components_to_check = self._build_unique_components_for_vuln_scan(dependencies)

                    if offline:
                        ui.console.print(
                            "[yellow]📦 Modo offline ativo: usando apenas banco local de vulnerabilidades[/yellow]"
                        )
                        vulnerabilities = offline_sync_service.get_vulnerabilities_for_components(components_to_check)
                    else:
                        auto_sync_summary = offline_sync_service.run_weekly_auto_sync_if_needed()
                        if auto_sync_summary and auto_sync_summary.get("processed", 0) > 0:
                            ui.console.print(
                                "[dim]↻ Atualização semanal automática do banco offline concluída: "
                                f"{auto_sync_summary['synced']}/{auto_sync_summary['processed']} componente(s).[/dim]"
                            )

                    if not offline:
                        ui.console.print(f"[dim]   Analisando {len(components_to_check)} componente(s)...[/dim]")
                        with Progress(
                            SpinnerColumn(),
                            BarColumn(),
                            TextColumn("[bold blue]{task.description}"),
                            TimeElapsedColumn(),
                            console=ui.console,
                        ) as progress:
                            task = progress.add_task(
                                "🔍 Consultando fontes de vulnerabilidades...",
                                total=len(components_to_check),
                            )

                            def update_vulnerability_progress(component_name: str):
                                progress.update(task, description=f"🔍 Analisando {component_name}...")
                                progress.advance(task)

                            vulnerabilities = aggregator.fetch_multiple_components(
                                components_to_check,
                                parallel=True,
                                progress_callback=update_vulnerability_progress,
                            )

                        ui.console.print("[cyan]💾 Sincronizando componentes para banco offline...[/cyan]")
                        with Progress(
                            SpinnerColumn(),
                            TextColumn("[bold blue]{task.description}"),
                            TimeElapsedColumn(),
                            console=ui.console,
                        ) as progress:
                            task = progress.add_task("💾 Gravando no banco offline...", total=None)
                            sync_summary = offline_sync_service.sync_components(
                                components=components_to_check,
                                force=False,
                                progress_callback=lambda name: progress.update(
                                    task, description=f"💾 Sincronizando {name}..."
                                ),
                            )
                        if sync_summary.get("synced", 0) > 0:
                            ui.console.print(
                                f"[dim]↪ {sync_summary['synced']}/{sync_summary['processed']} componente(s) "
                                "sincronizado(s) para banco offline local[/dim]"
                            )

                        offline_sync_service.ingest_scan_results(
                            components=components_to_check,
                            vulnerabilities_by_name=vulnerabilities,
                        )

                    total_vulns = sum(len(v) for v in vulnerabilities.values())
                    vulns_components = sum(1 for v in vulnerabilities.values() if v)

                    if total_vulns > 0:
                        ui.console.print(
                            f"[yellow]⚠️  Encontradas {total_vulns} vulnerabilidade(s) em {vulns_components} "
                            "componente(s)[/yellow]"
                        )
                    else:
                        ui.console.print("[green]✅ Nenhuma vulnerabilidade conhecida encontrada[/green]")

                except Exception as exc:
                    ui.console.print(f"[yellow]⚠️  Erro ao buscar vulnerabilidades: {str(exc)}[/yellow]")
                    ui.console.print("[dim]   Continuando sem análise de vulnerabilidades...[/dim]")
                    vulnerabilities = {}
                finally:
                    if offline_sync_service:
                        offline_sync_service.close()
            elif skip_vulns:
                ui.console.print("[dim]🔍 Análise de vulnerabilidades pulada (--skip-vulns)[/dim]")

            report_data = reporter.generate_report_data(
                target_path,
                dependencies,
                ecosystems,
                output,
                vulnerabilities,
                all_dependencies=all_dependencies,
                report_options={
                    "include_transitive": include_transitive,
                    "transitive_hidden_count": filtered_count,
                },
                duration_seconds=(time.monotonic() - scan_started_at),
            )

            try:
                with Progress(
                    SpinnerColumn(),
                    BarColumn(),
                    TextColumn("[bold blue]{task.description}"),
                    TimeElapsedColumn(),
                    console=ui.console,
                ) as progress:
                    task = progress.add_task("💾 Gerando relatório HTML...", total=3)

                    def update_report_progress(stage: str):
                        stage_map = {
                            "resources": "💾 Preparando recursos do relatório...",
                            "html": "💾 Renderizando HTML do relatório...",
                            "written": "💾 Gravando arquivo do relatório...",
                        }
                        progress.update(task, description=stage_map.get(stage, "💾 Gerando relatório HTML..."))
                        progress.advance(task)

                    final_output_path = reporter.save_report_to_file(
                        report_data,
                        output,
                        progress_callback=update_report_progress,
                    )

                duration_after_write = time.monotonic() - scan_started_at
                reporter.update_saved_report_duration(final_output_path, duration_after_write)
            except Exception as exc:
                handle_file_save_error(exc, output)

            reporter.display_scan_results(dependencies, ecosystems, final_output_path, vulnerabilities)

        except KeyboardInterrupt:
            ui.display_warning("Operação cancelada pelo usuário.")
            raise click.Abort()
        except Exception as exc:
            ui.display_error(f"Erro durante a varredura: {str(exc)}")
            raise click.Abort()
