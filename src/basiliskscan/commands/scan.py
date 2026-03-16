# src/basiliskscan/commands/scan.py
"""Comando de varredura de dependências."""

import pathlib
from typing import Optional
import click
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn

from ..config import DEFAULT_OUTPUT_FILE
from ..help_text import SCAN_HELP, PROJECT_OPTION_HELP, URL_OPTION_HELP, OUTPUT_OPTION_HELP
from ..ui import BasiliskCommand, UIHelper, validate_target_path, handle_file_save_error
from ..scanner import DependencyScanner
from ..reporter import ReportGenerator
from ..ingest.aggregator import VulnerabilityAggregator
from ..updater import DependencyUpdateService


def _is_transitive_dependency(dep: dict) -> bool:
    """Identifica se uma dependência é transitiva."""
    if dep.get("is_transitive") is True:
        return True

    dependency_type = str(dep.get("dependency_type", "")).strip().lower()
    return dependency_type == "transitive"


def _filter_scan_dependencies(dependencies: list[dict], include_transitive: bool) -> list[dict]:
    """Filtra dependências usadas no scan, mantendo transitivas apenas quando solicitado."""
    if include_transitive:
        return dependencies

    return [dep for dep in dependencies if not _is_transitive_dependency(dep)]


@click.command(
    cls=BasiliskCommand,
    help=SCAN_HELP,
    context_settings={"help_option_names": ["-h", "--help"]},
)
@click.option(
    "--project",
    "-p",
    "project",
    type=click.Path(file_okay=False, exists=True, path_type=pathlib.Path),
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
    type=str,  # ← MUDANÇA AQUI: usar str em vez de click.Path
    default=DEFAULT_OUTPUT_FILE,
    show_default=True,
    help=OUTPUT_OPTION_HELP,
    metavar="<arquivo.html>"
)
@click.option(
    "--skip-vulns",
    is_flag=True,
    default=False,
    help="Pular a análise de vulnerabilidades (mais rápido)"
)
@click.option(
    "--include-transitive",
    is_flag=True,
    default=False,
    help="Incluir dependências transitivas no relatório e na busca de vulnerabilidades",
)
def scan_command(
    project: str,
    url: Optional[str],
    output: str,
    skip_vulns: bool,
    include_transitive: bool,
):
    """
    🚀 Executa uma varredura completa de dependências no projeto alvo.
    
    Analisa recursivamente o diretório especificado em busca de arquivos
    de dependências (package.json, requirements.txt) e gera um relatório
    interativo em HTML com abas para navegação entre componentes, vulnerabilidades
    e componentes desatualizados.
    """
    # Inicializa componentes
    ui = UIHelper()
    scanner = DependencyScanner(ui.console)
    reporter = ReportGenerator(ui.console)
    
    # Exibe header da aplicação
    ui.display_app_header()
    
    # Determina o diretório alvo baseado nos parâmetros fornecidos
    if url:
        target_path = pathlib.Path(url).resolve()
        url_mode = True
    else:
        target_path = pathlib.Path(project).resolve()
        url_mode = False
    
    # Valida o diretório alvo
    validate_target_path(target_path, url)
    
    # Exibe informações da varredura
    reporter.display_scan_header(target_path, output, url_mode, url)
    
    # Executa a varredura
    try:
        all_dependencies = scanner.collect_dependencies(target_path)
        dependencies = _filter_scan_dependencies(all_dependencies, include_transitive)
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
                updater = DependencyUpdateService()
                npm_candidates = {
                    dep.get('name', '')
                    for dep in dependencies
                    if dep.get('ecosystem') in {'npm', 'ionic'} and dep.get('name')
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

                        dependencies = updater.enrich_with_latest_versions_progress(
                            dependencies,
                            progress_callback=update_version_progress,
                        )
                else:
                    dependencies = updater.enrich_with_latest_versions(dependencies)
            except Exception as e:
                ui.console.print(f"[yellow]⚠️  Erro ao verificar atualizações: {str(e)}[/yellow]")
                ui.console.print("[dim]   Continuando sem dados de versão mais recente...[/dim]")
        
        # Buscar vulnerabilidades se não for pulado
        vulnerabilities = {}
        if not skip_vulns and dependencies:
            ui.console.print("[cyan]🔍 Buscando vulnerabilidades...[/cyan]")
            
            try:
                aggregator = VulnerabilityAggregator()
                
                # Preparar componentes para busca
                components_to_check = []
                for dep in dependencies:
                    # Extrair versão limpa (remover operadores como ^, ~, >=, etc)
                    version = dep.get('version_spec', '')
                    clean_version = version.lstrip('^~>=<')
                    
                    components_to_check.append({
                        'name': dep.get('name', ''),
                        'version': clean_version if clean_version else None,
                        'ecosystem': dep.get('ecosystem', '')
                    })
                
                # Debug: mostrar componentes que serão verificados
                ui.console.print(f"[dim]Debug: Componentes a verificar: {[c['name'] for c in components_to_check[:5]]}{'...' if len(components_to_check) > 5 else ''}[/dim]")
                
                # Buscar vulnerabilidades em paralelo
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
                
                # Debug: mostrar chaves retornadas
                ui.console.print(f"[dim]Debug: Chaves de vulnerabilidades retornadas: {list(vulnerabilities.keys())}[/dim]")
                
                # Contar vulnerabilidades encontradas
                total_vulns = sum(len(v) for v in vulnerabilities.values())
                vulns_components = sum(1 for v in vulnerabilities.values() if v)
                
                if total_vulns > 0:
                    ui.console.print(f"[yellow]⚠️  Encontradas {total_vulns} vulnerabilidade(s) em {vulns_components} componente(s)[/yellow]")
                    # Debug: mostrar quais componentes têm vulnerabilidades
                    for comp_name, vulns in vulnerabilities.items():
                        if vulns:
                            ui.console.print(f"[dim]   - {comp_name}: {len(vulns)} vulnerabilidade(s)[/dim]")
                else:
                    ui.console.print("[green]✅ Nenhuma vulnerabilidade conhecida encontrada[/green]")
                    
            except Exception as e:
                ui.console.print(f"[yellow]⚠️  Erro ao buscar vulnerabilidades: {str(e)}[/yellow]")
                ui.console.print("[dim]   Continuando sem análise de vulnerabilidades...[/dim]")
                vulnerabilities = {}
        elif skip_vulns:
            ui.console.print("[dim]🔍 Análise de vulnerabilidades pulada (--skip-vulns)[/dim]")
        
        # Gera e salva o relatório
        report_data = reporter.generate_report_data(
            target_path,
            dependencies,
            ecosystems,
            output,
            vulnerabilities,
            report_options={
                "include_transitive": include_transitive,
                "transitive_hidden_count": filtered_count,
            },
        )
        
        try:
            # save_report_to_file agora retorna o caminho final do arquivo salvo
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
                        'resources': '💾 Preparando recursos do relatório...',
                        'html': '💾 Renderizando HTML do relatório...',
                        'written': '💾 Gravando arquivo do relatório...',
                    }
                    progress.update(task, description=stage_map.get(stage, '💾 Gerando relatório HTML...'))
                    progress.advance(task)

                final_output_path = reporter.save_report_to_file(
                    report_data,
                    output,
                    progress_callback=update_report_progress,
                )
        except Exception as e:
            handle_file_save_error(e, output)
        
        # Exibe resultados com o caminho final
        reporter.display_scan_results(dependencies, ecosystems, final_output_path, vulnerabilities)
        
    except KeyboardInterrupt:
        ui.display_warning("Operação cancelada pelo usuário.")
        raise click.Abort()
    except Exception as e:
        ui.display_error(f"Erro durante a varredura: {str(e)}")
        raise click.Abort()