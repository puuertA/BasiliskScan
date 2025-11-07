# src/basiliskscan/commands/scan.py
"""Comando de varredura de dependências."""

import pathlib
from typing import Optional
import click

from ..config import DEFAULT_OUTPUT_FILE
from ..help_text import SCAN_HELP, PROJECT_OPTION_HELP, URL_OPTION_HELP, OUTPUT_OPTION_HELP
from ..ui import BasiliskCommand, UIHelper, validate_target_path, handle_file_save_error
from ..scanner import DependencyScanner
from ..reporter import ReportGenerator


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
def scan_command(project: str, url: Optional[str], output: str):
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
        dependencies = scanner.collect_dependencies(target_path)
        ecosystems = scanner.get_project_statistics(dependencies)
        
        # Gera e salva o relatório
        report_data = reporter.generate_report_data(target_path, dependencies, ecosystems, output)
        
        try:
            # save_report_to_file agora retorna o caminho final do arquivo salvo
            final_output_path = reporter.save_report_to_file(report_data, output)
        except Exception as e:
            handle_file_save_error(e, output)
        
        # Exibe resultados com o caminho final
        reporter.display_scan_results(dependencies, ecosystems, final_output_path)
        
    except KeyboardInterrupt:
        ui.display_warning("Operação cancelada pelo usuário.")
        raise click.Abort()
    except Exception as e:
        ui.display_error(f"Erro durante a varredura: {str(e)}")
        raise click.Abort()