# src/basiliskscan/reporter.py
"""Módulo responsável pela geração de relatórios e apresentação de resultados."""

import json
import pathlib
from datetime import datetime
from typing import Dict, List
from rich.console import Console

from .config import APP_NAME, APP_VERSION, ECOSYSTEM_EMOJIS


class ReportGenerator:
    """Gerador de relatórios de análise de dependências."""
    
    def __init__(self, console: Console = None):
        """
        Inicializa o gerador de relatórios.
        
        Args:
            console: Console do Rich para output formatado
        """
        self.console = console or Console()
    
    def generate_report_data(
        self, 
        target_path: pathlib.Path, 
        dependencies: List[Dict], 
        ecosystems: Dict, 
        output_file: str
    ) -> Dict:
        """
        Gera os dados estruturados do relatório.
        
        Args:
            target_path: Caminho do projeto analisado
            dependencies: Lista de dependências encontradas
            ecosystems: Estatísticas por ecossistema
            output_file: Arquivo de saída
            
        Returns:
            Dicionário com dados estruturados do relatório
        """
        return {
            "scan_metadata": {
                "tool": APP_NAME,
                "version": APP_VERSION,
                "scan_date": datetime.now().isoformat(),
                "scan_timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "target_path": str(target_path),
                "output_file": output_file
            },
            "project_info": {
                "path": str(target_path),
                "dependency_count": len(dependencies),
                "ecosystems_found": ecosystems
            },
            "dependencies": dependencies
        }
    
    def save_report_to_file(self, report_data: Dict, output_path: str) -> None:
        """
        Salva o relatório em arquivo JSON.
        
        Args:
            report_data: Dados do relatório
            output_path: Caminho do arquivo de saída
            
        Raises:
            PermissionError: Se não houver permissão para escrever no arquivo
            OSError: Se houver erro de I/O ao salvar o arquivo
        """
        output_file = pathlib.Path(output_path)
        
        # Avisa se o arquivo já existe
        if output_file.exists():
            self.console.print(f"[yellow]⚠️  O arquivo '{output_path}' já existe e será sobrescrito.[/yellow]")
        
        try:
            with open(output_path, "w", encoding="utf-8") as fh:
                json.dump(report_data, fh, indent=2, ensure_ascii=False)
        except PermissionError:
            raise PermissionError(f"Sem permissão para escrever no arquivo: {output_path}")
        except OSError as e:
            raise OSError(f"Erro ao salvar o relatório: {e}")
    
    def display_scan_results(self, dependencies: List[Dict], ecosystems: Dict, output_file: str) -> None:
        """
        Exibe os resultados da varredura no console.
        
        Args:
            dependencies: Lista de dependências encontradas
            ecosystems: Estatísticas por ecossistema
            output_file: Arquivo onde o relatório foi salvo
        """
        self.console.print("[bold green]✅ Varredura concluída com sucesso![/bold green]")
        self.console.print(f"[cyan]📊 Estatísticas:[/cyan]")
        self.console.print(f"   • [bold]{len(dependencies)}[/bold] dependências encontradas")
        
        for eco, count in ecosystems.items():
            emoji = ECOSYSTEM_EMOJIS.get(eco, "❓")
            self.console.print(f"   • {emoji} [bold]{count}[/bold] dependência(s) do ecossistema [italic]{eco}[/italic]")
        
        self.console.print(f"\n[bold blue]📁 Relatório detalhado salvo em:[/bold blue] [underline]{output_file}[/underline]")
        self.console.print("[dim]💡 Dica: Use 'cat' ou seu editor preferido para visualizar o relatório JSON[/dim]")
    
    def display_scan_header(self, target_path: pathlib.Path, output_file: str, url_mode: bool = False, url: str = None) -> None:
        """
        Exibe o cabeçalho da varredura.
        
        Args:
            target_path: Caminho do projeto sendo analisado
            output_file: Arquivo onde o relatório será salvo
            url_mode: Se está usando modo URL
            url: URL original (se aplicável)
        """
        if url_mode and url:
            self.console.print(f"[dim]🎯 Usando modo URL: {url}[/dim]")
        else:
            self.console.print(f"[dim]🎯 Usando diretório do projeto: {target_path}[/dim]")
        
        self.console.print(f"[cyan]🔍 [BasiliskScan][/cyan] Analisando projeto em: [bold green]{target_path}[/bold green]")
        self.console.print(f"[dim]📋 Relatório será salvo em: {output_file}[/dim]\n")


class SummaryReporter:
    """Gerador de relatórios resumidos."""
    
    @staticmethod
    def generate_dependency_summary(dependencies: List[Dict]) -> Dict:
        """
        Gera um resumo das dependências por arquivo e ecossistema.
        
        Args:
            dependencies: Lista de dependências
            
        Returns:
            Dicionário com resumo organizado
        """
        summary = {
            "total_dependencies": len(dependencies),
            "by_ecosystem": {},
            "by_file": {},
            "files_analyzed": set()
        }
        
        for dep in dependencies:
            # Por ecossistema
            eco = dep.get("ecosystem", "unknown")
            summary["by_ecosystem"][eco] = summary["by_ecosystem"].get(eco, 0) + 1
            
            # Por arquivo
            file_path = dep.get("declared_in", "unknown")
            summary["by_file"][file_path] = summary["by_file"].get(file_path, 0) + 1
            summary["files_analyzed"].add(file_path)
        
        # Converte set para list para serialização JSON
        summary["files_analyzed"] = list(summary["files_analyzed"])
        
        return summary