# src/basiliskscan/scanner.py
"""Módulo responsável pela descoberta e análise de arquivos de dependências."""

import pathlib
from typing import List, Dict
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn

from .config import IGNORED_DIRS, SUPPORTED_FILES
from .parsers import get_parser_for_file


class DependencyScanner:
    """Scanner para descoberta e análise de dependências em projetos."""
    
    def __init__(self, console: Console = None):
        """
        Inicializa o scanner.
        
        Args:
            console: Console do Rich para output formatado
        """
        self.console = console or Console()
    
    def _walk_directory(self, path: pathlib.Path, accumulator: List[pathlib.Path]) -> None:
        """
        Percorre recursivamente um diretório coletando arquivos de dependências.
        
        Args:
            path: Diretório a ser percorrido
            accumulator: Lista onde os arquivos encontrados serão adicionados
        """
        if path.is_dir():
            # Ignora diretórios na lista de exclusão
            if path.name in IGNORED_DIRS:
                return
            
            try:
                for child in path.iterdir():
                    self._walk_directory(child, accumulator)
            except PermissionError:
                # Ignora diretórios sem permissão de leitura
                self.console.print(f"[yellow]⚠️  Sem permissão para acessar: {path}[/yellow]")
                return
        else:
            # Adiciona arquivos de dependências suportados
            if path.name in SUPPORTED_FILES:
                accumulator.append(path)
    
    def find_dependency_files(self, root: pathlib.Path) -> List[pathlib.Path]:
        """
        Encontra todos os arquivos de dependências em um projeto.
        
        Args:
            root: Diretório raiz do projeto
            
        Returns:
            Lista de caminhos para arquivos de dependências encontrados
            
        Raises:
            FileNotFoundError: Se o diretório raiz não existir
            NotADirectoryError: Se o path não for um diretório
        """
        if not root.exists():
            raise FileNotFoundError(f"Diretório não encontrado: {root}")
        
        if not root.is_dir():
            raise NotADirectoryError(f"Path não é um diretório: {root}")
        
        candidates: List[pathlib.Path] = []
        
        try:
            for path in root.iterdir():
                self._walk_directory(path, candidates)
        except PermissionError:
            raise PermissionError(f"Sem permissão para acessar o diretório: {root}")
        
        return candidates
    
    def collect_dependencies(self, root: pathlib.Path) -> List[Dict]:
        """
        Coleta todas as dependências encontradas no projeto.
        
        Args:
            root: Diretório raiz do projeto
            
        Returns:
            Lista de dicionários com informações das dependências
        """
        files = self.find_dependency_files(root)
        deps: List[Dict] = []

        if not files:
            self.console.print("[yellow]⚠️  [BasiliskScan][/yellow] Nenhum arquivo de dependência encontrado no projeto.")
            self.console.print(f"[dim]   Procurando por: {', '.join(SUPPORTED_FILES)}[/dim]")
            self.console.print("[dim]   Dica: Verifique se está no diretório correto do projeto[/dim]")
            return deps

        self.console.print(f"[green]📁 Arquivos de dependência encontrados: {len(files)}[/green]")
        for f in files:
            self.console.print(f"   • [cyan]{f.name}[/cyan] em [dim]{f.parent}[/dim]")
        
        self.console.print()

        processed_messages: List[str] = []

        with Progress(
            SpinnerColumn(),
            BarColumn(),
            TextColumn("[bold blue]{task.description}"),
            TimeElapsedColumn(),
            transient=False,
            console=self.console,
        ) as progress:
            task = progress.add_task("📋 Processando arquivos de dependências...", total=len(files))
            
            for f in files:
                progress.update(task, description=f"📋 Processando {f.name}...")
                
                try:
                    parser = get_parser_for_file(f.name)
                    file_deps = parser(f)
                    deps.extend(file_deps)
                    processed_messages.append(
                        f"   ✓ [green]{f.name}[/green]: {len(file_deps)} dependência(s) extraída(s)"
                    )
                    
                except Exception as e:
                    processed_messages.append(f"   ❌ [red]Erro ao processar {f.name}[/red]: {str(e)}")
                    continue
                
                progress.advance(task)

        for message in processed_messages:
            self.console.print(message)
        
        self.console.print()
        return deps
    
    def get_project_statistics(self, dependencies: List[Dict]) -> Dict:
        """
        Calcula estatísticas do projeto baseado nas dependências encontradas.
        
        Args:
            dependencies: Lista de dependências
            
        Returns:
            Dicionário com estatísticas organizadas por ecossistema
        """
        ecosystems = {}
        for dep in dependencies:
            eco = dep.get("ecosystem", "unknown")
            ecosystems[eco] = ecosystems.get(eco, 0) + 1
        
        return ecosystems