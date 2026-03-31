# src/basiliskscan/ui.py
"""Módulo para customizações da interface de usuário e classes Click personalizadas."""

import click
from rich.console import Console

from .help_text import LOGO
from .config import APP_NAME, APP_VERSION, APP_DESCRIPTION


class BasiliskCommand(click.Command):
    """Comando Click customizado com logo e branding do BasiliskScan."""
    
    def __init__(self, *args, **kwargs):
        self.console = Console()
        super().__init__(*args, **kwargs)
    
    def get_help(self, ctx):
        """Exibe help personalizado com logo e informações da ferramenta."""
        self.console.print(f"[bold green]{LOGO}[/bold green]")
        self.console.print(f"[bold cyan]{APP_NAME} v{APP_VERSION}[/bold cyan]")
        self.console.print(f"[italic]{APP_DESCRIPTION}[/italic]")
        self.console.print("[dim]Identifica dependências vulneráveis e desatualizadas em projetos de software[/dim]\n")
        return super().get_help(ctx)


class BasiliskGroup(click.Group):
    """Grupo Click customizado com logo e branding do BasiliskScan."""
    
    def __init__(self, *args, **kwargs):
        self.console = Console()
        super().__init__(*args, **kwargs)
    
    def get_help(self, ctx):
        """Exibe help personalizado com logo e informações da ferramenta."""
        self.console.print(f"[bold green]{LOGO}[/bold green]")
        self.console.print(f"[bold cyan]{APP_NAME} v{APP_VERSION}[/bold cyan]")
        self.console.print(f"[italic]{APP_DESCRIPTION}[/italic]")
        self.console.print("[dim]Identifica dependências vulneráveis e desatualizadas em projetos de software[/dim]\n")
        return super().get_help(ctx)


class UIHelper:
    """Classe auxiliar para operações de interface de usuário."""
    
    def __init__(self, console: Console = None):
        """
        Inicializa o helper de UI.
        
        Args:
            console: Console do Rich para output formatado
        """
        self.console = console or Console()
    
    def display_app_header(self) -> None:
        """Exibe o cabeçalho da aplicação com logo e versão."""
        self.console.print(f"[bold green]{LOGO}[/bold green]")
        self.console.print(f"[bold cyan]{APP_NAME} v{APP_VERSION}[/bold cyan]")
        self.console.print("[italic]🛡️ Iniciando Análise de Dependências...[/italic]\n")
    
    def display_quick_start_help(self) -> None:
        """Exibe as opções de início rápido."""
        self.console.print("\n[bold green]🚀 INÍCIO RÁPIDO:[/bold green]")
        self.console.print("  bscan scan                    # Analisa o diretório atual")
        self.console.print("  bscan scan --skip-vulns       # Gera relatório sem consultar OSV/NVD/Sonatype")
        self.console.print("  bscan scan --include-transitive  # Inclui dependências transitivas")
        self.console.print("  bscan sonatype-guide-key --prompt # Configura token Sonatype Guide")
        self.console.print("  bscan scan --help             # Ajuda detalhada do comando scan")
        self.console.print("  bscan --version               # Versão do BasiliskScan")
        self.console.print("\n[dim]💡 Dica: defina NVD_API_KEY e/ou credenciais Sonatype para enriquecer as consultas[/dim]")
        self.console.print("\n[dim]💡 Para mais informações, use: bscan scan --help[/dim]")
    
    def display_error(self, message: str, suggestion: str = None) -> None:
        """
        Exibe uma mensagem de erro formatada.
        
        Args:
            message: Mensagem de erro principal
            suggestion: Sugestão opcional para resolver o problema
        """
        self.console.print(f"[red]❌ {message}[/red]")
        if suggestion:
            self.console.print(f"[dim]💡 {suggestion}[/dim]")
    
    def display_warning(self, message: str) -> None:
        """
        Exibe uma mensagem de aviso formatada.
        
        Args:
            message: Mensagem de aviso
        """
        self.console.print(f"[yellow]⚠️  {message}[/yellow]")
    
    def display_success(self, message: str) -> None:
        """
        Exibe uma mensagem de sucesso formatada.
        
        Args:
            message: Mensagem de sucesso
        """
        self.console.print(f"[green]✅ {message}[/green]")
    
    def display_info(self, message: str, emoji: str = "ℹ️") -> None:
        """
        Exibe uma mensagem informativa formatada.
        
        Args:
            message: Mensagem informativa
            emoji: Emoji a ser exibido junto da mensagem
        """
        self.console.print(f"[blue]{emoji} {message}[/blue]")


def validate_target_path(target_path, url=None):
    """
    Valida se o caminho alvo existe e é um diretório.
    
    Args:
        target_path: Caminho do diretório alvo
        url: URL original (se aplicável)
        
    Raises:
        click.ClickException: Se o path não for válido
    """
    if not target_path.exists():
        raise click.ClickException(
            f"❌ Erro: O diretório alvo '{target_path}' não existe ou não é acessível.\n"
            f"   Verifique o caminho e as permissões, e tente novamente."
        )

    if not target_path.is_dir():
        raise click.ClickException(
            f"❌ Erro: O alvo '{target_path}' não é um diretório válido.\n"
            f"   Por favor, especifique um diretório de projeto."
        )


def handle_file_save_error(error: Exception, output_path: str):
    """
    Trata erros durante o salvamento de arquivos.
    
    Args:
        error: Exceção capturada
        output_path: Caminho do arquivo que falhou ao salvar
        
    Raises:
        click.ClickException: Com mensagem de erro formatada
    """
    raise click.ClickException(
        f"❌ Erro ao salvar o relatório em '{output_path}': {str(error)}\n"
        f"   Verifique as permissões de escrita no diretório de destino."
    )