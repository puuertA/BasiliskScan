# src/basiliskscan/ui.py
"""Módulo para customizações da interface de usuário e classes Click personalizadas."""

import click
import re
import os
import sys
from rich.console import Console

from .help_text import LOGO
from .config import APP_NAME, APP_VERSION, APP_DESCRIPTION


def _configure_windows_stdio_utf8() -> None:
    if os.name != "nt":
        return

    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        if stream is None or not hasattr(stream, "reconfigure"):
            continue

        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            continue


_configure_windows_stdio_utf8()


_MARKUP_TAG_RE = re.compile(r"\[[^\]]+\]")


def _strip_rich_markup(text: str) -> str:
    return _MARKUP_TAG_RE.sub("", text)


def _sanitize_for_legacy_console(text: str) -> str:
    return _strip_rich_markup(text).encode("cp1252", errors="replace").decode("cp1252")


def _safe_console_print(console: Console, message: str) -> None:
    try:
        console.print(message)
    except UnicodeEncodeError:
        click.echo(_sanitize_for_legacy_console(message))


class BasiliskCommand(click.Command):
    """Comando Click customizado com logo e branding do BasiliskScan."""
    
    def __init__(self, *args, **kwargs):
        self.console = Console()
        super().__init__(*args, **kwargs)
    
    def get_help(self, ctx):
        """Exibe help personalizado com logo e informações da ferramenta."""
        _safe_console_print(self.console, f"[bold green]{LOGO}[/bold green]")
        _safe_console_print(self.console, f"[bold cyan]{APP_NAME} v{APP_VERSION}[/bold cyan]")
        _safe_console_print(self.console, f"[italic]{APP_DESCRIPTION}[/italic]")
        _safe_console_print(self.console, "[dim]Identifica dependências vulneráveis e desatualizadas em projetos de software[/dim]\n")
        return super().get_help(ctx)


class BasiliskGroup(click.Group):
    """Grupo Click customizado com logo e branding do BasiliskScan."""
    
    def __init__(self, *args, **kwargs):
        self.console = Console()
        super().__init__(*args, **kwargs)
    
    def get_help(self, ctx):
        """Exibe help personalizado com logo e informações da ferramenta."""
        _safe_console_print(self.console, f"[bold green]{LOGO}[/bold green]")
        _safe_console_print(self.console, f"[bold cyan]{APP_NAME} v{APP_VERSION}[/bold cyan]")
        _safe_console_print(self.console, f"[italic]{APP_DESCRIPTION}[/italic]")
        _safe_console_print(self.console, "[dim]Identifica dependências vulneráveis e desatualizadas em projetos de software[/dim]\n")
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
        _safe_console_print(self.console, f"[bold green]{LOGO}[/bold green]")
        _safe_console_print(self.console, f"[bold cyan]{APP_NAME} v{APP_VERSION}[/bold cyan]")
        _safe_console_print(self.console, "[italic]🛡️ Iniciando Análise de Dependências...[/italic]\n")
    
    def display_quick_start_help(self) -> None:
        """Exibe as opções de início rápido."""
        _safe_console_print(self.console, "\n[bold green]🚀 INÍCIO RÁPIDO:[/bold green]")
        _safe_console_print(self.console, "  bscan scan                    # Analisa o diretório atual")
        _safe_console_print(self.console, "  bscan scan --skip-vulns       # Gera relatório sem consultar OSV/NVD/Sonatype")
        _safe_console_print(self.console, "  bscan scan --offline          # Usa apenas base local de vulnerabilidades")
        _safe_console_print(self.console, "  bscan scan --include-transitive  # Inclui dependências transitivas")
        _safe_console_print(self.console, "  bscan offline-db --sync --force  # Força atualização do banco offline")
        _safe_console_print(self.console, "  bscan sonatype-guide-key --prompt # Configura token Sonatype Guide")
        _safe_console_print(self.console, "  bscan scan --help             # Ajuda detalhada do comando scan")
        _safe_console_print(self.console, "  bscan --version               # Versão do BasiliskScan")
        _safe_console_print(self.console, "\n[dim]💡 Dica: defina NVD_API_KEY e/ou credenciais Sonatype para enriquecer as consultas[/dim]")
        _safe_console_print(self.console, "\n[dim]💡 Para mais informações, use: bscan scan --help[/dim]")
    
    def display_error(self, message: str, suggestion: str = None) -> None:
        """
        Exibe uma mensagem de erro formatada.
        
        Args:
            message: Mensagem de erro principal
            suggestion: Sugestão opcional para resolver o problema
        """
        _safe_console_print(self.console, f"[red]❌ {message}[/red]")
        if suggestion:
            _safe_console_print(self.console, f"[dim]💡 {suggestion}[/dim]")
    
    def display_warning(self, message: str) -> None:
        """
        Exibe uma mensagem de aviso formatada.
        
        Args:
            message: Mensagem de aviso
        """
        _safe_console_print(self.console, f"[yellow]⚠️  {message}[/yellow]")
    
    def display_success(self, message: str) -> None:
        """
        Exibe uma mensagem de sucesso formatada.
        
        Args:
            message: Mensagem de sucesso
        """
        _safe_console_print(self.console, f"[green]✅ {message}[/green]")
    
    def display_info(self, message: str, emoji: str = "ℹ️") -> None:
        """
        Exibe uma mensagem informativa formatada.
        
        Args:
            message: Mensagem informativa
            emoji: Emoji a ser exibido junto da mensagem
        """
        _safe_console_print(self.console, f"[blue]{emoji} {message}[/blue]")


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