"""Comandos auxiliares para configuração e onboarding da Sonatype Guide."""

from __future__ import annotations

import click

from ..controllers.credentials_controller import CredentialsController
from ..views.terminal_view import BasiliskCommand


@click.command(
    cls=BasiliskCommand,
    name="sonatype-guide-key",
    context_settings={"help_option_names": ["-h", "--help"]},
    help="Configura, exibe ou remove credenciais da Sonatype Guide (username + token).",
)
@click.option(
    "--username",
    type=str,
    default=None,
    metavar="<username>",
    help="Define o username da Sonatype Guide (usar junto com --token).",
)
@click.option(
    "--token",
    type=str,
    default=None,
    metavar="<token>",
    help="Define o token da Sonatype Guide (usar junto com --username).",
)
@click.option(
    "--prompt",
    is_flag=True,
    default=False,
    help="Solicita username e token de forma interativa (token oculto).",
)
@click.option(
    "--show",
    is_flag=True,
    default=False,
    help="Mostra status das credenciais configuradas (valores mascarados + origem).",
)
@click.option(
    "--clear",
    is_flag=True,
    default=False,
    help="Remove credenciais persistidas da Sonatype Guide.",
)
@click.option(
    "--save-to-keyring",
    is_flag=True,
    default=False,
    help="Também salva as credenciais no keyring do sistema quando disponível.",
)
def sonatype_guide_key_command(
    username: str | None,
    token: str | None,
    prompt: bool,
    show: bool,
    clear: bool,
    save_to_keyring: bool,
):
    """Gerencia credenciais da Sonatype Guide no BasiliskScan."""
    controller = CredentialsController()
    controller.handle_sonatype_guide_key(username, token, prompt, show, clear, save_to_keyring)


@click.command(
    cls=BasiliskCommand,
    name="sonatype-guide-register-guide",
    context_settings={"help_option_names": ["-h", "--help"]},
    help="Mostra um passo a passo para criar conta na Sonatype Guide e gerar token.",
)
@click.option(
    "--open",
    "open_browser",
    is_flag=True,
    default=False,
    help="Abre automaticamente a página da API da Sonatype Guide.",
)
def sonatype_guide_register_guide_command(open_browser: bool):
    """Exibe instruções para cadastro e geração de token na Sonatype Guide."""
    controller = CredentialsController()
    controller.handle_sonatype_guide_register_guide(open_browser)
