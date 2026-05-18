"""Comandos auxiliares para configuração e onboarding do NVD."""

from __future__ import annotations

import click

from ..controllers.credentials_controller import CredentialsController
from ..views.terminal_view import BasiliskCommand


@click.command(
    cls=BasiliskCommand,
    name="nvd-key",
    context_settings={"help_option_names": ["-h", "--help"]},
    help="Configura, exibe ou remove a API key do NVD usada pelo BasiliskScan.",
)
@click.option(
    "--set",
    "api_key",
    type=str,
    default=None,
    metavar="<api-key>",
    help="Define a API key do NVD.",
)
@click.option(
    "--prompt",
    is_flag=True,
    default=False,
    help="Solicita a API key de forma interativa (entrada oculta).",
)
@click.option(
    "--show",
    is_flag=True,
    default=False,
    help="Mostra status da API key configurada (valor mascarado + origem).",
)
@click.option(
    "--clear",
    is_flag=True,
    default=False,
    help="Remove a API key persistida para o NVD.",
)
@click.option(
    "--save-to-keyring",
    is_flag=True,
    default=False,
    help="Também salva a credencial no keyring do sistema quando disponível.",
)
def nvd_key_command(
    api_key: str | None,
    prompt: bool,
    show: bool,
    clear: bool,
    save_to_keyring: bool,
):
    """Gerencia a API key do NVD no BasiliskScan."""
    controller = CredentialsController()
    controller.handle_nvd_key(api_key, prompt, show, clear, save_to_keyring)


@click.command(
    cls=BasiliskCommand,
    name="nvd-register-guide",
    context_settings={"help_option_names": ["-h", "--help"]},
    help="Mostra um passo a passo para criar conta no NVD e solicitar API key.",
)
@click.option(
    "--open",
    "open_browser",
    is_flag=True,
    default=False,
    help="Abre automaticamente a página oficial de solicitação da API key do NVD.",
)
def nvd_register_guide_command(open_browser: bool):
    """Exibe instruções para cadastro e requisição de API key no NVD."""
    controller = CredentialsController()
    controller.handle_nvd_register_guide(open_browser)
