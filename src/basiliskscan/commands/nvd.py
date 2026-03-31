"""Comandos auxiliares para configuração e onboarding do NVD."""

from __future__ import annotations

import os
import webbrowser
from pathlib import Path

import click

from ..auth.credential_manager import CredentialManager
from ..env import find_dotenv
from ..ui import BasiliskCommand, UIHelper


def _mask_api_key(value: str) -> str:
    cleaned = str(value or "").strip()
    if not cleaned:
        return "(vazia)"
    if len(cleaned) <= 8:
        return "*" * len(cleaned)
    return f"{cleaned[:4]}{'*' * (len(cleaned) - 8)}{cleaned[-4:]}"


def _remove_nvd_key_from_dotenv(search_from: Path | None = None) -> tuple[bool, Path | None]:
    """Remove linha NVD_API_KEY do `.env` mais próximo, se existir."""
    env_path = find_dotenv(search_from)
    if not env_path:
        return (False, None)

    original_lines = env_path.read_text(encoding="utf-8").splitlines(keepends=True)
    filtered_lines = []
    removed = False

    for line in original_lines:
        stripped = line.strip()
        if stripped.startswith("NVD_API_KEY=") or stripped.startswith("export NVD_API_KEY="):
            removed = True
            continue
        filtered_lines.append(line)

    if removed:
        env_path.write_text("".join(filtered_lines), encoding="utf-8")

    return (removed, env_path)


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
    ui = UIHelper()
    manager = CredentialManager()

    actions_selected = sum([bool(api_key), bool(prompt), bool(show), bool(clear)])
    if actions_selected == 0:
        ui.display_info("Nenhuma ação selecionada.")
        ui.console.print("Use [bold]bscan nvd-key --help[/bold] para ver as opções.")
        return

    if clear and (api_key or prompt or show):
        raise click.ClickException("Use --clear sozinho, sem combinar com --set/--prompt/--show.")

    if show and (api_key or prompt):
        raise click.ClickException("Use --show sozinho ou separado de --set/--prompt.")

    if clear:
        had_env_value = bool(os.getenv("NVD_API_KEY"))
        manager.clear_stored_credentials("nvd")
        os.environ.pop("NVD_API_KEY", None)
        removed_from_dotenv, dotenv_path = _remove_nvd_key_from_dotenv(Path.cwd())

        ui.display_success("API key do NVD removida com sucesso.")

        if had_env_value:
            ui.console.print("   • Variável NVD_API_KEY removida da sessão atual.")

        if removed_from_dotenv and dotenv_path:
            ui.console.print(f"   • Chave removida de [italic]{dotenv_path}[/italic].")
        elif dotenv_path:
            ui.console.print(
                f"   • Nenhuma entrada NVD_API_KEY encontrada em [italic]{dotenv_path}[/italic]."
            )

        ui.console.print("   • Credenciais em variáveis de ambiente do sistema (fora da sessão) devem ser removidas manualmente.")
        return

    if show:
        record = manager.discover_credentials("nvd")
        if not record:
            ui.display_warning("Nenhuma API key do NVD configurada.")
            ui.console.print("Use [bold]bscan nvd-register-guide[/bold] para obter uma chave.")
            ui.console.print("Depois configure com [bold]bscan nvd-key --prompt[/bold].")
            return

        masked_value = _mask_api_key(record.data.get("api_key", ""))
        ui.display_success("API key do NVD encontrada.")
        ui.console.print(f"   • Valor: [bold]{masked_value}[/bold]")
        ui.console.print(f"   • Origem: [italic]{record.source.value}[/italic]")
        ui.console.print("   • Dica: variáveis de ambiente têm prioridade sobre arquivo/keyring.")
        return

    resolved_api_key = api_key
    if prompt:
        resolved_api_key = click.prompt("Informe a API key do NVD", hide_input=True, type=str).strip()

    if not resolved_api_key:
        raise click.ClickException("Informe a chave com --set <api-key> ou use --prompt.")

    manager.set_credentials(
        "nvd",
        {"api_key": resolved_api_key},
        save_to_keyring=save_to_keyring,
    )
    ui.display_success("API key do NVD configurada com sucesso.")
    ui.console.print("Use [bold]bscan nvd-key --show[/bold] para validar a configuração.")


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
    ui = UIHelper()
    request_url = "https://nvd.nist.gov/developers/request-an-api-key"
    start_url = "https://nvd.nist.gov/developers"

    ui.console.print("[bold green]🧭 Guia rápido de cadastro no NVD[/bold green]")
    ui.console.print("\n1) Acesse o portal de desenvolvedores do NVD:")
    ui.console.print(f"   [underline]{start_url}[/underline]")
    ui.console.print("2) Abra a página de solicitação de API key:")
    ui.console.print(f"   [underline]{request_url}[/underline]")
    ui.console.print("3) Preencha o formulário com seu e-mail e envie a solicitação.")
    ui.console.print("4) Aguarde o e-mail de confirmação do NVD com a API key.")
    ui.console.print("5) Configure a chave no BasiliskScan:")
    ui.console.print("   [bold]bscan nvd-key --prompt[/bold]")
    ui.console.print("6) Verifique se ficou tudo certo:")
    ui.console.print("   [bold]bscan nvd-key --show[/bold]")

    ui.console.print("\n[dim]Dica: também é possível usar a variável NVD_API_KEY no .env.[/dim]")

    if open_browser:
        try:
            opened = webbrowser.open(request_url)
            if opened:
                ui.display_success("Página de solicitação da API key do NVD aberta no navegador.")
            else:
                ui.display_warning("Não foi possível abrir o navegador automaticamente.")
        except Exception as error:
            ui.display_warning(f"Falha ao abrir navegador: {error}")
