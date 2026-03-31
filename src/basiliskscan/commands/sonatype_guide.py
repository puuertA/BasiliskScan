"""Comandos auxiliares para configuração e onboarding da Sonatype Guide."""

from __future__ import annotations

import os
import webbrowser
from pathlib import Path

import click

from ..auth.credential_manager import CredentialManager
from ..env import find_dotenv
from ..ui import BasiliskCommand, UIHelper


def _mask_secret(value: str) -> str:
    cleaned = str(value or "").strip()
    if not cleaned:
        return "(vazio)"
    if len(cleaned) <= 8:
        return "*" * len(cleaned)
    return f"{cleaned[:4]}{'*' * (len(cleaned) - 8)}{cleaned[-4:]}"


def _remove_sonatype_guide_keys_from_dotenv(search_from: Path | None = None) -> tuple[list[str], Path | None]:
    """Remove entradas de credenciais da Sonatype Guide do `.env` mais próximo, se existir."""
    env_path = find_dotenv(search_from)
    if not env_path:
        return ([], None)

    keys = {
        "OSS_INDEX_USERNAME",
        "OSS_INDEX_TOKEN",
        "OSSINDEX_USERNAME",
        "OSSINDEX_TOKEN",
    }

    original_lines = env_path.read_text(encoding="utf-8").splitlines(keepends=True)
    filtered_lines = []
    removed_keys: list[str] = []

    for line in original_lines:
        stripped = line.strip()
        normalized = stripped[7:].strip() if stripped.startswith("export ") else stripped

        matched_key = None
        for key in keys:
            if normalized.startswith(f"{key}="):
                matched_key = key
                break

        if matched_key:
            if matched_key not in removed_keys:
                removed_keys.append(matched_key)
            continue

        filtered_lines.append(line)

    if removed_keys:
        env_path.write_text("".join(filtered_lines), encoding="utf-8")

    return (removed_keys, env_path)


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
    ui = UIHelper()
    manager = CredentialManager()

    set_mode = bool(username or token)
    actions_selected = sum([bool(set_mode), bool(prompt), bool(show), bool(clear)])

    if actions_selected == 0:
        ui.display_info("Nenhuma ação selecionada.")
        ui.console.print("Use [bold]bscan sonatype-guide-key --help[/bold] para ver as opções.")
        return

    if clear and (set_mode or prompt or show):
        raise click.ClickException("Use --clear sozinho, sem combinar com --username/--token/--prompt/--show.")

    if show and (set_mode or prompt):
        raise click.ClickException("Use --show sozinho, sem combinar com --username/--token/--prompt.")

    if clear:
        env_names = ["OSS_INDEX_USERNAME", "OSS_INDEX_TOKEN", "OSSINDEX_USERNAME", "OSSINDEX_TOKEN"]
        had_session_env = [name for name in env_names if os.getenv(name)]

        manager.clear_stored_credentials("oss_index")

        for env_name in env_names:
            os.environ.pop(env_name, None)

        removed_keys, dotenv_path = _remove_sonatype_guide_keys_from_dotenv(Path.cwd())

        ui.display_success("Credenciais da Sonatype Guide removidas com sucesso.")

        if had_session_env:
            ui.console.print(
                "   • Variáveis removidas da sessão atual: "
                + ", ".join(f"[italic]{name}[/italic]" for name in had_session_env)
            )

        if removed_keys and dotenv_path:
            ui.console.print(
                f"   • Chaves removidas de [italic]{dotenv_path}[/italic]: "
                + ", ".join(f"[italic]{name}[/italic]" for name in removed_keys)
            )
        elif dotenv_path:
            ui.console.print(
                f"   • Nenhuma chave da Sonatype Guide encontrada em [italic]{dotenv_path}[/italic]."
            )

        ui.console.print(
            "   • Credenciais em variáveis de ambiente do sistema (fora da sessão) devem ser removidas manualmente."
        )
        return

    if show:
        record = manager.discover_credentials("oss_index")
        if not record:
            ui.display_warning("Nenhuma credencial da Sonatype Guide configurada.")
            ui.console.print("Use [bold]bscan sonatype-guide-register-guide[/bold] para obter acesso.")
            ui.console.print("Depois configure com [bold]bscan sonatype-guide-key --prompt[/bold].")
            return

        masked_token = _mask_secret(record.data.get("token", ""))
        username_value = record.data.get("username", "")
        ui.display_success("Credenciais da Sonatype Guide encontradas.")
        ui.console.print(f"   • Username: [bold]{username_value}[/bold]")
        ui.console.print(f"   • Token: [bold]{masked_token}[/bold]")
        ui.console.print(f"   • Origem: [italic]{record.source.value}[/italic]")
        ui.console.print("   • Dica: variáveis de ambiente têm prioridade sobre arquivo/keyring.")
        return

    resolved_username = (username or "").strip()
    resolved_token = (token or "").strip()

    if prompt:
        resolved_username = click.prompt("Informe o username da Sonatype Guide", type=str).strip()
        resolved_token = click.prompt("Informe o token da Sonatype Guide", hide_input=True, type=str).strip()

    if not resolved_username or not resolved_token:
        raise click.ClickException(
            "Informe username e token com --username <user> --token <token> ou use --prompt."
        )

    manager.set_credentials(
        "oss_index",
        {"username": resolved_username, "token": resolved_token},
        save_to_keyring=save_to_keyring,
    )
    ui.display_success("Credenciais da Sonatype Guide configuradas com sucesso.")
    ui.console.print("Use [bold]bscan sonatype-guide-key --show[/bold] para validar a configuração.")


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
    ui = UIHelper()
    guide_url = "https://guide.sonatype.com"
    api_guide_url = "https://guide.sonatype.com/api"
    profile_url = "https://guide.sonatype.com/settings/profile"
    token_management_url = "https://guide.sonatype.com/settings/tokens"
    docs_url = "https://ossindex.sonatype.org/doc"

    ui.console.print("[bold green]🧭 Guia rápido Sonatype Guide[/bold green]")
    ui.console.print("\n1) Acesse o Sonatype Guide:")
    ui.console.print(f"   [underline]{guide_url}[/underline]")
    ui.console.print("2) Crie sua conta (Sign up) ou faça login.")
    ui.console.print("3) Confira seu username no perfil:")
    ui.console.print(f"   [underline]{profile_url}[/underline]")
    ui.console.print("4) Acesse o gerenciamento de tokens:")
    ui.console.print(f"   [underline]{token_management_url}[/underline]")
    ui.console.print("5) Crie um Personal Access Token com expiração [bold]never[/bold].")
    ui.console.print("6) Configure credenciais no BasiliskScan:")
    ui.console.print("   [bold]bscan sonatype-guide-key --prompt[/bold]")
    ui.console.print("7) Verifique se ficou tudo certo:")
    ui.console.print("   [bold]bscan sonatype-guide-key --show[/bold]")
    ui.console.print("8) Referência da Guide API (token Bearer):")
    ui.console.print(f"   [underline]{api_guide_url}[/underline]")
    ui.console.print("9) Compatibilidade legado (Basic Auth):")
    ui.console.print(f"   [underline]{docs_url}[/underline]")

    ui.console.print(
        "\n[dim]Dica: se preferir, configure via .env usando as variáveis de ambiente compatíveis do provedor.[/dim]"
    )

    if open_browser:
        try:
            opened = webbrowser.open(api_guide_url)
            if opened:
                ui.display_success("Página da Sonatype Guide API aberta no navegador.")
            else:
                ui.display_warning("Não foi possível abrir o navegador automaticamente.")
        except Exception as error:
            ui.display_warning(f"Falha ao abrir navegador: {error}")
