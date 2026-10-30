"""Comandos del asistente IA."""

import os

import click

from bazzingakit.ai import OutputAnalyzer, get_provider
from bazzingakit.config import load_config, save_config
from bazzingakit.core import SessionManager
from bazzingakit.utils import console


@click.group()
def ai() -> None:
    """Asistente IA: análisis de outputs, sugerencias."""


@ai.command("setup")
@click.option("--model", default="claude-opus-4-7", help="Modelo de Anthropic")
@click.option(
    "--env-var",
    default="ANTHROPIC_API_KEY",
    help="Variable de entorno que contiene la API key",
)
@click.option("--enable/--disable", default=True)
def setup_cmd(model: str, env_var: str, enable: bool) -> None:
    """Configura el asistente IA."""
    cfg = load_config()
    cfg.ai.enabled = enable
    cfg.ai.provider = "anthropic"
    cfg.ai.model = model
    cfg.ai.api_key_env = env_var
    save_config(cfg)

    console.print(f"[green]✓[/green] IA {'habilitada' if enable else 'deshabilitada'}")
    console.print(f"  Provider: [cyan]anthropic[/cyan]")
    console.print(f"  Modelo: [cyan]{model}[/cyan]")
    console.print(f"  API key desde: [cyan]${env_var}[/cyan]")

    if enable and not os.environ.get(env_var):
        console.print(
            f"[yellow]⚠[/yellow] La variable [cyan]{env_var}[/cyan] no está definida. "
            f"Exporta tu API key antes de usar los comandos de IA."
        )


@ai.command("test")
def test_cmd() -> None:
    """Prueba la conexión con el provider de IA."""
    cfg = load_config()

    if not cfg.ai.enabled:
        console.print("[red]✗[/red] IA no habilitada. Ejecuta: [cyan]bazzingakit ai setup[/cyan]")
        raise click.Abort()

    try:
        provider = get_provider(cfg.ai)
    except ValueError as e:
        console.print(f"[red]✗[/red] {e}")
        raise click.Abort()

    console.print(f"Probando [cyan]{provider.name}[/cyan]...")
    if provider.test_connection():
        console.print("[green]✓[/green] Conexión exitosa")
    else:
        console.print("[red]✗[/red] Conexión falló (revisa API key y modelo)")
        raise click.Abort()


@ai.command("analyze")
@click.argument("session_ref")
@click.option("--no-redact", is_flag=True, help="No redactar datos sensibles")
def analyze_cmd(session_ref: str, no_redact: bool) -> None:
    """Analiza el output de una sesión con IA."""
    cfg = load_config()

    if not cfg.ai.enabled:
        console.print("[red]✗[/red] IA no habilitada. Ejecuta: [cyan]bazzingakit ai setup[/cyan]")
        raise click.Abort()

    try:
        provider = get_provider(cfg.ai)
    except ValueError as e:
        console.print(f"[red]✗[/red] {e}")
        raise click.Abort()

    manager = SessionManager(cfg.paths.sessions_dir)
    try:
        session = manager.resolve(session_ref)
    except (FileNotFoundError, ValueError) as e:
        console.print(f"[red]✗[/red] {e}")
        raise click.Abort()

    redact = cfg.ai.redact_sensitive and not no_redact
    analyzer = OutputAnalyzer(provider, redact=redact)

    console.print(f"Analizando sesión [cyan]{session.id}[/cyan]...")
    if redact:
        console.print("[dim]Redacción de datos sensibles: ON[/dim]")

    try:
        result = analyzer.analyze_session(session)
    except FileNotFoundError as e:
        console.print(f"[red]✗[/red] {e}")
        raise click.Abort()
    except Exception as e:
        console.print(f"[red]✗[/red] Error en análisis: {e}")
        raise click.Abort()

    console.print()
    console.print(result.content)
    console.print()
    console.print(
        f"[dim]Tokens: {result.tokens_in} in / {result.tokens_out} out · "
        f"Modelo: {result.model}[/dim]"
    )
    console.print(f"[green]✓[/green] Análisis guardado en la sesión.")
