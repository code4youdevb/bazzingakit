"""Comandos para gestionar sesiones de análisis."""

import json

import click
from rich.table import Table

from bazzingakit.config import load_config
from bazzingakit.core import SessionManager
from bazzingakit.utils import console


@click.group()
def session() -> None:
    """Gestión de sesiones de análisis."""


@session.command("list")
@click.option("--limit", default=20, help="Máximo de sesiones a mostrar")
def list_cmd(limit: int) -> None:
    """Lista sesiones recientes."""
    cfg = load_config()
    manager = SessionManager(cfg.paths.sessions_dir)

    sessions = manager.list_sessions()[:limit]

    if not sessions:
        console.print("[yellow]No hay sesiones todavía.[/yellow]")
        return

    table = Table(title=f"Sesiones ({len(sessions)})")
    table.add_column("ID", style="cyan")
    table.add_column("Package", style="magenta")
    table.add_column("Plataforma")
    table.add_column("Scripts", justify="right")

    for session_id in sessions:
        try:
            s = manager.load(session_id)
            table.add_row(
                session_id,
                s.metadata.package_name,
                s.metadata.platform,
                str(len(s.metadata.scripts_loaded)),
            )
        except Exception:
            table.add_row(session_id, "[red]error[/red]", "", "")

    console.print(table)


@session.command("show")
@click.argument("session_ref")
def show_cmd(session_ref: str) -> None:
    """Muestra detalles de una sesión."""
    cfg = load_config()
    manager = SessionManager(cfg.paths.sessions_dir)

    try:
        s = manager.resolve(session_ref)
    except (FileNotFoundError, ValueError) as e:
        console.print(f"[red]✗[/red] {e}")
        raise click.Abort()

    console.print(f"[bold cyan]{s.id}[/bold cyan]\n")
    console.print(f"Package:     {s.metadata.package_name}")
    console.print(f"Plataforma:  {s.metadata.platform}")
    console.print(f"Perfil:      {s.metadata.profile_name or '(ninguno)'}")
    console.print(f"Playbook:    {s.metadata.playbook_name or '(ninguno)'}")
    console.print(f"Inicio:      {s.metadata.started_at}")
    console.print(f"Fin:         {s.metadata.ended_at or '(en curso)'}")
    console.print(f"Directorio:  {s.session_dir}")

    if s.metadata.scripts_loaded:
        console.print(f"\n[bold]Scripts cargados:[/bold]")
        for script in s.metadata.scripts_loaded:
            console.print(f"  • {script}")

    if s.metadata.rasp_detected:
        console.print(f"\n[bold]RASP detectado:[/bold]")
        console.print(json.dumps(s.metadata.rasp_detected, indent=2))

    if s.metadata.findings:
        console.print(f"\n[bold]Hallazgos:[/bold] {len(s.metadata.findings)}")

    # Lista archivos de la sesión
    console.print(f"\n[bold]Artefactos:[/bold]")
    for f in sorted(s.session_dir.rglob("*")):
        if f.is_file():
            rel = f.relative_to(s.session_dir)
            size = f.stat().st_size
            console.print(f"  [dim]{size:>8}b[/dim]  {rel}")


@session.command("path")
@click.argument("session_ref")
def path_cmd(session_ref: str) -> None:
    """Imprime el path absoluto de una sesión."""
    cfg = load_config()
    manager = SessionManager(cfg.paths.sessions_dir)

    try:
        s = manager.resolve(session_ref)
    except (FileNotFoundError, ValueError) as e:
        console.print(f"[red]✗[/red] {e}")
        raise click.Abort()

    console.print(str(s.session_dir))
