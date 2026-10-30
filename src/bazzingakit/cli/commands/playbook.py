"""Comandos para gestión de playbooks."""

import click
from rich.table import Table

from bazzingakit.core import list_builtin_playbooks, load_playbook
from bazzingakit.utils import console


@click.group()
def playbook() -> None:
    """Gestión de playbooks."""


@playbook.command("list")
def list_cmd() -> None:
    """Lista playbooks disponibles."""
    paths = list_builtin_playbooks()

    if not paths:
        console.print("[yellow]No hay playbooks disponibles.[/yellow]")
        return

    table = Table(title=f"Playbooks ({len(paths)})")
    table.add_column("Nombre", style="cyan")
    table.add_column("Platform", style="magenta")
    table.add_column("Scripts", justify="right")
    table.add_column("Spawn", justify="center")
    table.add_column("Descripción", style="dim")

    for path in paths:
        try:
            pb = load_playbook(path)
            table.add_row(
                pb.name,
                pb.platform,
                str(len(pb.scripts)),
                "✓" if pb.spawn_required else "",
                pb.description or "-",
            )
        except Exception as e:
            table.add_row(path.stem, "?", "?", "", f"[red]error: {e}[/red]")

    console.print(table)


@playbook.command("show")
@click.argument("name")
def show_cmd(name: str) -> None:
    """Muestra detalles de un playbook."""
    from bazzingakit.core import find_builtin_playbook

    path = find_builtin_playbook(name)
    if not path:
        console.print(f"[red]✗[/red] Playbook '{name}' no encontrado.")
        raise click.Abort()

    pb = load_playbook(path)

    console.print(f"[bold cyan]{pb.name}[/bold cyan]")
    console.print(f"Platform:       {pb.platform}")
    console.print(f"Spawn required: {pb.spawn_required}")
    console.print(f"Description:    {pb.description or '-'}")
    if pb.warning:
        console.print(f"\n[yellow]⚠ Warning:[/yellow]\n{pb.warning}")

    console.print(f"\n[bold]Scripts ({len(pb.scripts)}):[/bold]")
    for s in sorted(pb.scripts, key=lambda x: x.order):
        critical = " [red](critical)[/red]" if s.critical else ""
        console.print(f"  {s.order}. [cyan]{s.name}[/cyan]{critical}")
        console.print(f"     [dim]{s.path}[/dim]")
