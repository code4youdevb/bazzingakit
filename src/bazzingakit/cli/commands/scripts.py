"""Comandos de gestión del registry de scripts."""

import click
from rich.table import Table

from bazzingakit.core import default_registry
from bazzingakit.utils import console


@click.group()
def scripts() -> None:
    """Gestión de scripts Frida registrados."""


@scripts.command("list")
@click.option("--platform", help="Filtrar por plataforma (android/ios)")
@click.option("--category", help="Filtrar por categoría")
def list_cmd(platform: str, category: str) -> None:
    """Lista scripts registrados."""
    registry = default_registry()
    results = registry.find(platform=platform, category=category)

    if not results:
        console.print("[yellow]No hay scripts registrados con esos filtros.[/yellow]")
        return

    table = Table(title=f"Scripts ({len(results)})")
    table.add_column("Nombre", style="cyan")
    table.add_column("Platform", style="magenta")
    table.add_column("Categoría")
    table.add_column("Técnica")
    table.add_column("Path", style="dim")

    for s in sorted(results, key=lambda x: (x.platform, x.category, x.name)):
        try:
            rel = s.path.relative_to(s.path.parents[3])
        except (ValueError, IndexError):
            rel = s.path
        table.add_row(
            s.name,
            s.platform,
            s.category,
            s.technique or "-",
            str(rel),
        )

    console.print(table)


@scripts.command("show")
@click.argument("name")
def show_cmd(name: str) -> None:
    """Muestra metadata y preview de un script."""
    registry = default_registry()
    matches = registry.find_by_name(name)

    if not matches:
        console.print(f"[red]✗[/red] Script '{name}' no encontrado.")
        raise click.Abort()

    for m in matches:
        console.print(f"[bold cyan]{m.name}[/bold cyan]  [dim]({m.id})[/dim]")
        console.print(f"  Platform:    {m.platform}")
        console.print(f"  Category:    {m.category}")
        console.print(f"  Technique:   {m.technique or '-'}")
        console.print(f"  Author:      {m.author or '-'}")
        console.print(f"  Version:     {m.version or '-'}")
        console.print(f"  Description: {m.description or '-'}")
        if m.targets:
            console.print(f"  Targets:     {', '.join(m.targets)}")
        console.print(f"  Path:        {m.path}")
        console.print()
