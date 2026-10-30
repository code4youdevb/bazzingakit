"""Comandos para interactuar con el dispositivo activo."""

import click
from rich.table import Table

from bazzingakit.config import load_config
from bazzingakit.core import get_device_manager
from bazzingakit.utils import console


@click.group()
def device() -> None:
    """Interacción con el dispositivo del perfil activo."""


def _get_manager():
    cfg = load_config()
    profile = cfg.get_active_profile()
    if not profile:
        console.print("[red]✗[/red] No hay perfil activo. Usa [cyan]bazzingakit config use <n>[/cyan]")
        raise click.Abort()
    return get_device_manager(profile), profile


@device.command("list")
def list_cmd() -> None:
    """Lista dispositivos detectados por el perfil activo."""
    manager, profile = _get_manager()

    if not manager.is_available():
        console.print(
            f"[red]✗[/red] {manager.platform} tools no disponibles. "
            f"Revisa el perfil '{profile.name}'."
        )
        raise click.Abort()

    devices = manager.list_devices()
    if not devices:
        console.print("[yellow]No se detectaron dispositivos.[/yellow]")
        return

    table = Table(title=f"Dispositivos ({profile.platform.value})")
    table.add_column("Identifier", style="cyan")
    table.add_column("Modelo")
    table.add_column("Estado")

    for d in devices:
        status = "[green]online[/green]" if d.is_online else "[red]offline[/red]"
        table.add_row(d.identifier, d.model or "-", status)

    console.print(table)


@device.command("info")
def info_cmd() -> None:
    """Muestra información detallada del dispositivo activo."""
    manager, profile = _get_manager()

    if not manager.is_connected():
        console.print("[red]✗[/red] Dispositivo no conectado")
        raise click.Abort()

    info = manager.get_device_info()
    if not info:
        console.print("[red]✗[/red] No se pudo obtener información del dispositivo")
        raise click.Abort()

    console.print(f"[bold]Plataforma:[/bold]    {info.platform}")
    console.print(f"[bold]Identifier:[/bold]    {info.identifier}")
    console.print(f"[bold]Modelo:[/bold]        {info.model or '-'}")
    console.print(f"[bold]OS version:[/bold]    {info.os_version or '-'}")
    console.print(f"[bold]Arquitectura:[/bold]  {info.arch or '-'}")
    console.print(
        f"[bold]Root/JB:[/bold]       "
        f"{'[green]sí[/green]' if info.is_rooted else '[yellow]no detectado[/yellow]'}"
    )


@device.command("shell")
@click.argument("command", nargs=-1, required=True)
def shell_cmd(command: tuple[str, ...]) -> None:
    """Ejecuta un comando shell en el dispositivo."""
    manager, _ = _get_manager()

    if not manager.is_connected():
        console.print("[red]✗[/red] Dispositivo no conectado")
        raise click.Abort()

    full_command = " ".join(command)
    result = manager.shell(full_command, timeout=30)

    if result.stdout:
        console.print(result.stdout, end="")
    if result.stderr:
        console.print(f"[red]{result.stderr}[/red]", end="")

    if not result.ok:
        raise click.Abort()


@device.command("packages")
@click.option("--all", "show_all", is_flag=True, help="Incluir apps del sistema")
def packages_cmd(show_all: bool) -> None:
    """Lista paquetes instalados (solo Android)."""
    manager, profile = _get_manager()

    if profile.platform.value != "android":
        console.print("[yellow]Este comando es solo para Android. Usa 'device apps' para iOS.[/yellow]")
        raise click.Abort()

    if not manager.is_connected():
        console.print("[red]✗[/red] Dispositivo no conectado")
        raise click.Abort()

    packages = manager.list_packages(filter_user=not show_all)
    console.print(f"[bold]{len(packages)} paquetes[/bold]")
    for pkg in packages:
        console.print(f"  {pkg}")
