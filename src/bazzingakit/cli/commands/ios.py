"""Comandos específicos de iOS: info del dispositivo, lista de apps."""

import click
from rich.table import Table

from bazzingakit.config import Platform, load_config
from bazzingakit.core import FRIDA_AVAILABLE, FridaManager, get_device_manager
from bazzingakit.utils import console


@click.group()
def ios() -> None:
    """Utilidades para iOS (jailbroken)."""


def _require_ios_profile():
    cfg = load_config()
    profile = cfg.get_active_profile()
    if not profile:
        console.print("[red]✗[/red] No hay perfil activo.")
        raise click.Abort()
    if profile.platform != Platform.IOS:
        console.print(
            f"[red]✗[/red] El perfil activo '{profile.name}' es {profile.platform.value}, no iOS.\n"
            "[dim]Cambia con: bazzingakit config use <perfil_ios>[/dim]"
        )
        raise click.Abort()
    return profile, get_device_manager(profile)


@ios.command("info")
def info_cmd() -> None:
    """Muestra estado del iPhone (modo USB o network según perfil)."""
    cfg = load_config()
    profile = cfg.get_active_profile()
    if not profile:
        console.print("[red]✗[/red] No hay perfil activo.")
        raise click.Abort()
    if profile.platform != Platform.IOS:
        console.print(
            f"[red]✗[/red] El perfil activo '{profile.name}' es {profile.platform.value}, no iOS.\n"
            "[dim]Cambia con: bazzingakit config use <perfil_ios>[/dim]"
        )
        raise click.Abort()

    # Detectar modo
    is_usb_mode = not profile.ssh_host
    console.print(f"[bold]Perfil:[/bold] {profile.name}")
    if is_usb_mode:
        console.print(f"  [bold]Modo:[/bold] [cyan]USB[/cyan] (sin ssh_host configurado)")
        console.print(f"  port:   {profile.frida_port}")
    else:
        console.print(f"  [bold]Modo:[/bold] [cyan]Network[/cyan]")
        console.print(f"  ssh:    {profile.ssh_user}@{profile.ssh_host}:{profile.ssh_port}")
        console.print(f"  port:   {profile.frida_port}")

    if not FRIDA_AVAILABLE:
        console.print("\n[red]✗[/red] frida no está instalado.")
        return

    # Modo USB: hablamos directamente con frida via USB device, no SSH
    if is_usb_mode:
        _info_usb_mode(profile)
        return

    # Modo network: usa SSH para info adicional
    _info_network_mode(profile)


def _info_usb_mode(profile) -> None:
    """Info via USB device de Frida (sin SSH)."""
    import frida

    console.print("\n[bold]frida (modo USB):[/bold]")
    console.print(f"  cliente:  {frida.__version__}")

    try:
        device = frida.get_usb_device(timeout=5)
    except Exception as e:
        console.print(f"  [red]✗[/red] No se encontró device USB: {e}")
        console.print(
            "\n[yellow]Tips:[/yellow]\n"
            "  - Conecta el iPhone por USB y confía en este equipo\n"
            "  - Instala libimobiledevice (Windows: imobiledevice-net; "
            "Linux: apt install libimobiledevice-utils; Mac: brew install libimobiledevice)\n"
            "  - Verifica con: [cyan]frida-ls-devices[/cyan]"
        )
        return

    console.print(f"  [green]✓[/green] device: [cyan]{device.name}[/cyan] (id: {device.id})")

    # Intentar enumerar procesos para confirmar que el server responde
    try:
        procs = device.enumerate_processes()
        console.print(f"  [green]✓[/green] frida-server responde ({len(procs)} procesos visibles)")
    except Exception as e:
        console.print(f"  [yellow]⚠[/yellow] device visible pero frida-server no responde: {e}")
        console.print(
            "  [dim]Esto suele significar que el daemon de frida en el iPhone no está activo. "
            "Reinicia el iPhone o reinstala Frida desde Sileo.[/dim]"
        )


def _info_network_mode(profile) -> None:
    """Info via SSH + network device de Frida."""
    device_manager = get_device_manager(profile)

    # SSH
    console.print("\n[bold]Conexión SSH:[/bold]")
    if device_manager.is_connected():
        console.print(f"  [green]✓[/green] Conecta a {profile.ssh_host}")
    else:
        console.print(
            f"  [red]✗[/red] No conecta. "
            f"[dim](IP cambió? OpenSSH instalado?)[/dim]"
        )
        console.print(
            "\n[yellow]Tip:[/yellow] verifica la IP del iPhone:\n"
            "  Settings → WiFi → toca tu red → IP Address"
        )
        return

    # Info del dispositivo
    info = device_manager.get_device_info()
    if info:
        console.print(f"\n[bold]Dispositivo:[/bold]")
        if info.model:
            console.print(f"  modelo:  {info.model}")
        if info.os_version:
            console.print(f"  iOS:     {info.os_version}")
        if info.arch:
            console.print(f"  arch:    {info.arch}")

    fm = FridaManager(profile, device_manager)

    console.print("\n[bold]frida-server:[/bold]")
    path = fm.detect_ios_frida_path()
    if not path:
        console.print("  [red]✗[/red] No encontrado en el iPhone")
        console.print(
            "  [dim]Instala desde Sileo/Cydia (fuente: build.frida.re)[/dim]"
        )
    else:
        console.print(f"  [green]✓[/green] binario: {path}")
        try:
            sv = fm.server_version()
            if sv:
                console.print(f"  versión:  {sv}")
                console.print(f"  cliente:  {fm.client_version}")
        except Exception:
            pass

        listening, where = fm.is_ios_server_listening()
        if listening:
            console.print(f"  [green]✓[/green] escuchando en: [cyan]{where}:{profile.frida_port}[/cyan]")
            if where == "127.0.0.1":
                console.print(
                    "  [yellow]⚠[/yellow] solo escucha en 127.0.0.1 — la PC no puede conectar.\n"
                    "  [dim]Ejecuta: bazzingakit frida setup-ios[/dim]"
                )
        else:
            console.print("  [yellow]·[/yellow] no está corriendo")
            console.print("  [dim]Ejecuta: bazzingakit frida setup-ios[/dim]")


@ios.command("apps")
@click.option("--filter", "filter_str", help="Filtrar por nombre o bundle ID (substring)")
def apps_cmd(filter_str: str) -> None:
    """Lista bundle IDs de apps instaladas en el iPhone.

    Funciona tanto en modo USB (sin SSH) como network (con ssh_host).
    """
    if not FRIDA_AVAILABLE:
        console.print("[red]✗[/red] frida no está instalado.")
        raise click.Abort()

    cfg = load_config()
    profile = cfg.get_active_profile()
    if not profile:
        console.print("[red]✗[/red] No hay perfil activo.")
        raise click.Abort()
    if profile.platform != Platform.IOS:
        console.print(
            f"[red]✗[/red] El perfil activo '{profile.name}' es {profile.platform.value}, no iOS."
        )
        raise click.Abort()

    is_usb_mode = not profile.ssh_host

    if is_usb_mode:
        # Modo USB: directo a frida.get_usb_device, sin SSH
        import frida
        try:
            device = frida.get_usb_device(timeout=5)
        except Exception as e:
            console.print(
                f"[red]✗[/red] No se encontró device USB: {e}\n"
                "[dim]Conecta el iPhone, confía en este equipo, y verifica con 'frida-ls-devices'.[/dim]"
            )
            raise click.Abort()
    else:
        # Modo network: validamos SSH primero
        device_manager = get_device_manager(profile)
        fm = FridaManager(profile, device_manager)
        listening, _ = fm.is_ios_server_listening()
        if not listening:
            console.print(
                "[red]✗[/red] frida-server no está corriendo en el iPhone.\n"
                "[dim]Ejecuta primero: bazzingakit frida setup-ios[/dim]"
            )
            raise click.Abort()
        try:
            device = fm._get_frida_device()
        except Exception as e:
            console.print(f"[red]✗[/red] No se pudo conectar: {e}")
            raise click.Abort()

    # Enumerar apps
    try:
        apps = device.enumerate_applications()
    except Exception as e:
        console.print(f"[red]✗[/red] No se pudo enumerar apps: {e}")
        raise click.Abort()

    # Filtrar
    rows = []
    f = filter_str.lower() if filter_str else None
    for a in apps:
        if f and f not in a.identifier.lower() and f not in a.name.lower():
            continue
        rows.append((a.name, a.identifier, str(a.pid) if a.pid else "-"))

    if not rows:
        if filter_str:
            console.print(f"[yellow]Ninguna app matchea '{filter_str}'[/yellow]")
        else:
            console.print("[yellow]No hay apps reportadas por frida.[/yellow]")
        return

    table = Table(title=f"Apps ({len(rows)})")
    table.add_column("Nombre", style="cyan")
    table.add_column("Bundle ID", style="magenta")
    table.add_column("PID", justify="right")

    for name, bid, pid in sorted(rows, key=lambda r: r[1]):
        table.add_row(name, bid, pid)

    console.print(table)
