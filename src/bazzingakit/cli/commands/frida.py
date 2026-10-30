"""Comando frida: gestión de frida-server en el dispositivo."""

import click

from bazzingakit.config import Platform, load_config
from bazzingakit.core import FRIDA_AVAILABLE, FridaError, FridaManager, get_device_manager
from bazzingakit.utils import console


@click.group()
def frida() -> None:
    """Gestión de frida-server en el dispositivo."""


def _get_manager(allow_ios_usb: bool = False):
    """Obtiene FridaManager + profile.

    Args:
        allow_ios_usb: si True, permite perfiles iOS sin ssh_host (modo USB puro).
                       Para comandos que pueden funcionar sin SSH (ej. status simple).
                       Default False: bloquea con mensaje claro.
    """
    if not FRIDA_AVAILABLE:
        console.print("[red]✗[/red] frida no está instalado. pip install frida frida-tools")
        raise click.Abort()

    cfg = load_config()
    profile = cfg.get_active_profile()
    if not profile:
        console.print("[red]✗[/red] No hay perfil activo.")
        raise click.Abort()

    # Guard: comandos que requieren SSH no funcionan en iOS USB-only
    if (
        profile.platform == Platform.IOS
        and not profile.ssh_host
        and not allow_ios_usb
    ):
        console.print(
            f"[red]✗[/red] Este comando requiere SSH al iPhone, "
            f"pero el perfil '{profile.name}' está en modo USB (sin ssh_host).\n\n"
            "[yellow]En modo USB iOS:[/yellow]\n"
            "  - El frida-server precargado del iPhone (LaunchDaemon) ya está corriendo.\n"
            "  - No necesitas comandos de gestión del server (start/stop/setup/sync).\n"
            "  - Si los necesitas, añade ssh_host al perfil:\n"
            f"      [cyan]bazzingakit config remove {profile.name}[/cyan]\n"
            f"      [cyan]bazzingakit config add-profile {profile.name} --platform ios "
            "--ssh-host <ip> --ssh-user mobile[/cyan]"
        )
        raise click.Abort()

    device_manager = get_device_manager(profile)
    if not device_manager.is_connected():
        console.print("[red]✗[/red] Dispositivo no conectado.")
        raise click.Abort()

    return FridaManager(profile, device_manager), profile


@frida.command("status")
def status_cmd() -> None:
    """Muestra el estado de frida-server y compatibilidad con el cliente.

    Funciona en Android, iOS network (con SSH), e iOS USB (consulta el device USB).
    """
    if not FRIDA_AVAILABLE:
        console.print("[red]✗[/red] frida no está instalado. pip install frida frida-tools")
        raise click.Abort()

    cfg = load_config()
    profile = cfg.get_active_profile()
    if not profile:
        console.print("[red]✗[/red] No hay perfil activo.")
        raise click.Abort()

    import frida as _frida
    console.print(f"[bold]Cliente (pip):[/bold] {_frida.__version__}")

    # Caso especial: iOS USB sin SSH — consultamos via frida.get_usb_device
    if profile.platform == Platform.IOS and not profile.ssh_host:
        console.print(f"[bold]Modo:[/bold] [cyan]iOS USB[/cyan] (sin ssh_host)")
        try:
            device = _frida.get_usb_device(timeout=5)
        except Exception as e:
            console.print(f"[red]✗[/red] No se encontró iPhone via USB: {e}")
            console.print(
                "[dim]Conecta el iPhone, confía en el equipo, y verifica con 'frida-ls-devices'.[/dim]"
            )
            return

        console.print(f"[bold]Device:[/bold] {device.name} (id: {device.id})")
        try:
            procs = device.enumerate_processes()
            console.print(
                f"[bold]Estado:[/bold] [green]frida-server responde[/green] "
                f"({len(procs)} procesos)"
            )
            console.print(
                "\n[green]✓ Cliente y server son compatibles.[/green]"
            )
        except Exception as e:
            console.print(f"[bold]Estado:[/bold] [red]server no responde[/red]")
            err_str = str(e)
            console.print(f"  [dim]{err_str}[/dim]")
            if "major" in err_str.lower() or "version" in err_str.lower():
                console.print(
                    "\n[yellow]Sugerencia:[/yellow] mismatch de versiones. "
                    "Alinea el cliente PC con la versión major del frida-server del iPhone.\n"
                    "  Si tu iPhone tiene frida 16.x:\n"
                    "  [cyan]pip install \"frida==16.7.19\" \"frida-tools<13\"[/cyan]"
                )
        return

    # Android o iOS network: comportamiento original
    fm, _ = _get_manager()

    if profile.platform == Platform.ANDROID:
        arch = fm.get_device_arch()
        console.print(f"[bold]Arch dispositivo:[/bold] {arch or '?'}")
        console.print(f"[bold]frida-server path:[/bold] {profile.frida_server_path}")

    server_version = fm.server_version()
    if server_version is None:
        console.print("[bold]Server en device:[/bold] [red]no instalado[/red]")
        console.print("\n[yellow]Sugerencia:[/yellow] bazzingakit frida setup")
        return

    console.print(f"[bold]Server en device:[/bold] {server_version}")

    running = fm.is_server_running()
    status_str = "[green]corriendo[/green]" if running else "[yellow]detenido[/yellow]"
    console.print(f"[bold]Estado:[/bold] {status_str}")

    compat, msg = fm.check_version_compat()
    icon = "[green]✓[/green]" if compat else "[red]✗[/red]"
    console.print(f"\n{icon} {msg}")

    if not running:
        console.print("\n[yellow]Sugerencia:[/yellow] bazzingakit frida start")
    elif not compat:
        console.print("\n[yellow]Sugerencia:[/yellow] bazzingakit frida setup --force")


@frida.command("setup")
@click.option("--version", help="Versión específica (default: igual al cliente)")
@click.option("--force", is_flag=True, help="Reinstalar aunque ya exista con misma versión")
@click.option("--start/--no-start", default=True, help="Arrancar después de instalar")
def setup_cmd(version: str, force: bool, start: bool) -> None:
    """Descarga, instala y arranca frida-server en el dispositivo."""
    fm, profile = _get_manager()

    if profile.platform != Platform.ANDROID:
        console.print("[yellow]setup solo soporta Android por ahora.[/yellow]")
        console.print("Para iOS instala frida desde Cydia/Sileo.")
        raise click.Abort()

    target_version = version or fm.client_version
    console.print(f"Instalando frida-server [cyan]{target_version}[/cyan]...")

    try:
        fm.setup_server(version=version, force=force)
        console.print("[green]✓[/green] frida-server instalado")
    except FridaError as e:
        console.print(f"[red]✗[/red] {e}")
        raise click.Abort()

    if start:
        console.print("Arrancando frida-server...")
        if fm.start_server():
            console.print("[green]✓[/green] frida-server corriendo")
        else:
            console.print("[yellow]⚠[/yellow] No se pudo arrancar automáticamente.")
            console.print(f"Arranca manualmente: adb shell 'su -c {profile.frida_server_path} &'")


@frida.command("start")
def start_cmd() -> None:
    """Arranca frida-server en el dispositivo."""
    fm, profile = _get_manager()

    if profile.platform != Platform.ANDROID:
        console.print("[yellow]start solo aplica a Android.[/yellow]")
        raise click.Abort()

    if fm.is_server_running():
        console.print("[green]✓[/green] frida-server ya está corriendo")
        return

    try:
        if fm.start_server():
            console.print("[green]✓[/green] frida-server arrancado")
        else:
            console.print("[red]✗[/red] No se pudo arrancar. Revisa permisos (root?).")
            console.print(f"Intenta manual: adb shell 'su -c {profile.frida_server_path} &'")
            raise click.Abort()
    except FridaError as e:
        console.print(f"[red]✗[/red] {e}")
        raise click.Abort()


@frida.command("stop")
def stop_cmd() -> None:
    """Detiene frida-server."""
    fm, _ = _get_manager()

    if not fm.is_server_running():
        console.print("frida-server no está corriendo")
        return

    if fm.stop_server():
        console.print("[green]✓[/green] frida-server detenido")
    else:
        console.print("[yellow]⚠[/yellow] No se pudo detener")


@frida.command("install")
@click.argument("binary_path", type=click.Path(exists=True))
def install_cmd(binary_path: str) -> None:
    """Sube un binario frida-server local al dispositivo."""
    fm, profile = _get_manager()

    if profile.platform != Platform.ANDROID:
        console.print("[yellow]install solo soporta Android.[/yellow]")
        raise click.Abort()

    try:
        fm.install_server(binary_path)
        console.print(f"[green]✓[/green] Binario instalado en {profile.frida_server_path}")
    except FridaError as e:
        console.print(f"[red]✗[/red] {e}")
        raise click.Abort()


@frida.command("sync")
@click.option(
    "--direction",
    type=click.Choice(["auto", "to-device", "to-client"]),
    default="auto",
    help="Dirección de sincronización. auto: Android→device, iOS→client",
)
def sync_cmd(direction: str) -> None:
    """Iguala las versiones de frida entre cliente y device.

    Por defecto:
      - Android: instala en el device la versión del cliente
      - iOS: instala en el cliente la versión del device
    """
    fm, profile = _get_manager()

    # Resolver dirección automática
    if direction == "auto":
        direction = "to-device" if profile.platform == Platform.ANDROID else "to-client"

    client = fm.client_version
    server = fm.server_version()

    console.print(f"[bold]Cliente:[/bold] {client}")
    console.print(f"[bold]Server:[/bold]  {server or '(no detectado)'}")
    console.print(f"[bold]Dirección:[/bold] {direction}\n")

    if direction == "to-device":
        if profile.platform != Platform.ANDROID:
            console.print("[red]✗[/red] to-device solo aplica a Android.")
            raise click.Abort()
        try:
            fm.setup_server(force=True)
            console.print(f"[green]✓[/green] Device actualizado a {client}")
        except FridaError as e:
            console.print(f"[red]✗[/red] {e}")
            raise click.Abort()

    else:  # to-client
        if not server:
            console.print("[red]✗[/red] No se pudo detectar versión del server.")
            raise click.Abort()

        if not click.confirm(f"Instalar frida=={server} en el cliente (pip)?"):
            return

        ok, msg = fm.sync_client_to_server()
        icon = "[green]✓[/green]" if ok else "[red]✗[/red]"
        console.print(f"{icon} {msg}")
        if not ok:
            raise click.Abort()


@frida.command("setup-ios")
@click.option(
    "--bind",
    default="0.0.0.0",
    help="Dirección a la que bindear frida-server. 0.0.0.0 expone a la red (default), "
         "127.0.0.1 solo permite conexión local.",
)
@click.option(
    "--usb",
    is_flag=True,
    help="Modo USB con iproxy (requiere libimobiledevice instalado en la PC). "
         "No toca el iPhone.",
)
def setup_ios_cmd(bind: str, usb: bool) -> None:
    """Configura frida-server en el iPhone para conexión desde la PC.

    Pre-requisitos:
      - Perfil iOS activo con ssh_host configurado
      - SSH funcionando contra el iPhone (mobile@ip)
      - Frida instalado en el iPhone (vía Cydia/Sileo)

    Modo network (default): mata el frida-server y lo relanza escuchando en 0.0.0.0
    para que tu PC pueda conectar via 'frida -H ip:port'.

    Modo --usb: arranca iproxy en la PC para hacer port forwarding USB→TCP.
    Requiere iproxy (parte de libimobiledevice).
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
            f"[red]✗[/red] El perfil activo '{profile.name}' es {profile.platform.value}, "
            "no iOS.\n"
            "[dim]Cambia con: bazzingakit config use <perfil_ios>[/dim]"
        )
        raise click.Abort()

    # En modo USB no es necesario hacer setup, frida-server precargado ya funciona
    if not profile.ssh_host and not usb:
        console.print(
            "[yellow]ℹ[/yellow] El perfil '{}' está en modo USB (sin ssh_host).\n"
            "  En modo USB, el frida-server precargado del iPhone (LaunchDaemon) ya está corriendo.\n"
            "  Conecta el iPhone por USB y usa los comandos directamente:\n"
            "  [cyan]bazzingakit ios apps[/cyan]\n"
            "  [cyan]bazzingakit run <bundle_id> --script <script.js>[/cyan]\n\n"
            "  Si quieres modo network (acceso via WiFi), añade ssh_host al perfil.\n"
            "  Si quieres lanzar iproxy (USB→TCP forwarding), usa: "
            "[cyan]bazzingakit frida setup-ios --usb[/cyan]".format(profile.name)
        )
        return

    if usb:
        _setup_ios_usb(profile)
        return

    _setup_ios_network(profile, bind)


def _setup_ios_network(profile, bind: str) -> None:
    """Modo network: relanza frida-server en bind:port en el iPhone."""
    import shutil

    device_manager = get_device_manager(profile)

    # Validaciones
    console.print("[bold]Validando conexión SSH...[/bold]")
    if not device_manager.is_connected():
        console.print(
            f"[red]✗[/red] No se pudo conectar al iPhone vía SSH "
            f"({profile.ssh_user}@{profile.ssh_host}:{profile.ssh_port})\n"
            "[yellow]Tips:[/yellow]\n"
            "  - Verifica que el iPhone está encendido y en la misma WiFi\n"
            "  - Verifica la IP: en el iPhone Settings → WiFi → toca tu red → IP Address\n"
            "  - Verifica que OpenSSH está instalado en el iPhone (Cydia/Sileo)\n"
            f"  - Prueba manual: ssh {profile.ssh_user}@{profile.ssh_host}\n"
            "  - Si la IP cambió: bazzingakit config remove <perfil> + add-profile con nueva IP"
        )
        raise click.Abort()
    console.print(f"  [green]✓[/green] SSH conecta a {profile.ssh_host}")

    fm = FridaManager(profile, device_manager)

    # Detectar path
    console.print("[bold]Buscando frida-server en el iPhone...[/bold]")
    path = fm.detect_ios_frida_path()
    if not path:
        console.print(
            "[red]✗[/red] frida-server no encontrado en rutas conocidas.\n"
            "[yellow]Tips:[/yellow]\n"
            "  - Instálalo desde Sileo/Cydia: añade fuente 'https://build.frida.re' "
            "y busca 'Frida'\n"
            "  - O cópialo manualmente a /var/jb/usr/sbin/frida-server (rootless) "
            "o /usr/sbin/frida-server (tradicional)"
        )
        raise click.Abort()
    console.print(f"  [green]✓[/green] Encontrado en: [cyan]{path}[/cyan]")

    # Setup
    console.print(f"[bold]Lanzando frida-server con bind {bind}:{profile.frida_port}...[/bold]")
    try:
        info = fm.setup_ios_network(bind=bind)
    except FridaError as e:
        console.print(f"[red]✗[/red] {e}")
        raise click.Abort()

    console.print(
        f"  [green]✓[/green] frida-server escuchando en "
        f"[cyan]{info['listening_on']}:{info['port']}[/cyan]"
    )

    # Resumen + comandos útiles
    console.print()
    if bind == "0.0.0.0":
        console.print("[bold green]✓ Listo para conectar desde la PC.[/bold green]")
        console.print(f"\n[bold]Cómo conectar:[/bold]")
        console.print(
            f"  Manual:      [cyan]frida -H {profile.ssh_host}:{info['port']} "
            f"-f <bundle_id> -l <script.js>[/cyan]"
        )
        console.print(
            f"  Bazzingakit: [cyan]bazzingakit run <bundle_id> --script <script.js>[/cyan]"
        )
        console.print(
            f"\n[yellow]⚠ Atención:[/yellow] frida-server expone el puerto a "
            f"toda tu red WiFi. Úsalo solo en redes confiables."
        )
    else:
        console.print(f"[green]frida-server vinculado a {bind} (modo seguro).[/green]")


def _setup_ios_usb(profile) -> None:
    """Modo USB: lanza iproxy en la PC."""
    import shutil
    import subprocess

    if not shutil.which("iproxy"):
        console.print(
            "[red]✗[/red] iproxy no encontrado en PATH.\n"
            "[yellow]Instalación:[/yellow]\n"
            "  - Windows: instala libimobiledevice "
            "(https://github.com/libimobiledevice-win32/imobiledevice-net)\n"
            "  - Linux:   sudo apt install libimobiledevice-utils\n"
            "  - Mac:     brew install libimobiledevice"
        )
        raise click.Abort()

    port = profile.frida_port
    console.print(f"[bold]Lanzando iproxy {port}:{port} en background...[/bold]")

    # Matar iproxy previo si lo hay
    try:
        if shutil.which("pkill"):
            subprocess.run(["pkill", "-x", "iproxy"], capture_output=True, timeout=3)
        else:
            # Windows: taskkill
            subprocess.run(
                ["taskkill", "/F", "/IM", "iproxy.exe"],
                capture_output=True, timeout=3,
            )
    except Exception:
        pass

    # Lanzar iproxy en background
    try:
        subprocess.Popen(
            ["iproxy", str(port), str(port)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception as e:
        console.print(f"[red]✗[/red] No se pudo lanzar iproxy: {e}")
        raise click.Abort()

    console.print(f"  [green]✓[/green] iproxy {port}:{port} corriendo")
    console.print(f"\n[bold]Cómo conectar:[/bold]")
    console.print(
        f"  Manual:      [cyan]frida -H 127.0.0.1:{port} -f <bundle_id> -l <script.js>[/cyan]"
    )
    console.print(
        f"  Bazzingakit: [cyan]bazzingakit run <bundle_id> --script <script.js>[/cyan]"
    )
    console.print(
        f"  [dim](Para bazzingakit con USB, configura el perfil con ssh_host=127.0.0.1)[/dim]"
    )
