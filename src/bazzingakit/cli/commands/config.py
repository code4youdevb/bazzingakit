"""Comandos de gestión de configuración."""

import subprocess
from pathlib import Path

import click
from rich.table import Table

from bazzingakit.config import (
    DeviceProfile,
    Platform,
    add_profile,
    get_config_path,
    init_config,
    load_config,
    save_config,
    set_active_profile,
)
from bazzingakit.utils import console, get_logger

log = get_logger(__name__)


@click.group()
def config() -> None:
    """Gestión de la configuración y perfiles de dispositivo."""


@config.command("init")
@click.option("--force", is_flag=True, help="Sobrescribir si ya existe")
def init_cmd(force: bool) -> None:
    """Inicializa el directorio de configuración en ~/.bazzingakit/."""
    path = init_config(force=force)
    console.print(f"[green]✓[/green] Configuración inicializada en: [cyan]{path}[/cyan]")


@config.command("show")
def show_cmd() -> None:
    """Muestra la configuración actual."""
    cfg = load_config()
    path = get_config_path()

    console.print(f"[bold]Archivo:[/bold] {path}")
    console.print(f"[bold]Perfil activo:[/bold] {cfg.active_profile or '(ninguno)'}\n")

    if not cfg.profiles:
        console.print("[yellow]No hay perfiles configurados.[/yellow]")
        console.print("Añade uno con: [cyan]bazzingakit config add-profile[/cyan]")
        return

    table = Table(title="Perfiles")
    table.add_column("Nombre", style="cyan")
    table.add_column("Plataforma", style="magenta")
    table.add_column("Detalles")
    table.add_column("Activo", justify="center")

    for name, profile in cfg.profiles.items():
        if profile.platform == Platform.ANDROID:
            details = f"adb: {profile.adb_path or '(system)'} @ {profile.adb_host}:{profile.adb_port}"
        else:
            details = f"ssh: {profile.ssh_user}@{profile.ssh_host}:{profile.ssh_port}"

        active = "✓" if name == cfg.active_profile else ""
        table.add_row(name, profile.platform.value, details, active)

    console.print(table)


@config.command("add-profile")
@click.argument("name")
@click.option(
    "--platform",
    type=click.Choice(["android", "ios"]),
    required=True,
)
@click.option("--adb-path", help="Ruta a adb (útil para nox_adb)")
@click.option("--adb-host", default="127.0.0.1")
@click.option("--adb-port", type=int, default=5037)
@click.option("--device-serial", help="Serial específico del dispositivo")
@click.option("--ssh-host", help="Host SSH (iOS)")
@click.option("--ssh-port", type=int, default=22)
@click.option("--ssh-user", default="root")
@click.option("--ssh-key", help="Path a clave SSH privada")
@click.option("--activate/--no-activate", default=True, help="Marcar como activo")
def add_profile_cmd(
    name: str,
    platform: str,
    adb_path: str | None,
    adb_host: str,
    adb_port: int,
    device_serial: str | None,
    ssh_host: str | None,
    ssh_port: int,
    ssh_user: str,
    ssh_key: str | None,
    activate: bool,
) -> None:
    """Añade un perfil de dispositivo."""
    cfg = load_config()

    if name in cfg.profiles:
        if not click.confirm(f"El perfil '{name}' ya existe. ¿Sobrescribir?"):
            return

    profile = DeviceProfile(
        name=name,
        platform=Platform(platform),
        adb_path=adb_path,
        adb_host=adb_host,
        adb_port=adb_port,
        device_serial=device_serial,
        ssh_host=ssh_host,
        ssh_port=ssh_port,
        ssh_user=ssh_user,
        ssh_key=ssh_key,
    )

    add_profile(cfg, profile)
    if activate:
        set_active_profile(cfg, name)

    save_config(cfg)
    console.print(f"[green]✓[/green] Perfil '[cyan]{name}[/cyan]' añadido.")
    if activate:
        console.print(f"[green]✓[/green] Marcado como activo.")


@config.command("use")
@click.argument("name")
def use_cmd(name: str) -> None:
    """Cambia el perfil activo."""
    cfg = load_config()
    try:
        set_active_profile(cfg, name)
    except ValueError as e:
        console.print(f"[red]✗[/red] {e}")
        raise click.Abort()

    save_config(cfg)
    console.print(f"[green]✓[/green] Perfil activo: [cyan]{name}[/cyan]")


@config.command("remove")
@click.argument("name")
def remove_cmd(name: str) -> None:
    """Elimina un perfil."""
    cfg = load_config()
    if name not in cfg.profiles:
        console.print(f"[red]✗[/red] Perfil '{name}' no existe.")
        raise click.Abort()

    if not click.confirm(f"¿Eliminar el perfil '{name}'?"):
        return

    del cfg.profiles[name]
    if cfg.active_profile == name:
        cfg.active_profile = next(iter(cfg.profiles), None)

    save_config(cfg)
    console.print(f"[green]✓[/green] Perfil '[cyan]{name}[/cyan]' eliminado.")


@config.command("test")
def test_cmd() -> None:
    """Verifica que el perfil activo funcione (adb/ssh responde)."""
    cfg = load_config()
    profile = cfg.get_active_profile()

    if not profile:
        console.print("[red]✗[/red] No hay perfil activo.")
        raise click.Abort()

    console.print(f"Probando perfil [cyan]{profile.name}[/cyan]...")

    if profile.platform == Platform.ANDROID:
        adb_cmd = profile.adb_path or "adb"
        if not Path(adb_cmd).exists() and adb_cmd != "adb":
            console.print(f"[red]✗[/red] adb no existe en: {adb_cmd}")
            raise click.Abort()

        try:
            result = subprocess.run(
                [adb_cmd, "devices"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            console.print(f"[green]✓[/green] adb responde:")
            console.print(f"[dim]{result.stdout.strip()}[/dim]")
        except FileNotFoundError:
            console.print(f"[red]✗[/red] No se puede ejecutar: {adb_cmd}")
        except subprocess.TimeoutExpired:
            console.print("[red]✗[/red] adb timeout")
        except Exception as e:
            console.print(f"[red]✗[/red] Error: {e}")

    else:  # iOS
        if not profile.ssh_host:
            console.print("[red]✗[/red] ssh_host no configurado")
            raise click.Abort()

        ssh_args = ["ssh", "-o", "ConnectTimeout=5", "-o", "BatchMode=yes"]
        if profile.ssh_key:
            ssh_args += ["-i", profile.ssh_key]
        ssh_args += [
            "-p",
            str(profile.ssh_port),
            f"{profile.ssh_user}@{profile.ssh_host}",
            "echo OK",
        ]

        try:
            result = subprocess.run(ssh_args, capture_output=True, text=True, timeout=10)
            if "OK" in result.stdout:
                console.print(f"[green]✓[/green] SSH conecta a {profile.ssh_host}")
            else:
                console.print(f"[red]✗[/red] SSH falló: {result.stderr.strip()}")
        except Exception as e:
            console.print(f"[red]✗[/red] Error SSH: {e}")


@config.command("path")
def path_cmd() -> None:
    """Muestra la ruta del archivo de configuración."""
    console.print(str(get_config_path()))


@config.command("setup-ssh-key")
@click.argument("profile_name", required=False)
@click.option(
    "--key-path",
    default=None,
    help="Ruta de la clave a usar/generar. Default: ~/.ssh/bazzingakit_<perfil>",
)
@click.option(
    "--regenerate",
    is_flag=True,
    help="Regenerar la clave aunque ya exista",
)
def setup_ssh_key_cmd(profile_name: str, key_path: str, regenerate: bool) -> None:
    """Configura SSH sin password para un perfil iOS.

    Genera una SSH key si no existe, la copia al dispositivo, y actualiza
    el perfil para usarla. Después de esto, ninguna operación SSH pedirá
    password.

    Si no pasas profile_name, usa el perfil activo.
    """
    cfg = load_config()

    # Resolver perfil
    if profile_name:
        if profile_name not in cfg.profiles:
            console.print(f"[red]✗[/red] Perfil '{profile_name}' no existe.")
            raise click.Abort()
        profile = cfg.profiles[profile_name]
    else:
        profile = cfg.get_active_profile()
        if not profile:
            console.print("[red]✗[/red] No hay perfil activo y no especificaste uno.")
            raise click.Abort()
        profile_name = profile.name

    if profile.platform != Platform.IOS:
        console.print(
            f"[red]✗[/red] El perfil '{profile_name}' es {profile.platform.value}, "
            "no iOS. Este comando es solo para perfiles iOS."
        )
        raise click.Abort()

    if not profile.ssh_host:
        console.print(
            f"[red]✗[/red] El perfil '{profile_name}' no tiene ssh_host configurado."
        )
        raise click.Abort()

    # Verificar ssh-keygen disponible
    import shutil
    if not shutil.which("ssh-keygen"):
        console.print(
            "[red]✗[/red] ssh-keygen no encontrado en PATH.\n"
            "[dim]Windows 10+ ya lo trae. Si te falta, instala OpenSSH client desde "
            "Settings → Apps → Optional features.[/dim]"
        )
        raise click.Abort()

    if not shutil.which("ssh"):
        console.print("[red]✗[/red] ssh no encontrado en PATH.")
        raise click.Abort()

    # Decidir ruta de la key
    if key_path:
        key_path_obj = Path(key_path).expanduser()
    else:
        key_path_obj = Path.home() / ".ssh" / f"bazzingakit_{profile_name}"

    pub_key_path = Path(str(key_path_obj) + ".pub")

    console.print(
        f"[bold]Configurando SSH key para perfil[/bold] "
        f"[cyan]{profile_name}[/cyan] → {profile.ssh_user}@{profile.ssh_host}"
    )
    console.print(f"  [dim]Key path: {key_path_obj}[/dim]")

    # 1. Generar clave si no existe
    if key_path_obj.exists() and not regenerate:
        console.print(f"  [green]✓[/green] La clave ya existe (usa --regenerate para forzar)")
    else:
        if key_path_obj.exists() and regenerate:
            console.print(f"  [yellow]⚠[/yellow] Sobrescribiendo clave existente...")
            try:
                key_path_obj.unlink()
                if pub_key_path.exists():
                    pub_key_path.unlink()
            except Exception as e:
                console.print(f"[red]✗[/red] No se pudo eliminar key vieja: {e}")
                raise click.Abort()

        # Asegurar que ~/.ssh existe
        key_path_obj.parent.mkdir(parents=True, exist_ok=True)

        console.print("  [dim]Generando clave ed25519 sin passphrase...[/dim]")
        try:
            result = subprocess.run(
                [
                    "ssh-keygen",
                    "-t", "ed25519",
                    "-f", str(key_path_obj),
                    "-N", "",  # sin passphrase
                    "-C", f"bazzingakit-{profile_name}",
                    "-q",
                ],
                capture_output=True, text=True, timeout=30,
            )
        except subprocess.TimeoutExpired:
            console.print("[red]✗[/red] ssh-keygen timeout")
            raise click.Abort()

        if result.returncode != 0:
            console.print(f"[red]✗[/red] ssh-keygen falló: {result.stderr}")
            raise click.Abort()
        console.print(f"  [green]✓[/green] Clave generada")

    # 2. Copiar la pública al dispositivo
    if not pub_key_path.exists():
        console.print(f"[red]✗[/red] No se encuentra la clave pública: {pub_key_path}")
        raise click.Abort()

    pub_key_content = pub_key_path.read_text(encoding="utf-8").strip()

    console.print(
        f"\n[bold]Copiando clave pública al iPhone...[/bold]\n"
        f"[yellow]Te va a pedir el password de {profile.ssh_user} UNA vez.[/yellow]"
    )

    # Comando que mete la pub key en authorized_keys, idempotente
    # (no duplica si ya estaba)
    remote_cmd = (
        "mkdir -p ~/.ssh && "
        "chmod 700 ~/.ssh && "
        "touch ~/.ssh/authorized_keys && "
        "chmod 600 ~/.ssh/authorized_keys && "
        f'(grep -qxF "{pub_key_content}" ~/.ssh/authorized_keys || '
        f'echo "{pub_key_content}" >> ~/.ssh/authorized_keys)'
    )

    ssh_cmd = [
        "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-p", str(profile.ssh_port),
        f"{profile.ssh_user}@{profile.ssh_host}",
        remote_cmd,
    ]

    try:
        result = subprocess.run(ssh_cmd, timeout=60)
    except subprocess.TimeoutExpired:
        console.print("[red]✗[/red] SSH timeout")
        raise click.Abort()
    except KeyboardInterrupt:
        console.print("[yellow]Cancelado por el usuario.[/yellow]")
        raise click.Abort()

    if result.returncode != 0:
        console.print(
            f"[red]✗[/red] No se pudo copiar la clave (return code {result.returncode}).\n"
            "[dim]Verifica que el password fue correcto y que SSH al iPhone funciona.[/dim]"
        )
        raise click.Abort()

    console.print("  [green]✓[/green] Clave copiada al iPhone")

    # 3. Verificar conexión sin password
    console.print("\n[bold]Verificando conexión sin password...[/bold]")
    verify_cmd = [
        "ssh",
        "-i", str(key_path_obj),
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=5",
        "-p", str(profile.ssh_port),
        f"{profile.ssh_user}@{profile.ssh_host}",
        "echo OK",
    ]
    try:
        result = subprocess.run(verify_cmd, capture_output=True, text=True, timeout=15)
    except Exception as e:
        console.print(f"[red]✗[/red] Verificación falló: {e}")
        raise click.Abort()

    if result.returncode != 0 or "OK" not in result.stdout:
        console.print(
            f"[red]✗[/red] SSH key copiada pero la verificación falla.\n"
            f"  stdout: {result.stdout}\n  stderr: {result.stderr}"
        )
        raise click.Abort()

    console.print("  [green]✓[/green] Conexión sin password funciona")

    # 4. Actualizar perfil
    profile.ssh_key = str(key_path_obj)
    cfg.profiles[profile_name] = profile
    save_config(cfg)

    console.print(
        f"\n[bold green]✓ SSH key configurada para '{profile_name}'.[/bold green]"
    )
    console.print(
        "[dim]A partir de ahora, todos los comandos SSH (ios info, frida setup-ios, etc.) "
        "funcionarán sin pedir password.[/dim]"
    )
