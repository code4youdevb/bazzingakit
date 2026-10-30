"""Comando proxy: gestión de certificados de Burp en el dispositivo."""

import tempfile
from pathlib import Path

import click

from bazzingakit.config import Platform, load_config
from bazzingakit.core import BurpProxyError, BurpProxyManager, get_device_manager
from bazzingakit.utils import console


@click.group()
def proxy() -> None:
    """Gestión de proxies y certificados (Burp Suite)."""


def _get_managers():
    cfg = load_config()
    profile = cfg.get_active_profile()
    if not profile:
        console.print("[red]✗[/red] No hay perfil activo.")
        raise click.Abort()
    if profile.platform != Platform.ANDROID:
        console.print("[yellow]El comando proxy solo soporta Android por ahora.[/yellow]")
        raise click.Abort()

    device_manager = get_device_manager(profile)
    burp = BurpProxyManager(device_manager)
    return device_manager, burp, profile


def _print_check(name: str, ok: bool, message: str) -> None:
    icon = "[green]✓[/green]" if ok else "[red]✗[/red]"
    console.print(f"  {icon} {name}: {message}")


@proxy.command("setup-burp")
@click.option("--host", "burp_host", default="127.0.0.1", help="Host donde corre Burp")
@click.option("--port", default=8080, type=int, help="Puerto de Burp Proxy")
@click.option(
    "--permanent",
    is_flag=True,
    help="Instalar como módulo Magisk (permanente, requiere reboot). "
         "Default es bind mount (solo sesión actual).",
)
@click.option(
    "--skip-burp-check",
    is_flag=True,
    help="No validar que Burp esté accesible (útil si descargas cert manual primero).",
)
def setup_burp_cmd(burp_host: str, port: int, permanent: bool, skip_burp_check: bool) -> None:
    """Descarga e instala el certificado CA de Burp en el dispositivo.

    Pre-requisitos:
      - Burp Suite abierto con proxy listener en {host}:{port} (default 127.0.0.1:8080)
      - openssl instalado en la PC
      - Dispositivo Android rooteado con Magisk

    Por defecto usa bind mount (no permanente, se pierde al reboot).
    Con --permanent genera e instala un módulo Magisk (requiere reboot del device).
    """
    device, burp, profile = _get_managers()

    # ---------- Validaciones ----------
    console.print("[bold]Validando entorno...[/bold]")

    ok, msg = burp.check_openssl()
    _print_check("openssl", ok, msg)
    if not ok:
        raise click.Abort()

    if not skip_burp_check:
        ok, msg = burp.check_burp(host=burp_host, port=port)
        _print_check(f"Burp ({burp_host}:{port})", ok, msg)
        if not ok:
            raise click.Abort()
    else:
        console.print("  [dim]✓ Burp check saltado[/dim]")

    ok, msg = burp.check_device_ready()
    _print_check("Dispositivo", ok, msg)
    if not ok:
        raise click.Abort()

    ok, msg = burp.check_magisk()
    _print_check("Magisk", ok, msg)
    if not ok:
        raise click.Abort()

    # ---------- Procesar cert ----------
    console.print("\n[bold]Procesando certificado...[/bold]")
    try:
        with tempfile.TemporaryDirectory(prefix="bazzingakit_burp_") as tmpdir:
            tmp = Path(tmpdir)
            der = burp.download_cert(host=burp_host, port=port)
            cert = burp.process_cert(der, tmp)
            console.print(f"  [green]✓[/green] Cert procesado: [cyan]{cert.hash_name}[/cyan]")

            # ---------- Instalar ----------
            if permanent:
                console.print("\n[bold]Instalando como módulo Magisk (permanente)...[/bold]")
                console.print(
                    "[yellow]⚠[/yellow] Este modo requiere reboot del dispositivo "
                    "para que tome efecto."
                )
                if not click.confirm("¿Continuar?", default=True):
                    return
                zip_path = burp.install_via_magisk_module(cert, tmp)
                console.print(f"  [green]✓[/green] Módulo instalado: [cyan]{zip_path}[/cyan]")
                console.print(
                    "\n[bold yellow]Acción requerida:[/bold yellow] "
                    "reinicia el dispositivo para activar el cert.\n"
                    "  [dim]Comando útil:[/dim] "
                    f"[cyan]{profile.adb_path or 'adb'} reboot[/cyan]"
                )
            else:
                console.print("\n[bold]Instalando vía bind mount (sesión actual)...[/bold]")
                burp.install_via_bind_mount(cert)
                console.print(
                    f"\n[bold green]✓ Cert instalado.[/bold green] "
                    f"Hash: [cyan]{cert.hash_name}[/cyan]"
                )
                console.print(
                    "[dim]Esto durará hasta que reinicies el dispositivo. "
                    "Configura el proxy en la WiFi del Android manualmente.[/dim]"
                )
    except BurpProxyError as e:
        console.print(f"\n[red]✗ Error:[/red] {e}")
        raise click.Abort()


@proxy.command("status")
@click.option("--hash", "hash_name", help="Hash específico a verificar (ej. 9a5ba575.0)")
def status_cmd(hash_name: str) -> None:
    """Muestra el estado del cert y bind mount en el dispositivo."""
    device, burp, _ = _get_managers()

    info = burp.status(hash_name=hash_name)

    icon_dev = "[green]✓[/green]" if info["device_connected"] else "[red]✗[/red]"
    console.print(f"{icon_dev} Dispositivo conectado: {info['device_connected']}")

    if not info["device_connected"]:
        return

    if hash_name:
        icon_a = "[green]✓[/green]" if info["cert_in_apex"] else "[yellow]·[/yellow]"
        icon_l = "[green]✓[/green]" if info["cert_in_legacy"] else "[yellow]·[/yellow]"
        console.print(f"{icon_a} Cert en {' /apex/com.android.conscrypt/cacerts/'}: {hash_name}")
        console.print(f"{icon_l} Cert en /system/etc/security/cacerts/: {hash_name}")
    else:
        console.print("[dim]Pasa --hash <hash>.0 para verificar un cert específico.[/dim]")

    icon_b = "[green]✓[/green]" if info["bind_mount_active"] else "[yellow]·[/yellow]"
    console.print(f"{icon_b} Bind mount activo: {info['bind_mount_active']}")


@proxy.command("clean")
def clean_cmd() -> None:
    """Deshace el bind mount (revierte el cert instalado vía bind mount).

    No remueve módulos Magisk — esos se quitan desde Magisk Manager.
    """
    device, burp, _ = _get_managers()

    if not click.confirm("¿Deshacer el bind mount de cacerts?", default=True):
        return

    burp.unmount_bind()
    console.print("[green]✓[/green] Bind mounts removidos (si existían)")
    console.print(
        "[dim]Si instalaste vía --permanent (módulo Magisk), "
        "remuévelo desde Magisk Manager → Modules.[/dim]"
    )
