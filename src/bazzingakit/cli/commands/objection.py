"""Comando objection: wrapper sobre objection (https://github.com/sensepost/objection)."""

import shutil
import subprocess
import sys
from typing import Optional

import click

from bazzingakit.config import Platform, load_config
from bazzingakit.utils import console


def _build_objection_args(
    package: str,
    use_network: bool,
    ssh_host: Optional[str],
    frida_port: int,
    attach: bool,
    commands: tuple,
) -> list[str]:
    """Construye los argumentos para invocar objection."""
    args = ["objection"]

    # Modo network (iOS con ssh_host)
    if use_network and ssh_host:
        args.extend(["-N", "--host", ssh_host, "--port", str(frida_port)])

    # Gadget / package
    args.extend(["-g", package])

    # Comando o shell interactiva
    if commands:
        # Múltiples -c se acumulan en objection
        # objection -g pkg -c "cmd1" -c "cmd2" no es soportado directamente,
        # pero podemos combinarlos con ";"
        combined = " ; ".join(commands)
        args.extend(["explore", "--startup-command", combined])
    else:
        args.append("explore")

    # Attach a proceso existente
    if attach:
        # objection por defecto hace attach. -s es para spawn.
        pass
    else:
        args.append("--startup-command-once" if commands else "")
        # Filtrar vacíos
        args = [a for a in args if a]

    return args


@click.command()
@click.argument("package_name")
@click.option(
    "-c", "--command",
    "commands",
    multiple=True,
    help="Comando(s) de objection a ejecutar al inicio. Puede repetirse.",
)
@click.option(
    "--attach/--spawn",
    default=False,
    help="Attach a proceso existente (default) o spawn nuevo. "
         "Objection por defecto hace attach.",
)
@click.option(
    "--network",
    "force_network",
    is_flag=True,
    help="Forzar modo network (-N --host) usando ssh_host del perfil iOS.",
)
@click.option(
    "--usb",
    "force_usb",
    is_flag=True,
    help="Forzar modo USB (ignora ssh_host del perfil).",
)
@click.option(
    "--print-cmd",
    is_flag=True,
    help="Solo imprime el comando objection que se ejecutaría, sin lanzarlo.",
)
def objection(
    package_name: str,
    commands: tuple,
    attach: bool,
    force_network: bool,
    force_usb: bool,
    print_cmd: bool,
) -> None:
    """Lanza objection contra una app, con detección automática de modo.

    Modo de conexión:
      - Android: siempre USB
      - iOS sin ssh_host configurado: USB
      - iOS con ssh_host: network (-N --host ip:port)
      - Con --usb / --network: fuerza el modo

    Ejemplos:
      bazzingakit objection com.app
      bazzingakit objection com.app -c "ios sslpinning disable"
      bazzingakit objection com.app -c "android root disable" -c "android sslpinning disable"
      bazzingakit objection com.app --print-cmd
    """
    if force_network and force_usb:
        console.print("[red]✗[/red] No puedes usar --network y --usb a la vez.")
        raise click.Abort()

    # 1. Verificar objection instalado
    if not shutil.which("objection"):
        console.print(
            "[red]✗[/red] objection no encontrado en PATH.\n"
            "[yellow]Instalación:[/yellow] [cyan]pip install objection[/cyan]"
        )
        raise click.Abort()

    # 2. Resolver perfil
    cfg = load_config()
    profile = cfg.get_active_profile()
    if not profile:
        console.print("[red]✗[/red] No hay perfil activo.")
        raise click.Abort()

    # 3. Decidir modo
    use_network = False
    ssh_host_port = None
    frida_port = profile.frida_port

    if profile.platform == Platform.ANDROID:
        if force_network:
            console.print("[yellow]⚠[/yellow] --network solo aplica a iOS, ignorando.")
        # Android siempre USB
        use_network = False
    else:  # iOS
        if force_usb:
            use_network = False
        elif force_network:
            if not profile.ssh_host:
                console.print(
                    "[red]✗[/red] --network requiere ssh_host configurado en el perfil."
                )
                raise click.Abort()
            use_network = True
            ssh_host_port = profile.ssh_host
        else:
            # Auto: si hay ssh_host, network; si no, USB
            if profile.ssh_host:
                use_network = True
                ssh_host_port = profile.ssh_host
            else:
                use_network = False

    # 4. Construir comando
    args = ["objection"]
    if use_network:
        args.extend(["-N", "--host", f"{ssh_host_port}:{frida_port}"])
    args.extend(["-g", package_name, "explore"])

    if commands:
        combined = " ; ".join(commands)
        args.extend(["--startup-command", combined])

    # 5. Print o ejecutar
    cmd_str = " ".join(f'"{a}"' if " " in a else a for a in args)
    mode_label = (
        f"[cyan]network[/cyan] ({ssh_host_port}:{frida_port})"
        if use_network else "[cyan]USB[/cyan]"
    )
    console.print(f"[bold]Modo:[/bold] {mode_label}")
    console.print(f"[dim]$ {cmd_str}[/dim]\n")

    if print_cmd:
        return

    # 6. Lanzar objection (toma control de la terminal)
    try:
        # No usamos capture_output: objection es interactivo
        result = subprocess.run(args)
        if result.returncode != 0:
            console.print(
                f"\n[yellow]objection terminó con código {result.returncode}.[/yellow]"
            )
    except FileNotFoundError:
        console.print("[red]✗[/red] objection no se pudo lanzar.")
        raise click.Abort()
    except KeyboardInterrupt:
        console.print("\n[dim]Cancelado por usuario.[/dim]")
