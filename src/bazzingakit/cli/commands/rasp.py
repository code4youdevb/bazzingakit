"""Comandos de detección de RASP."""

from pathlib import Path

import click
from rich.table import Table

from bazzingakit.config import Platform, load_config
from bazzingakit.core import RASPDetector, detect_from_device, get_device_manager
from bazzingakit.utils import console


@click.group()
def rasp() -> None:
    """Detección de RASP (Runtime Application Self-Protection)."""


@rasp.command("detect")
@click.argument("package_name")
def detect_cmd(package_name: str) -> None:
    """Detecta RASP en una app instalada (pull + análisis estático)."""
    cfg = load_config()
    profile = cfg.get_active_profile()

    if not profile:
        console.print("[red]✗[/red] No hay perfil activo.")
        raise click.Abort()

    if profile.platform != Platform.ANDROID:
        console.print("[yellow]La detección desde dispositivo solo soporta Android por ahora.[/yellow]")
        console.print("Para iOS usa: bazzingakit rasp analyze <archivo.ipa>")
        raise click.Abort()

    manager = get_device_manager(profile)
    if not manager.is_connected():
        console.print("[red]✗[/red] Dispositivo no conectado.")
        raise click.Abort()

    console.print(f"Analizando [cyan]{package_name}[/cyan]...")
    detector = RASPDetector()
    report = detect_from_device(package_name, manager, detector=detector)

    if report is None:
        console.print("[red]✗[/red] No se pudo analizar el paquete (¿está instalado?).")
        raise click.Abort()

    _print_report(report)


@rasp.command("analyze")
@click.argument("apk_path", type=click.Path(exists=True, path_type=Path))
@click.option("--platform", default="android", type=click.Choice(["android", "ios"]))
def analyze_cmd(apk_path: Path, platform: str) -> None:
    """Analiza un APK local sin necesidad de dispositivo."""
    console.print(f"Analizando [cyan]{apk_path}[/cyan]...")
    detector = RASPDetector()
    report = detector.analyze_apk(apk_path, platform=platform)
    _print_report(report)


@rasp.command("list")
def list_cmd() -> None:
    """Lista las firmas de RASP conocidas por el framework."""
    detector = RASPDetector()

    table = Table(title=f"Firmas ({len(detector.signatures)})")
    table.add_column("ID", style="cyan")
    table.add_column("Nombre", style="magenta")
    table.add_column("Vendor")
    table.add_column("Platforms")
    table.add_column("Categoría")

    for sig in detector.signatures:
        table.add_row(
            sig.id,
            sig.name,
            sig.vendor,
            ", ".join(sig.platforms),
            sig.category,
        )

    console.print(table)


@rasp.command("scan-runtime")
@click.argument("package_name")
@click.option("--timeout", default=10, help="Segundos a esperar la enumeración")
@click.option("--spawn", is_flag=True, help="Spawnear la app en lugar de attach")
def scan_runtime_cmd(package_name: str, timeout: int, spawn: bool) -> None:
    """Detecta RASPs enumerando clases cargadas en runtime.

    Por defecto hace attach (la app debe estar corriendo).
    Usa --spawn para que bazzingakit abra la app automáticamente.
    """
    from pathlib import Path

    from bazzingakit.core import FRIDA_AVAILABLE, FridaError, FridaManager

    if not FRIDA_AVAILABLE:
        console.print("[red]✗[/red] frida no está instalado.")
        raise click.Abort()

    cfg = load_config()
    profile = cfg.get_active_profile()
    if not profile:
        console.print("[red]✗[/red] No hay perfil activo.")
        raise click.Abort()

    if profile.platform != Platform.ANDROID:
        console.print("[yellow]scan-runtime solo soporta Android por ahora.[/yellow]")
        raise click.Abort()

    device_manager = get_device_manager(profile)
    if not device_manager.is_connected():
        console.print("[red]✗[/red] Dispositivo no conectado.")
        raise click.Abort()

    fm = FridaManager(profile, device_manager)

    # Probe script
    script_path = (
        Path(__file__).parent.parent.parent
        / "scripts"
        / "android"
        / "detection"
        / "rasp_probe.js"
    )

    if not script_path.exists():
        console.print(f"[red]✗[/red] Script probe no encontrado: {script_path}")
        raise click.Abort()

    # Capturar el resultado
    result_holder: dict = {}

    def on_msg(script_name, message, data):
        if message.get("type") == "send":
            payload = message.get("payload", {})
            if isinstance(payload, dict) and payload.get("type") == "rasp_probe_result":
                result_holder["data"] = payload

    pid = None

    if spawn:
        console.print(f"Spawneando [cyan]{package_name}[/cyan]...")
        try:
            pid = fm.spawn(package_name)
        except FridaError as e:
            console.print(f"[red]✗[/red] {e}")
            raise click.Abort()
    else:
        console.print(f"Attach a [cyan]{package_name}[/cyan]...")
        try:
            fm.attach(package_name)
        except FridaError as e:
            console.print(f"[red]✗[/red] {e}")
            raise click.Abort()
        except Exception as e:
            msg = str(e)
            if "unable to find process" in msg:
                console.print(
                    f"[red]✗[/red] La app [cyan]{package_name}[/cyan] no está corriendo.\n"
                    f"[yellow]Opciones:[/yellow]\n"
                    f"  - Abre la app manualmente y reintenta\n"
                    f"  - Usa el flag [cyan]--spawn[/cyan] para que bazzingakit la abra"
                )
            else:
                console.print(f"[red]✗[/red] {msg}")
            raise click.Abort()

    fm.on_message(on_msg)

    try:
        fm.load_script_file(script_path, name="rasp_probe")
    except Exception as e:
        console.print(f"[red]✗[/red] Error cargando script: {e}")
        fm.detach()
        raise click.Abort()

    # Si spawneamos, hacer resume para que la app arranque
    if pid is not None:
        try:
            fm.resume(pid)
        except Exception:
            pass

    # Esperar respuesta
    console.print(f"Enumerando clases cargadas (timeout {timeout}s)...")
    import time
    waited = 0
    while "data" not in result_holder and waited < timeout:
        time.sleep(0.5)
        waited += 0.5

    fm.detach()

    if "data" not in result_holder:
        console.print("[red]✗[/red] No se recibió respuesta del probe (timeout).")
        console.print("[dim]Posibles causas: la app se cerró, o aún no cargó las clases.[/dim]")
        raise click.Abort()

    payload = result_holder["data"]
    total = payload.get("total_classes", 0)
    findings = payload.get("findings", {})

    console.print(f"\n[bold]Clases enumeradas:[/bold] {total}")

    if not findings:
        console.print("[green]✓ No se detectaron patrones de RASP en runtime.[/green]")
        return

    console.print("\n[bold]Detecciones en runtime:[/bold]")
    for rasp_id, classes in findings.items():
        console.print(f"  [red]⚠[/red] [bold]{rasp_id}[/bold]  ({len(classes)} clases)")
        for cls in classes[:5]:
            console.print(f"      [dim]{cls}[/dim]")
        if len(classes) > 5:
            console.print(f"      [dim]... y {len(classes) - 5} más[/dim]")


def _print_report(report) -> None:
    if not report.matches:
        console.print("\n[green]✓[/green] No se detectaron RASPs ni protecciones conocidas.")
        return

    console.print("\n[bold]Detecciones:[/bold]")
    for match in report.matches:
        sig = match.signature
        icon = "[red]⚠[/red]" if sig.category == "rasp" else "[yellow]•[/yellow]"
        confidence_pct = int(match.confidence * 100)
        console.print(
            f"  {icon} [bold]{sig.name}[/bold] "
            f"[dim]({sig.category})[/dim]  "
            f"confianza: [cyan]{confidence_pct}%[/cyan]"
        )
        for ev in match.evidence[:5]:
            console.print(f"      [dim]{ev}[/dim]")
        if len(match.evidence) > 5:
            console.print(f"      [dim]... y {len(match.evidence) - 5} más[/dim]")

    # Resumen
    console.print()
    if report.has_rasp:
        primary = report.primary_rasp
        console.print(
            f"[bold red]⚠ RASP principal:[/bold red] "
            f"{primary.signature.name} ({int(primary.confidence * 100)}%)"
        )
        console.print(
            "[yellow]Los bypasses genéricos probablemente no funcionarán. "
            "Considera un playbook RASP-específico.[/yellow]"
        )
    else:
        console.print("[green]✓ Sin RASP comercial detectado.[/green]")
        console.print("Puedes usar el playbook estándar.")
