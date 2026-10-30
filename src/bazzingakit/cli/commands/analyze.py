"""Comandos principales: analyze (solo análisis) y run (análisis + ejecución)."""

from pathlib import Path

import click

from bazzingakit.config import Platform, load_config
from bazzingakit.core import (
    FRIDA_AVAILABLE,
    FridaManager,
    PlaybookRunner,
    SessionManager,
    analyze_and_decide,
    get_device_manager,
)
from bazzingakit.utils import console


def _decision_summary(decision) -> None:
    """Imprime resumen de la decisión del orchestrator."""
    console.print()
    if decision.rasp_report:
        r = decision.rasp_report
        if r.has_rasp and r.primary_rasp:
            conf = int(r.primary_rasp.confidence * 100)
            console.print(
                f"[bold red]⚠ RASP detectado:[/bold red] "
                f"{r.primary_rasp.signature.name} ({conf}%)"
            )
        elif r.matches:
            console.print("[yellow]Protecciones discretas detectadas:[/yellow]")
            for m in r.matches[:5]:
                conf = int(m.confidence * 100)
                console.print(f"  • {m.signature.name} ({conf}%)")
        else:
            console.print("[green]✓[/green] Sin protecciones conocidas detectadas.")

    console.print(f"\n[bold]Decisión:[/bold] {decision.reason}")

    for w in decision.warnings:
        console.print(f"[yellow]⚠[/yellow] {w}")

    if decision.recommended_playbook:
        pb = decision.recommended_playbook
        console.print(f"[bold]Playbook:[/bold] [cyan]{pb.name}[/cyan]")
        console.print(f"  Scripts a cargar: {len(pb.scripts)}")
        for s in sorted(pb.scripts, key=lambda x: x.order):
            critical = " [red](critical)[/red]" if s.critical else ""
            console.print(f"    {s.order}. {s.name}{critical}")
    else:
        console.print("[yellow]No hay playbook aplicable automáticamente.[/yellow]")


@click.command()
@click.argument("package_name")
@click.option("--playbook", help="Forzar playbook específico")
@click.option("--no-rasp-check", is_flag=True, help="Saltar detección de RASP")
def analyze(package_name: str, playbook: str, no_rasp_check: bool) -> None:
    """Analiza una app (detecta RASP) y muestra el plan sugerido, sin ejecutar."""
    cfg = load_config()
    profile = cfg.get_active_profile()
    if not profile:
        console.print("[red]✗[/red] No hay perfil activo.")
        raise click.Abort()

    manager = get_device_manager(profile)
    if not manager.is_connected():
        console.print("[red]✗[/red] Dispositivo no conectado.")
        raise click.Abort()

    console.print(f"Analizando [cyan]{package_name}[/cyan] en perfil [cyan]{profile.name}[/cyan]...")

    decision = analyze_and_decide(
        package_name=package_name,
        device_manager=manager,
        platform=profile.platform.value,
        force_playbook=playbook,
        skip_rasp_check=no_rasp_check,
    )

    _decision_summary(decision)


@click.command()
@click.argument("package_name")
@click.option("--playbook", help="Forzar playbook específico")
@click.option("--no-rasp-check", is_flag=True, help="Saltar detección de RASP")
@click.option("--yes", "-y", is_flag=True, help="No pedir confirmación")
@click.option(
    "--script",
    "scripts",
    multiple=True,
    type=click.Path(exists=True),
    help="Ruta a un .js a cargar (puede repetirse). Si se usa, salta playbook y RASP detection.",
)
@click.option(
    "--spawn/--attach",
    default=True,
    help="Spawnear la app (default) o attach a un proceso ya corriendo. Solo aplica con --script.",
)
@click.option(
    "--duration",
    default=0,
    help="Segundos a mantener la sesión viva (0 = hasta Ctrl+C). Solo aplica con --script.",
)
def run(
    package_name: str,
    playbook: str,
    no_rasp_check: bool,
    yes: bool,
    scripts: tuple,
    spawn: bool,
    duration: int,
) -> None:
    """Analiza la app y ejecuta el playbook recomendado.

    Modo simple (--script): equivalente a `frida -U -f <pkg> -l <script.js>` pero
    con sesión, captura de logs y soporte de múltiples scripts.

    Modo orquestado (sin --script): detecta RASP y selecciona playbook automático.
    """
    if not FRIDA_AVAILABLE:
        console.print("[red]✗[/red] frida no está instalado. pip install frida frida-tools")
        raise click.Abort()

    cfg = load_config()
    profile = cfg.get_active_profile()
    if not profile:
        console.print("[red]✗[/red] No hay perfil activo.")
        raise click.Abort()

    manager = get_device_manager(profile)
    if not manager.is_connected():
        console.print("[red]✗[/red] Dispositivo no conectado.")
        raise click.Abort()

    # Modo simple: --script
    if scripts:
        _run_with_scripts(
            cfg, profile, manager,
            package_name=package_name,
            script_paths=[Path(s) for s in scripts],
            do_spawn=spawn,
            duration=duration,
        )
        return

    # Modo orquestado (original)
    console.print(f"Analizando [cyan]{package_name}[/cyan]...")

    decision = analyze_and_decide(
        package_name=package_name,
        device_manager=manager,
        platform=profile.platform.value,
        force_playbook=playbook,
        skip_rasp_check=no_rasp_check,
    )

    _decision_summary(decision)

    if not decision.recommended_playbook:
        console.print("\n[red]✗[/red] No hay playbook aplicable. Ejecución abortada.")
        raise click.Abort()

    if not yes:
        if not click.confirm("\n¿Continuar con la ejecución?"):
            console.print("Abortado por el usuario.")
            return

    # Crear sesión
    session_manager = SessionManager(cfg.paths.sessions_dir)
    session = session_manager.create(
        package_name=package_name,
        platform=profile.platform.value,
        profile_name=profile.name,
        playbook_name=decision.recommended_playbook.name,
    )

    if decision.rasp_report and decision.rasp_report.primary_rasp:
        p = decision.rasp_report.primary_rasp
        session.metadata.rasp_detected = {
            "rasp": p.signature.id,
            "name": p.signature.name,
            "confidence": p.confidence,
        }
        session.save_metadata()

    console.print(f"\n[green]Sesión:[/green] [cyan]{session.id}[/cyan]")

    # Inicializar Frida y runner
    frida_manager = FridaManager(profile, manager)

    # Handler que captura mensajes al log de la sesión
    def capture_to_log(script_name, message, data):
        msg_type = message.get("type", "?")
        if msg_type == "send":
            payload = message.get("payload", "")
            session.append_log(
                "frida_output.log",
                f"[{script_name}] {payload}",
            )
        elif msg_type == "log":
            level = message.get("level", "info")
            payload = message.get("payload", "")
            session.append_log(
                "frida_output.log",
                f"[{script_name}][{level}] {payload}",
            )
        elif msg_type == "error":
            session.append_log(
                "frida_output.log",
                f"[{script_name}] ERROR: {message.get('description')}",
            )

    frida_manager.on_message(capture_to_log)

    runner = PlaybookRunner(frida_manager, session)

    try:
        result = runner.run(decision.recommended_playbook, package_name)

        console.print("\n[bold]Resultado:[/bold]")
        for sr in result.scripts_results:
            icon = "[green]✓[/green]" if sr.loaded else "[red]✗[/red]"
            error = f" [red]({sr.error})[/red]" if sr.error else ""
            console.print(f"  {icon} {sr.name}{error}")

        if result.aborted:
            console.print(f"\n[red]Ejecución abortada:[/red] {result.abort_reason}")
        else:
            console.print(
                f"\n[green]✓ Playbook ejecutado.[/green] "
                "La sesión sigue activa. Ctrl+C para detener."
            )
            console.print(
                f"Logs en tiempo real → [dim]{session.path('frida_output.log')}[/dim]"
            )

            # Mantener la sesión viva hasta que el usuario haga Ctrl+C
            try:
                import time
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                console.print("\nDeteniendo...")

    finally:
        frida_manager.detach()
        session.close()
        console.print(f"[green]✓[/green] Sesión cerrada: {session.id}")


def _run_with_scripts(
    cfg,
    profile,
    device_manager,
    package_name: str,
    script_paths: list[Path],
    do_spawn: bool,
    duration: int,
) -> None:
    """Modo simple: carga scripts directos sin orchestrator/playbook.

    Equivalente conceptual a `frida -U -f <pkg> -l script.js` pero con sesión
    de bazzingakit y captura de logs.
    """
    import time

    # Validar headers (warning si falta, no error)
    for sp in script_paths:
        try:
            content = sp.read_text(encoding="utf-8")
            if "@name" not in content[:2000]:
                console.print(
                    f"[yellow]⚠[/yellow] {sp.name} no tiene header @name. "
                    f"Funciona igual, pero conviene añadirlo para registrarlo en el registry."
                )
        except Exception:
            pass

    # Crear sesión
    session_manager = SessionManager(cfg.paths.sessions_dir)
    session = session_manager.create(
        package_name=package_name,
        platform=profile.platform.value,
        profile_name=profile.name,
        playbook_name="manual_scripts",
    )
    console.print(f"[green]Sesión:[/green] [cyan]{session.id}[/cyan]")

    frida_manager = FridaManager(profile, device_manager)

    # Capturar mensajes al log de la sesión
    def capture_to_log(script_name, message, data):
        msg_type = message.get("type", "?")
        if msg_type == "send":
            payload = message.get("payload", "")
            session.append_log("frida_output.log", f"[{script_name}] {payload}")
        elif msg_type == "log":
            level = message.get("level", "info")
            payload = message.get("payload", "")
            session.append_log("frida_output.log", f"[{script_name}][{level}] {payload}")
        elif msg_type == "error":
            session.append_log(
                "frida_output.log", f"[{script_name}] ERROR: {message.get('description')}"
            )

    frida_manager.on_message(capture_to_log)

    pid = None
    try:
        if do_spawn:
            console.print(f"Spawneando [cyan]{package_name}[/cyan]...")
            try:
                pid = frida_manager.spawn(package_name)
            except Exception as e:
                console.print(f"[red]✗[/red] Spawn falló: {e}")
                raise click.Abort()
        else:
            console.print(f"Attach a [cyan]{package_name}[/cyan]...")
            try:
                frida_manager.attach(package_name)
            except Exception as e:
                console.print(f"[red]✗[/red] Attach falló: {e}")
                raise click.Abort()

        # Cargar scripts
        for sp in script_paths:
            try:
                frida_manager.load_script_file(sp, name=sp.stem)
                session.add_script(sp.name)
                console.print(f"  ✓ {sp.name}")
            except Exception as e:
                console.print(f"  [red]✗[/red] {sp.name}: {e}")

        # Resume si spawneamos
        if pid is not None:
            try:
                frida_manager.resume(pid)
            except Exception as e:
                console.print(f"[yellow]⚠[/yellow] Resume falló: {e}")

        console.print(
            f"\n[green]✓[/green] Scripts cargados. La sesión sigue activa."
        )
        console.print(
            f"[dim]Logs en: {session.path('frida_output.log')}[/dim]"
        )

        # Mantener viva
        if duration > 0:
            console.print(f"Esperando {duration}s...")
            time.sleep(duration)
        else:
            console.print("[dim]Ctrl+C para terminar.[/dim]")
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                console.print("\nDeteniendo...")

    finally:
        try:
            frida_manager.detach()
        except Exception:
            pass
        session.close()
        console.print(f"[green]✓[/green] Sesión cerrada: {session.id}")
