"""Comando investigate: loop iterativo de análisis adaptativo + bypass."""

import time
from pathlib import Path
from typing import Optional

import click

from bazzingakit.config import Platform, load_config
from bazzingakit.core import (
    FRIDA_AVAILABLE,
    EventAnalyzer,
    FridaError,
    FridaManager,
    Recommendation,
    Recommender,
    SessionManager,
    get_device_manager,
)
from bazzingakit.utils import console

MAX_ITERATIONS = 5


def _print_findings(result, iteration: int) -> None:
    console.print(f"\n[bold]── Iteración {iteration} — Análisis ──[/bold]")
    console.print(f"Eventos capturados: {result.total_events}")
    if result.events_by_type:
        for ev_type, count in result.events_by_type.items():
            console.print(f"  [dim]{ev_type}: {count}[/dim]")

    if not result.findings:
        console.print("[green]✓ Sin bloqueos detectados.[/green]")
        return

    console.print(f"\n[bold]Hallazgos ({len(result.findings)}):[/bold]")
    for f in result.findings:
        confidence_pct = int(f.confidence * 100)
        icon = "[red]⚠[/red]" if f.confidence > 0.7 else "[yellow]•[/yellow]"
        console.print(
            f"  {icon} [bold]{f.category}[/bold] — {f.detail} "
            f"[dim]({confidence_pct}%)[/dim]"
        )
        for ev in f.evidence[:3]:
            ev_str = ", ".join(f"{k}={v}" for k, v in ev.items() if v)
            console.print(f"      [dim]{ev_str[:120]}[/dim]")


def _print_recommendations(recs: list[Recommendation]) -> None:
    if not recs:
        console.print("[yellow]Sin recomendaciones aplicables (no hay scripts en el registry para los hallazgos).[/yellow]")
        return

    console.print(f"\n[bold]Bypasses recomendados ({len(recs)}):[/bold]")
    for i, rec in enumerate(recs, 1):
        console.print(
            f"  {i}. [cyan]{rec.script.name}[/cyan]  "
            f"[dim](priority {rec.priority})[/dim]"
        )
        console.print(f"     Por: {rec.reason}")


def _run_probe_iteration(
    fm: FridaManager,
    package_name: str,
    bypass_scripts: list[Path],
    iteration: int,
    duration: int,
    use_probe: bool = True,
    keep_alive: bool = False,
) -> tuple[Optional["AnalysisResult"], bool]:
    """Una iteración: spawn → (probe) → bypasses → resume → esperar → matar.

    Args:
        use_probe: si True, carga el probe reactivo. En iteraciones de validación
                   (después de aplicar bypasses) se desactiva para evitar conflictos
                   de hooks duplicados con los bypasses.
        keep_alive: si True, no mata la app al final. Útil en la última iteración
                    para que el usuario pueda usar la app con bypasses cargados.

    Returns:
        (result, app_died_early): result es None si la iteración falló completamente.
                                  app_died_early=True si el proceso murió antes del timeout.
    """
    analyzer = EventAnalyzer()
    received_count = {"n": 0}

    def on_msg(script_name, message, data):
        if message.get("type") != "send":
            return
        payload = message.get("payload")
        if isinstance(payload, dict) and "event" in payload:
            received_count["n"] += 1
            analyzer.ingest(payload)

    console.print(f"\n[bold cyan]Iteración {iteration}:[/bold cyan] spawneando {package_name}...")

    try:
        pid = fm.spawn(package_name)
    except FridaError as e:
        console.print(f"[red]✗[/red] {e}")
        return None, False

    fm.on_message(on_msg)

    # Probe: solo en la primera iteración para descubrir.
    # En iteraciones >1 los bypasses ya están y el probe causaría conflicto de hooks.
    if use_probe:
        probe_path = (
            Path(__file__).parent.parent.parent
            / "scripts" / "android" / "detection" / "reactive_probe.js"
        )
        if not probe_path.exists():
            console.print(f"[red]✗[/red] Probe no encontrado: {probe_path}")
            fm.detach()
            return None, False

        try:
            fm.load_script_file(probe_path, name="probe")
            console.print("  [dim]✓ probe cargado[/dim]")
        except Exception as e:
            console.print(f"[red]✗[/red] No se pudo cargar el probe: {e}")
            fm.detach()
            return None, False

    # Bypasses: si hay múltiples, los concatenamos en un solo script para
    # evitar conflictos de hooks duplicados entre cargas separadas.
    if len(bypass_scripts) == 1:
        script_path = bypass_scripts[0]
        try:
            fm.load_script_file(script_path, name=script_path.stem)
            console.print(f"  ✓ {script_path.name}")
        except Exception as e:
            console.print(f"  [red]✗[/red] {script_path.name}: {e}")
    elif len(bypass_scripts) > 1:
        try:
            combined_source = _combine_scripts(bypass_scripts)
            combined_name = "combined_" + "_".join(p.stem for p in bypass_scripts)[:50]
            fm.load_script(
                source=combined_source,
                name=combined_name,
            )
            console.print(
                f"  ✓ Cargados {len(bypass_scripts)} scripts combinados: "
                + ", ".join(p.name for p in bypass_scripts)
            )
        except Exception as e:
            console.print(f"  [red]✗[/red] Combinación falló: {e}")

    # Resume y esperar
    try:
        fm.resume(pid)
    except Exception as e:
        console.print(f"[yellow]⚠[/yellow] Resume falló: {e}")

    console.print(f"[dim]Observando {duration}s...[/dim]")

    elapsed = 0
    poll_interval = 0.5
    app_died_early = False
    device = None
    try:
        device = fm._get_frida_device()
    except Exception:
        pass

    while elapsed < duration:
        time.sleep(poll_interval)
        elapsed += poll_interval

        if device is not None:
            try:
                processes = device.enumerate_processes()
                still_alive = any(p.pid == pid for p in processes)
                if not still_alive:
                    console.print(f"[yellow]⚠[/yellow] La app terminó tras {elapsed:.1f}s")
                    app_died_early = True
                    break
            except Exception:
                pass

    try:
        fm.detach()
    except Exception:
        pass

    if not app_died_early and not keep_alive and device is not None:
        try:
            device.kill(pid)
        except Exception:
            pass

    return analyzer.analyze(), app_died_early


def _combine_scripts(scripts: list[Path]) -> str:
    """Combina múltiples scripts Frida en un solo source string.

    Cada script se envuelve en un IIFE para aislar declaraciones a nivel top
    (var, const, let, function) y evitar colisiones de nombres entre scripts.
    El IIFE se evalúa con try/catch para que un fallo de uno no rompa los demás.
    """
    parts: list[str] = []
    parts.append(
        "// === Combined bypass scripts (auto-generated by bazzingakit) ===\n"
    )

    for script_path in scripts:
        source = script_path.read_text(encoding="utf-8")
        wrapper = (
            f"\n// ----- {script_path.name} -----\n"
            f"try {{\n"
            f"  (function () {{\n"
            f"{source}\n"
            f"  }})();\n"
            f"}} catch (e) {{\n"
            f"  console.error('[combined] {script_path.stem} failed: ' + e + "
            f"' stack: ' + (e.stack || ''));\n"
            f"}}\n"
        )
        parts.append(wrapper)

    return "\n".join(parts)


def _bisect_scripts(
    profile,
    device_manager,
    package_name: str,
    scripts: list[Path],
    duration: int,
) -> tuple[list[Path], list[Path]]:
    """Prueba cada script aisladamente. Devuelve (que_rompen, seguros)."""
    culprits: list[Path] = []
    safe: list[Path] = []

    test_duration = max(5, duration // 2)  # menos tiempo para ser más rápido

    for script in scripts:
        console.print(f"\n  Probando solo [cyan]{script.name}[/cyan]...")
        fm = FridaManager(profile, device_manager)
        _, died = _run_probe_iteration(
            fm, package_name, [script],
            iteration=999, duration=test_duration,
            use_probe=False, keep_alive=False,
        )
        if died:
            console.print(f"  [red]✗[/red] {script.name} → rompe la app")
            culprits.append(script)
        else:
            console.print(f"  [green]✓[/green] {script.name} → seguro")
            safe.append(script)

    return culprits, safe


@click.command()
@click.argument("package_name")
@click.option("--duration", default=10, help="Segundos de observación por iteración")
@click.option("--max-iterations", default=MAX_ITERATIONS, help="Máximo de iteraciones")
@click.option("--auto-apply", is_flag=True, help="Aplicar todas las recomendaciones sin preguntar")
@click.option(
    "--kill-when-done",
    is_flag=True,
    help="Matar la app al final (por defecto se deja viva con los bypasses cargados)",
)
@click.option(
    "--bisect",
    is_flag=True,
    help="Si la app muere con los bypasses, prueba uno por uno para identificar el culpable",
)
def investigate(
    package_name: str,
    duration: int,
    max_iterations: int,
    auto_apply: bool,
    kill_when_done: bool,
    bisect: bool,
) -> None:
    """Loop iterativo: analiza la app, recomienda bypasses, vuelve a probar.

    Cada iteración:
      1. Spawn de la app con los bypasses acumulados
      2. Probe reactivo observa qué pasa
      3. EventAnalyzer clasifica los hallazgos
      4. Recommender sugiere nuevos bypasses
      5. Si decides aplicarlos, se añaden y se repite

    La sesión se cierra al final con todos los hallazgos guardados.
    """
    if not FRIDA_AVAILABLE:
        console.print("[red]✗[/red] frida no está instalado.")
        raise click.Abort()

    cfg = load_config()
    profile = cfg.get_active_profile()
    if not profile:
        console.print("[red]✗[/red] No hay perfil activo.")
        raise click.Abort()

    if profile.platform != Platform.ANDROID:
        console.print("[yellow]investigate solo soporta Android por ahora.[/yellow]")
        raise click.Abort()

    device_manager = get_device_manager(profile)
    if not device_manager.is_connected():
        console.print("[red]✗[/red] Dispositivo no conectado.")
        raise click.Abort()

    # Crear sesión
    session_manager = SessionManager(cfg.paths.sessions_dir)
    session = session_manager.create(
        package_name=package_name,
        platform="android",
        profile_name=profile.name,
        playbook_name="investigate",
    )
    console.print(f"[green]Sesión:[/green] [cyan]{session.id}[/cyan]")

    recommender = Recommender()
    accumulated_scripts: list[Path] = []
    seen_recommendations: set[str] = set()

    try:
        for iteration in range(1, max_iterations + 1):
            fm = FridaManager(profile, device_manager)
            # Solo iteración 1 usa probe; las siguientes solo cargan bypasses
            # para evitar conflictos de hooks duplicados.
            use_probe = (iteration == 1)
            # En iteraciones de validación (sin probe), si hay bypasses cargados
            # y no se quiere matar al final, dejamos la app viva.
            keep_alive = (not use_probe) and (not kill_when_done)
            result, app_died_early = _run_probe_iteration(
                fm, package_name, accumulated_scripts, iteration, duration,
                use_probe=use_probe, keep_alive=keep_alive,
            )

            if result is None:
                console.print("[red]Iteración falló, abortando.[/red]")
                break

            if use_probe:
                _print_findings(result, iteration)
            else:
                # Iteración de validación: solo nos importa si la app vive
                console.print(f"\n[bold]── Iteración {iteration} — Validación ──[/bold]")
                if app_died_early:
                    console.print("[red]✗ La app murió con los bypasses aplicados.[/red]")
                else:
                    console.print(
                        f"[green]✓ La app se mantuvo viva durante {duration}s con los bypasses.[/green]"
                    )

            # Guardar findings en la sesión
            session.metadata.findings.append({
                "iteration": iteration,
                "events_count": result.total_events,
                "events_by_type": result.events_by_type,
                "app_died_early": app_died_early,
                "findings": [
                    {
                        "category": f.category,
                        "detail": f.detail,
                        "confidence": f.confidence,
                        "evidence_count": len(f.evidence),
                    }
                    for f in result.findings
                ],
            })
            session.save_metadata()

            # En iteraciones de validación (sin probe), solo evaluamos supervivencia
            if not use_probe:
                if app_died_early:
                    console.print(
                        "\n[yellow]Sugerencia:[/yellow] alguno de los bypasses está rompiendo la app."
                    )
                    if bisect and len(accumulated_scripts) > 1:
                        console.print(
                            f"\n[bold cyan]Bisect activo:[/bold cyan] probando los "
                            f"{len(accumulated_scripts)} scripts uno por uno..."
                        )
                        culprits, safe = _bisect_scripts(
                            profile, device_manager, package_name,
                            accumulated_scripts, duration,
                        )
                        if culprits:
                            console.print("\n[bold red]Scripts que rompen la app:[/bold red]")
                            for c in culprits:
                                console.print(f"  ✗ {c.name}")
                        if safe:
                            console.print("\n[bold green]Scripts seguros:[/bold green]")
                            for s in safe:
                                console.print(f"  ✓ {s.name}")
                            console.print(
                                "\n[dim]Re-ejecuta con solo los scripts seguros, "
                                "o investiga manualmente los que rompen.[/dim]"
                            )
                    else:
                        console.print(
                            "Pruébalos uno por uno manualmente para identificar cuál:\n"
                            f"  [dim]frida -U -f {package_name} -l <script.js>[/dim]\n"
                            f"[dim]o relanza con --bisect[/dim]"
                        )
                else:
                    console.print(
                        "\n[bold green]✓ Todo bien.[/bold green] Los bypasses aplicados funcionan."
                    )
                    if keep_alive and not app_died_early:
                        console.print(
                            "[dim]La app sigue corriendo en el dispositivo con los hooks activos. "
                            "Úsala normalmente.[/dim]"
                        )
                break

            # Si no hay findings, evaluar si fue por éxito o por crash silencioso
            if not result.findings:
                if app_died_early and result.total_events < 5:
                    console.print(
                        "\n[red]⚠ La app crasheó antes de generar eventos.[/red]\n"
                        "[yellow]No es 'limpia' — probablemente tiene detección que mata el proceso silenciosamente.[/yellow]\n"
                        "[dim]Considera añadir manualmente bypasses anti-detección o revisar logcat del dispositivo.[/dim]"
                    )
                else:
                    console.print("\n[bold green]✓ La app funciona limpia con los bypasses actuales.[/bold green]")
                break

            # Recomendar
            recommendations = recommender.recommend(result)
            new_recs = [r for r in recommendations if r.script.id not in seen_recommendations]

            if not new_recs:
                console.print(
                    "\n[yellow]Sin recomendaciones nuevas para esta iteración.[/yellow]\n"
                    "[dim]Los hallazgos persisten pero no hay scripts adicionales en el registry.[/dim]"
                )
                break

            _print_recommendations(new_recs)

            if iteration >= max_iterations:
                console.print(f"[yellow]Alcanzado max_iterations ({max_iterations}). Terminando.[/yellow]")
                break

            # Decidir qué aplicar
            if auto_apply:
                to_apply = new_recs
                console.print("\n[dim]--auto-apply activo, aplicando todas...[/dim]")
            else:
                if not click.confirm("\n¿Aplicar estas recomendaciones y volver a probar?"):
                    console.print("[yellow]Loop terminado por el usuario.[/yellow]")
                    break
                to_apply = new_recs

            for rec in to_apply:
                accumulated_scripts.append(rec.script.path)
                seen_recommendations.add(rec.script.id)
                session.add_script(rec.script.name)

    finally:
        session.close()
        console.print(f"\n[green]✓ Sesión cerrada:[/green] {session.id}")
        console.print(f"[dim]Findings y eventos en: {session.session_dir}[/dim]")
