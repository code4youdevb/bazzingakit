"""Comando `doctor`: diagnóstico integral del entorno."""

import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import Callable, Optional

import click

from bazzingakit import __version__
from bazzingakit.config import Platform, load_config
from bazzingakit.core import get_device_manager
from bazzingakit.utils import console


@dataclass
class CheckResult:
    """Resultado de un check individual."""

    name: str
    ok: bool
    message: str = ""
    hint: Optional[str] = None


def _icon(ok: bool) -> str:
    return "[green]✓[/green]" if ok else "[red]✗[/red]"


def _check_binary(name: str, version_flag: str = "--version") -> CheckResult:
    """Verifica que un binario esté disponible en PATH."""
    path = shutil.which(name)
    if not path:
        return CheckResult(
            name=name,
            ok=False,
            message="no encontrado en PATH",
            hint=f"Instala {name} o asegúrate de que esté en tu PATH",
        )
    try:
        result = subprocess.run(
            [name, version_flag],
            capture_output=True,
            text=True,
            timeout=5,
        )
        version = (result.stdout or result.stderr).strip().splitlines()[0][:60]
        return CheckResult(name=name, ok=True, message=f"{version} ({path})")
    except Exception as e:
        return CheckResult(name=name, ok=False, message=str(e))


def _check_python_package(module: str) -> CheckResult:
    """Verifica que un paquete Python esté instalado."""
    try:
        mod = __import__(module)
        version = getattr(mod, "__version__", "?")
        return CheckResult(name=module, ok=True, message=f"v{version}")
    except ImportError as e:
        return CheckResult(
            name=module,
            ok=False,
            message=str(e),
            hint=f"pip install {module}",
        )


def _run_checks(title: str, checks: list[Callable[[], CheckResult]]) -> list[CheckResult]:
    """Corre una sección de checks e imprime resultados."""
    console.print(f"\n[bold cyan]▸ {title}[/bold cyan]")
    results = []
    for check_fn in checks:
        result = check_fn()
        results.append(result)
        icon = _icon(result.ok)
        console.print(f"  {icon} [bold]{result.name}[/bold]  [dim]{result.message}[/dim]")
        if result.hint and not result.ok:
            console.print(f"      [yellow]hint:[/yellow] {result.hint}")
    return results


@click.command()
@click.option("--skip-device", is_flag=True, help="Omitir checks del dispositivo")
@click.option("--skip-ai", is_flag=True, help="Omitir checks del módulo IA")
def doctor(skip_device: bool, skip_ai: bool) -> None:
    """Diagnóstico integral del entorno bazzingakit."""
    console.print(f"[bold]bazzingakit doctor[/bold]  [dim]v{__version__}[/dim]")

    all_results: list[CheckResult] = []

    # -- System tools --
    system_checks = [
        lambda: _check_binary("python3"),
        lambda: _check_binary("adb"),
        lambda: _check_binary("ssh", version_flag="-V"),
        lambda: _check_binary("frida", version_flag="--version"),
    ]
    all_results.extend(_run_checks("System tools", system_checks))

    # -- Python packages --
    pkg_checks = [
        lambda: _check_python_package("click"),
        lambda: _check_python_package("pydantic"),
        lambda: _check_python_package("yaml"),
        lambda: _check_python_package("rich"),
        lambda: _check_python_package("anthropic"),
        lambda: _check_python_package("frida"),
    ]
    all_results.extend(_run_checks("Python packages", pkg_checks))

    # -- Config --
    def check_config() -> CheckResult:
        try:
            cfg = load_config()
            profile_count = len(cfg.profiles)
            active = cfg.active_profile
            if profile_count == 0:
                return CheckResult(
                    name="config",
                    ok=False,
                    message="no hay perfiles configurados",
                    hint="bazzingakit config add-profile <name> --platform android ...",
                )
            return CheckResult(
                name="config",
                ok=True,
                message=f"{profile_count} perfiles, activo: {active}",
            )
        except Exception as e:
            return CheckResult(name="config", ok=False, message=str(e))

    all_results.extend(_run_checks("Configuración", [check_config]))

    # -- Perfil activo + device --
    if not skip_device:
        cfg = load_config()
        profile = cfg.get_active_profile()

        if not profile:
            console.print(
                "\n[bold cyan]▸ Dispositivo[/bold cyan]\n"
                "  [yellow]⚠[/yellow]  No hay perfil activo, saltando checks de dispositivo."
            )
        else:
            def check_device_tools() -> CheckResult:
                manager = get_device_manager(profile)
                if manager.is_available():
                    return CheckResult(
                        name=f"{manager.platform} tools",
                        ok=True,
                        message="disponible",
                    )
                return CheckResult(
                    name=f"{manager.platform} tools",
                    ok=False,
                    message="adb/ssh no disponible",
                    hint="Verifica las rutas en el perfil con 'bazzingakit config show'",
                )

            def check_device_connected() -> CheckResult:
                manager = get_device_manager(profile)
                if manager.is_connected():
                    info = manager.get_device_info()
                    details = []
                    if info:
                        if info.model:
                            details.append(info.model)
                        if info.os_version:
                            details.append(f"OS {info.os_version}")
                        if info.arch:
                            details.append(info.arch)
                        if info.is_rooted:
                            details.append("rooted/jailbroken")
                    return CheckResult(
                        name="dispositivo",
                        ok=True,
                        message=", ".join(details) if details else "conectado",
                    )
                return CheckResult(
                    name="dispositivo",
                    ok=False,
                    message="no conectado",
                    hint=(
                        "Arranca el emulador o conecta el dispositivo. "
                        "Prueba: bazzingakit config test"
                    ),
                )

            def check_frida_server() -> CheckResult:
                manager = get_device_manager(profile)
                if not manager.is_connected():
                    return CheckResult(
                        name="frida-server",
                        ok=False,
                        message="dispositivo no conectado",
                    )
                if profile.platform == Platform.ANDROID:
                    result = manager.shell("pgrep -f frida-server || echo NO", timeout=5)
                    if result.ok and "NO" not in result.stdout:
                        return CheckResult(
                            name="frida-server",
                            ok=True,
                            message="corriendo",
                        )
                    return CheckResult(
                        name="frida-server",
                        ok=False,
                        message="no está corriendo en el dispositivo",
                        hint="bazzingakit frida setup  (o frida start si ya está instalado)",
                    )
                else:  # iOS
                    result = manager.shell(
                        "ps aux 2>/dev/null | grep -i frida | grep -v grep || echo NO",
                        timeout=5,
                    )
                    if result.ok and "NO" not in result.stdout and "frida" in result.stdout.lower():
                        return CheckResult(
                            name="frida-server",
                            ok=True,
                            message="corriendo",
                        )
                    return CheckResult(
                        name="frida-server",
                        ok=False,
                        message="no detectado en el dispositivo",
                        hint="Instala frida desde Cydia/Sileo",
                    )

            device_checks = [
                check_device_tools,
                check_device_connected,
                check_frida_server,
            ]
            all_results.extend(
                _run_checks(f"Dispositivo ({profile.name})", device_checks)
            )

    # -- IA --
    if not skip_ai:
        def check_ai_config() -> CheckResult:
            cfg = load_config()
            if not cfg.ai.enabled:
                return CheckResult(
                    name="AI enabled",
                    ok=False,
                    message="deshabilitada (opcional)",
                    hint="bazzingakit ai setup",
                )
            return CheckResult(
                name="AI enabled",
                ok=True,
                message=f"{cfg.ai.provider}/{cfg.ai.model}",
            )

        def check_ai_key() -> CheckResult:
            cfg = load_config()
            if not cfg.ai.enabled:
                return CheckResult(name="AI API key", ok=True, message="skip")
            if os.environ.get(cfg.ai.api_key_env):
                return CheckResult(
                    name="AI API key",
                    ok=True,
                    message=f"${cfg.ai.api_key_env} presente",
                )
            return CheckResult(
                name="AI API key",
                ok=False,
                message=f"${cfg.ai.api_key_env} no definida",
                hint=f"export {cfg.ai.api_key_env}=...",
            )

        all_results.extend(_run_checks("Módulo IA", [check_ai_config, check_ai_key]))

    # -- Resumen --
    total = len(all_results)
    passed = sum(1 for r in all_results if r.ok)
    failed = total - passed

    console.print()
    if failed == 0:
        console.print(
            f"[bold green]✓ Todo en orden ({passed}/{total} checks OK)[/bold green]"
        )
    else:
        console.print(
            f"[bold yellow]⚠ {passed}/{total} checks OK, "
            f"{failed} requieren atención[/bold yellow]"
        )
