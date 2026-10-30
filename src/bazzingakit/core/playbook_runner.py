"""Modelos de playbook y runner que orquesta la carga de scripts."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel, Field

from bazzingakit.utils import get_logger

from .frida_manager import FridaManager
from .session_manager import Session

log = get_logger(__name__)


class PlaybookScript(BaseModel):
    """Entrada de script dentro de un playbook."""

    name: str
    path: str  # relativa al paquete o absoluta
    order: int = 0
    critical: bool = False
    config: dict = Field(default_factory=dict)


class Playbook(BaseModel):
    """Modelo de un playbook."""

    name: str
    description: str = ""
    platform: str  # android|ios
    spawn_required: bool = False
    warning: Optional[str] = None
    scripts: list[PlaybookScript]
    preflight: list[dict] = Field(default_factory=list)


class PlaybookError(Exception):
    """Error en carga o ejecución de un playbook."""


def load_playbook(path: Path) -> Playbook:
    """Carga un playbook desde YAML."""
    if not path.exists():
        raise PlaybookError(f"Playbook no encontrado: {path}")

    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)

    return Playbook(**data)


def find_builtin_playbook(name: str, platform: Optional[str] = None) -> Optional[Path]:
    """Busca un playbook built-in por nombre.

    Soporta 'standard', 'banking', 'android/standard', 'rasp/promon_shield', etc.
    """
    playbooks_dir = Path(__file__).parent.parent / "playbooks"

    # Si tiene separador, buscar directamente
    if "/" in name:
        direct = playbooks_dir / f"{name}.yaml"
        if direct.exists():
            return direct

    # Buscar en plataforma específica
    if platform:
        candidate = playbooks_dir / platform / f"{name}.yaml"
        if candidate.exists():
            return candidate

    # Buscar en todas las subcarpetas
    for path in playbooks_dir.rglob(f"{name}.yaml"):
        return path

    return None


def list_builtin_playbooks() -> list[Path]:
    """Lista todos los playbooks built-in."""
    playbooks_dir = Path(__file__).parent.parent / "playbooks"
    if not playbooks_dir.exists():
        return []
    return sorted(playbooks_dir.rglob("*.yaml"))


@dataclass
class ScriptExecutionResult:
    """Resultado de cargar un script."""

    name: str
    loaded: bool
    error: Optional[str] = None


@dataclass
class PlaybookExecutionResult:
    """Resultado de ejecutar un playbook completo."""

    playbook_name: str
    package_name: str
    scripts_results: list[ScriptExecutionResult] = field(default_factory=list)
    aborted: bool = False
    abort_reason: Optional[str] = None


class PlaybookRunner:
    """Ejecuta un playbook: carga scripts en orden, maneja fallos críticos."""

    def __init__(self, frida: FridaManager, session: Session):
        self.frida = frida
        self.session = session

    def _resolve_script_path(self, rel_path: str) -> Path:
        """Resuelve path relativo del script al directorio del paquete."""
        if Path(rel_path).is_absolute():
            return Path(rel_path)

        package_root = Path(__file__).parent.parent
        full_path = package_root / rel_path
        if full_path.exists():
            return full_path

        raise PlaybookError(f"Script no encontrado: {rel_path}")

    def run(
        self,
        playbook: Playbook,
        package_name: str,
    ) -> PlaybookExecutionResult:
        """Ejecuta el playbook contra el paquete indicado.

        Flow:
          1. Spawn o attach según spawn_required
          2. Cargar scripts en orden
          3. Si critical falla, abortar
          4. Si spawn, hacer resume al final
        """
        result = PlaybookExecutionResult(
            playbook_name=playbook.name,
            package_name=package_name,
        )

        pid: Optional[int] = None

        log.info(f"Ejecutando playbook '{playbook.name}' contra {package_name}")
        self.session.metadata.playbook_name = playbook.name

        # Spawn o attach
        try:
            if playbook.spawn_required:
                log.info(f"Spawneando {package_name}...")
                pid = self.frida.spawn(package_name)
            else:
                log.info(f"Attach a {package_name}...")
                self.frida.attach(package_name)
        except Exception as e:
            result.aborted = True
            result.abort_reason = f"No se pudo iniciar sesión Frida: {e}"
            log.error(result.abort_reason)
            return result

        # Cargar scripts en orden
        scripts_ordered = sorted(playbook.scripts, key=lambda s: s.order)

        for entry in scripts_ordered:
            try:
                path = self._resolve_script_path(entry.path)
            except PlaybookError as e:
                result.scripts_results.append(
                    ScriptExecutionResult(
                        name=entry.name, loaded=False, error=str(e)
                    )
                )
                if entry.critical:
                    result.aborted = True
                    result.abort_reason = f"Script crítico no encontrado: {entry.name}"
                    break
                continue

            try:
                self.frida.load_script_file(
                    path, name=entry.name, config=entry.config
                )
                result.scripts_results.append(
                    ScriptExecutionResult(name=entry.name, loaded=True)
                )
                self.session.add_script(entry.name)
                log.info(f"  ✓ {entry.name}")
            except Exception as e:
                log.error(f"  ✗ {entry.name}: {e}")
                result.scripts_results.append(
                    ScriptExecutionResult(
                        name=entry.name, loaded=False, error=str(e)
                    )
                )
                if entry.critical:
                    result.aborted = True
                    result.abort_reason = f"Script crítico falló: {entry.name}"
                    break

        # Resume si spawneamos y no abortamos
        if pid is not None and not result.aborted:
            try:
                self.frida.resume(pid)
                log.info(f"App resumida (pid={pid})")
            except Exception as e:
                log.warning(f"Resume falló: {e}")

        self.session.save_metadata()
        return result
