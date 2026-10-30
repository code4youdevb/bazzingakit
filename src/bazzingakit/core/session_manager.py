"""Gestión de sesiones de análisis.

Una sesión representa un análisis de una app en un momento determinado.
Cada sesión tiene su directorio con logs, artefactos, y metadata estructurada.
"""

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from bazzingakit.utils import get_logger

log = get_logger(__name__)


@dataclass
class SessionMetadata:
    """Metadata de una sesión."""

    session_id: str
    package_name: str
    platform: str
    profile_name: Optional[str]
    playbook_name: Optional[str]
    started_at: str
    ended_at: Optional[str] = None
    scripts_loaded: list[str] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    rasp_detected: Optional[dict[str, Any]] = None


class Session:
    """Sesión de análisis activa."""

    def __init__(self, session_dir: Path, metadata: SessionMetadata):
        self.session_dir = session_dir
        self.metadata = metadata

    @property
    def id(self) -> str:
        return self.metadata.session_id

    def path(self, filename: str) -> Path:
        """Devuelve ruta a un archivo dentro de la sesión."""
        return self.session_dir / filename

    def artifact_path(self, filename: str) -> Path:
        """Ruta para artefactos (dumps, screenshots, etc.)."""
        artifacts = self.session_dir / "artifacts"
        artifacts.mkdir(exist_ok=True)
        return artifacts / filename

    def append_log(self, log_name: str, content: str) -> None:
        """Appendea contenido a un log de la sesión."""
        log_path = self.session_dir / log_name
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(content)
            if not content.endswith("\n"):
                f.write("\n")

    def add_finding(self, finding: dict[str, Any]) -> None:
        self.metadata.findings.append(finding)
        self.save_metadata()

    def add_script(self, script_name: str) -> None:
        if script_name not in self.metadata.scripts_loaded:
            self.metadata.scripts_loaded.append(script_name)
            self.save_metadata()

    def save_metadata(self) -> None:
        meta_path = self.session_dir / "session.json"
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(asdict(self.metadata), f, indent=2, ensure_ascii=False)

    def close(self) -> None:
        self.metadata.ended_at = datetime.now(timezone.utc).isoformat()
        self.save_metadata()
        log.info(f"Sesión cerrada: {self.id}")


class SessionManager:
    """Factory de sesiones."""

    def __init__(self, sessions_dir: Path):
        self.sessions_dir = sessions_dir
        self.sessions_dir.mkdir(parents=True, exist_ok=True)

    def create(
        self,
        package_name: str,
        platform: str,
        profile_name: Optional[str] = None,
        playbook_name: Optional[str] = None,
    ) -> Session:
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M%S")
        session_id = f"{timestamp}_{package_name}"
        session_dir = self.sessions_dir / session_id
        session_dir.mkdir(parents=True, exist_ok=True)
        (session_dir / "artifacts").mkdir(exist_ok=True)

        metadata = SessionMetadata(
            session_id=session_id,
            package_name=package_name,
            platform=platform,
            profile_name=profile_name,
            playbook_name=playbook_name,
            started_at=datetime.now(timezone.utc).isoformat(),
        )

        session = Session(session_dir, metadata)
        session.save_metadata()
        log.info(f"Sesión creada: {session_id}")
        return session

    def load(self, session_id: str) -> Session:
        """Carga una sesión existente por ID."""
        session_dir = self.sessions_dir / session_id
        if not session_dir.exists():
            raise FileNotFoundError(f"Sesión no encontrada: {session_id}")

        meta_path = session_dir / "session.json"
        with open(meta_path, encoding="utf-8") as f:
            data = json.load(f)

        metadata = SessionMetadata(**data)
        return Session(session_dir, metadata)

    def list_sessions(self) -> list[str]:
        """Lista IDs de todas las sesiones."""
        if not self.sessions_dir.exists():
            return []
        return sorted(
            [d.name for d in self.sessions_dir.iterdir() if d.is_dir()],
            reverse=True,
        )

    def resolve(self, session_ref: str) -> Session:
        """Resuelve una sesión por ID completo, path, o prefijo.

        Permite: 'abc123', '/path/to/session', o 'com.app' (match por prefijo).
        """
        path = Path(session_ref)
        if path.exists() and path.is_dir():
            return self.load(path.name)

        sessions = self.list_sessions()
        if session_ref in sessions:
            return self.load(session_ref)

        # Match por substring (última ocurrencia)
        matches = [s for s in sessions if session_ref in s]
        if len(matches) == 1:
            return self.load(matches[0])
        if len(matches) > 1:
            raise ValueError(
                f"Múltiples sesiones matchean '{session_ref}': {matches[:5]}"
            )

        raise FileNotFoundError(f"Sesión no encontrada: {session_ref}")
