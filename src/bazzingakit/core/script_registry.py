"""Registro de scripts Frida con metadata en headers."""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from bazzingakit.utils import get_logger

log = get_logger(__name__)


@dataclass
class ScriptMetadata:
    """Metadata parseada de un script Frida."""

    name: str
    path: Path
    platform: str = "any"
    category: str = "uncategorized"
    technique: Optional[str] = None
    targets: list[str] = field(default_factory=list)
    author: Optional[str] = None
    version: Optional[str] = None
    description: Optional[str] = None
    generated_by: Optional[str] = None
    extra: dict[str, str] = field(default_factory=dict)

    @property
    def id(self) -> str:
        """ID único: platform/category/name."""
        return f"{self.platform}/{self.category}/{self.name}"


class ScriptParseError(Exception):
    """Error al parsear metadata de un script."""


class ScriptRegistry:
    """Registra e indexa scripts Frida con metadata embebida.

    Formato de header esperado en los .js:

        /**
         * @name Nombre del script
         * @platform android
         * @category ssl_pinning
         * @technique okhttp_certificate_pinner
         * @targets com.squareup.okhttp3.CertificatePinner
         * @author usuario
         * @version 1.0
         * @description Bypass de OkHttp v3 CertificatePinner
         */
    """

    # Campos con múltiples valores separados por coma
    LIST_FIELDS = {"targets"}

    # Regex del bloque de comentario /** ... */
    HEADER_BLOCK_RE = re.compile(r"/\*\*(.*?)\*/", re.DOTALL)

    def __init__(self) -> None:
        self._by_id: dict[str, ScriptMetadata] = {}
        self._by_path: dict[Path, ScriptMetadata] = {}

    def parse_header(self, content: str, path: Path) -> ScriptMetadata:
        """Parsea el primer bloque de comentario del script."""
        match = self.HEADER_BLOCK_RE.search(content[:4000])
        if not match:
            raise ScriptParseError(f"Header no encontrado en {path}")

        header_text = match.group(1)

        # Parsear campos línea por línea, respetando multi-línea hasta el siguiente @
        fields: dict = {}
        current_key: Optional[str] = None
        current_value_lines: list[str] = []

        for raw_line in header_text.splitlines():
            line = raw_line.strip().lstrip("*").strip()
            m = re.match(r"^@(\w+)\s*(.*)$", line)
            if m:
                # Guardar anterior si había uno
                if current_key is not None:
                    fields[current_key] = " ".join(current_value_lines).strip()
                current_key = m.group(1).lower()
                current_value_lines = [m.group(2).strip()]
            elif current_key is not None and line:
                current_value_lines.append(line)

        if current_key is not None:
            fields[current_key] = " ".join(current_value_lines).strip()

        if "name" not in fields:
            raise ScriptParseError(f"Script sin @name: {path}")

        targets = []
        if "targets" in fields:
            targets = [t.strip() for t in fields["targets"].split(",") if t.strip()]

        known = {"name", "platform", "category", "technique", "targets",
                 "author", "version", "description", "generated_by"}
        extra = {k: v for k, v in fields.items() if k not in known}

        return ScriptMetadata(
            name=fields["name"],
            path=path,
            platform=fields.get("platform", "any").lower(),
            category=fields.get("category", "uncategorized").lower(),
            technique=fields.get("technique"),
            targets=targets,
            author=fields.get("author"),
            version=fields.get("version"),
            description=fields.get("description"),
            generated_by=fields.get("generated_by"),
            extra=extra,
        )

    def register(self, metadata: ScriptMetadata) -> None:
        self._by_id[metadata.id] = metadata
        self._by_path[metadata.path] = metadata

    def scan_directory(self, directory: Path, recursive: bool = True) -> int:
        """Escanea un directorio y registra todos los scripts válidos.

        Returns:
            Número de scripts registrados.
        """
        if not directory.exists():
            return 0

        count = 0
        pattern = "**/*.js" if recursive else "*.js"
        for script_path in directory.glob(pattern):
            try:
                content = script_path.read_text(encoding="utf-8")
                metadata = self.parse_header(content, script_path)
                self.register(metadata)
                count += 1
            except ScriptParseError as e:
                log.debug(f"Script sin header válido: {script_path.name} ({e})")
            except Exception as e:
                log.warning(f"Error procesando {script_path}: {e}")

        return count

    def find_by_id(self, script_id: str) -> Optional[ScriptMetadata]:
        return self._by_id.get(script_id)

    def find_by_name(self, name: str) -> list[ScriptMetadata]:
        """Busca scripts por nombre exacto."""
        return [m for m in self._by_id.values() if m.name == name]

    def find(
        self,
        platform: Optional[str] = None,
        category: Optional[str] = None,
        technique: Optional[str] = None,
    ) -> list[ScriptMetadata]:
        """Filtra scripts según criterios."""
        results = list(self._by_id.values())
        if platform:
            results = [r for r in results if r.platform in (platform, "any")]
        if category:
            results = [r for r in results if r.category == category]
        if technique:
            results = [r for r in results if r.technique == technique]
        return results

    def all(self) -> list[ScriptMetadata]:
        return list(self._by_id.values())

    def __len__(self) -> int:
        return len(self._by_id)


def default_registry() -> ScriptRegistry:
    """Crea un registry poblado con scripts built-in y de usuario."""
    from bazzingakit.config import load_config

    registry = ScriptRegistry()

    # Scripts built-in (en el paquete)
    builtin_dir = Path(__file__).parent.parent / "scripts"
    if builtin_dir.exists():
        count = registry.scan_directory(builtin_dir)
        log.debug(f"Built-in scripts registrados: {count}")

    # Scripts de usuario
    try:
        cfg = load_config()
        user_dir = cfg.paths.user_scripts_dir
        if user_dir.exists():
            count = registry.scan_directory(user_dir)
            log.debug(f"User scripts registrados: {count}")
    except Exception as e:
        log.debug(f"No se pudieron cargar scripts de usuario: {e}")

    return registry
