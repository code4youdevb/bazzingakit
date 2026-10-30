"""Detector de RASP y protecciones mediante análisis estático del APK/IPA."""

import re
import subprocess
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

from bazzingakit.utils import get_logger

log = get_logger(__name__)


@dataclass
class RASPSignature:
    """Firma de una protección/RASP cargada desde YAML."""

    id: str
    name: str
    vendor: str
    platforms: list[str]
    libraries: list[str] = field(default_factory=list)
    classes: list[str] = field(default_factory=list)
    strings: list[str] = field(default_factory=list)
    assets: list[str] = field(default_factory=list)
    confidence_weight: float = 0.8
    category: str = "rasp"


@dataclass
class DetectionMatch:
    """Evidencia de coincidencia con una firma."""

    signature: RASPSignature
    matched_libraries: list[str] = field(default_factory=list)
    matched_classes: list[str] = field(default_factory=list)
    matched_strings: list[str] = field(default_factory=list)
    matched_assets: list[str] = field(default_factory=list)
    confidence: float = 0.0

    @property
    def evidence(self) -> list[str]:
        out = []
        for lib in self.matched_libraries:
            out.append(f"Library: {lib}")
        for cls in self.matched_classes:
            out.append(f"Class: {cls}")
        for s in self.matched_strings:
            out.append(f"String: {s}")
        for a in self.matched_assets:
            out.append(f"Asset: {a}")
        return out


@dataclass
class DetectionReport:
    """Resultado del análisis completo."""

    apk_path: Optional[Path]
    package_name: Optional[str]
    matches: list[DetectionMatch] = field(default_factory=list)

    @property
    def rasp_matches(self) -> list[DetectionMatch]:
        return [m for m in self.matches if m.signature.category == "rasp"]

    @property
    def has_rasp(self) -> bool:
        return any(m.confidence >= 0.5 for m in self.rasp_matches)

    @property
    def primary_rasp(self) -> Optional[DetectionMatch]:
        rasps = sorted(self.rasp_matches, key=lambda m: m.confidence, reverse=True)
        return rasps[0] if rasps else None


class RASPDetector:
    """Detección estática de RASPs y protecciones en APKs."""

    def __init__(self, signatures_path: Optional[Path] = None):
        self.signatures = self._load_signatures(signatures_path)

    def _load_signatures(self, path: Optional[Path]) -> list[RASPSignature]:
        if path is None:
            path = Path(__file__).parent.parent / "signatures" / "rasp_signatures.yaml"

        if not path.exists():
            log.warning(f"Archivo de firmas no encontrado: {path}")
            return []

        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        sigs = []
        for sig_id, sig_data in data.items():
            indicators = sig_data.get("indicators", {})
            sigs.append(
                RASPSignature(
                    id=sig_id,
                    name=sig_data.get("name", sig_id),
                    vendor=sig_data.get("vendor", "?"),
                    platforms=sig_data.get("platforms", ["android"]),
                    libraries=indicators.get("libraries", []),
                    classes=indicators.get("classes", []),
                    strings=indicators.get("strings", []),
                    assets=indicators.get("assets", []),
                    confidence_weight=sig_data.get("confidence_weight", 0.8),
                    category=sig_data.get("category", "rasp"),
                )
            )

        log.debug(f"Firmas cargadas: {len(sigs)}")
        return sigs

    def analyze_apk(
        self,
        apk_path: Path,
        package_name: Optional[str] = None,
        platform: str = "android",
    ) -> DetectionReport:
        """Analiza un APK y retorna un reporte de detecciones."""
        if not apk_path.exists():
            raise FileNotFoundError(f"APK no encontrado: {apk_path}")

        report = DetectionReport(apk_path=apk_path, package_name=package_name)

        with zipfile.ZipFile(apk_path) as zf:
            namelist = zf.namelist()
            apk_libraries = self._extract_libraries(namelist)
            apk_assets = self._extract_assets(namelist)
            apk_strings = self._extract_dex_strings(zf, namelist)

        for sig in self.signatures:
            if platform not in sig.platforms:
                continue

            match = DetectionMatch(signature=sig)

            for lib in sig.libraries:
                matched = [l for l in apk_libraries if lib.lower() in l.lower()]
                match.matched_libraries.extend(matched)

            for cls in sig.classes:
                class_pattern = cls.replace(".", "/")
                matched = [s for s in apk_strings if class_pattern in s]
                if matched:
                    match.matched_classes.append(cls)

            for s in sig.strings:
                try:
                    pattern = re.compile(s, re.IGNORECASE)
                    matched = [string for string in apk_strings if pattern.search(string)]
                    if matched:
                        match.matched_strings.append(s)
                except re.error:
                    if any(s.lower() in string.lower() for string in apk_strings):
                        match.matched_strings.append(s)

            for asset in sig.assets:
                matched = [a for a in apk_assets if asset in a]
                match.matched_assets.extend(matched)

            # Calcular confianza
            total_indicators = (
                len(sig.libraries) + len(sig.classes)
                + len(sig.strings) + len(sig.assets)
            )
            matched_indicators = (
                min(len(match.matched_libraries), len(sig.libraries) if sig.libraries else 1)
                + len(match.matched_classes)
                + len(match.matched_strings)
                + min(len(match.matched_assets), len(sig.assets) if sig.assets else 1)
            )

            if total_indicators == 0 or matched_indicators == 0:
                continue

            ratio = matched_indicators / max(total_indicators, 1)
            match.confidence = min(ratio * sig.confidence_weight + 0.3, 1.0)

            if match.matched_libraries or match.matched_classes or match.matched_assets:
                report.matches.append(match)
            elif match.matched_strings and len(match.matched_strings) >= 2:
                report.matches.append(match)

        report.matches.sort(key=lambda m: m.confidence, reverse=True)
        return report

    def _extract_libraries(self, namelist: list[str]) -> list[str]:
        """Extrae nombres de librerías .so del APK."""
        libs = []
        for name in namelist:
            if name.startswith("lib/") and name.endswith(".so"):
                libs.append(Path(name).name)
        return list(set(libs))

    def _extract_assets(self, namelist: list[str]) -> list[str]:
        """Lista assets del APK."""
        return [n for n in namelist if n.startswith("assets/")]

    def _extract_dex_strings(
        self, zf: zipfile.ZipFile, namelist: list[str], max_bytes: int = 50_000_000
    ) -> list[str]:
        """Extrae strings de los DEX del APK (básico, sin decompilar).

        Busca secuencias ASCII imprimibles ≥4 caracteres.
        """
        strings: set[str] = set()
        pattern = re.compile(rb"[\x20-\x7e]{4,}")

        dex_files = [n for n in namelist if n.endswith(".dex")]
        total_read = 0
        for dex_name in dex_files:
            if total_read >= max_bytes:
                break
            try:
                with zf.open(dex_name) as f:
                    data = f.read(max_bytes - total_read)
                    total_read += len(data)
                    for match in pattern.finditer(data):
                        try:
                            s = match.group(0).decode("ascii")
                            if len(s) >= 4:
                                strings.add(s)
                        except UnicodeDecodeError:
                            continue
            except Exception as e:
                log.debug(f"Error leyendo {dex_name}: {e}")

        return list(strings)


def detect_from_device(
    package_name: str, device_manager, detector: Optional[RASPDetector] = None
) -> Optional[DetectionReport]:
    """Pull del APK desde el dispositivo y análisis."""
    detector = detector or RASPDetector()

    apk_path = device_manager.get_apk_path(package_name)
    if not apk_path:
        log.error(f"No se pudo obtener path del APK para {package_name}")
        return None

    with tempfile.TemporaryDirectory() as tmpdir:
        local_path = Path(tmpdir) / "app.apk"
        log.info(f"Descargando APK: {apk_path}")
        pull_result = device_manager.pull(apk_path, str(local_path))
        if not pull_result.ok:
            log.error(f"pull falló: {pull_result.stderr}")
            return None

        return detector.analyze_apk(local_path, package_name=package_name)
