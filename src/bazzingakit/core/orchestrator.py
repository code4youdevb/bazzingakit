"""Orchestrator: conecta análisis RASP con selección automática de playbook."""

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from bazzingakit.utils import get_logger

from .device_manager import DeviceManager
from .playbook_runner import (
    Playbook,
    find_builtin_playbook,
    load_playbook,
)
from .rasp_detector import DetectionReport, RASPDetector, detect_from_device

log = get_logger(__name__)


@dataclass
class AnalysisDecision:
    """Decisión del orchestrator tras analizar una app."""

    rasp_report: Optional[DetectionReport]
    recommended_playbook: Optional[Playbook]
    playbook_source: str  # 'standard', 'rasp_specific', 'research', 'unknown_rasp'
    reason: str
    warnings: list[str]


# Mapeo de RASP ID → playbook file (esperado bajo playbooks/rasp/)
RASP_PLAYBOOK_MAP: dict[str, str] = {
    "promon_shield": "rasp/promon_shield",
    "guardsquare_dexguard": "rasp/dexguard",
    "guardsquare_ixguard": "rasp/ixguard",
    "appdome": "rasp/appdome",
    "talsec_freerasp": "rasp/talsec",
    "zimperium": "rasp/zimperium",
    "build38_tak": "rasp/build38",
}


def analyze_and_decide(
    package_name: str,
    device_manager: DeviceManager,
    platform: str,
    detector: Optional[RASPDetector] = None,
    force_playbook: Optional[str] = None,
    skip_rasp_check: bool = False,
) -> AnalysisDecision:
    """Flujo de decisión completo.

    1. Si force_playbook: usarlo (con warning si detecta RASP y no es aware).
    2. Si skip_rasp_check: usar playbook standard de la plataforma.
    3. Correr RASP detection.
    4. Seleccionar playbook según resultado.
    """
    warnings: list[str] = []

    # Caso: playbook forzado por usuario
    if force_playbook:
        path = find_builtin_playbook(force_playbook, platform=platform)
        if not path:
            return AnalysisDecision(
                rasp_report=None,
                recommended_playbook=None,
                playbook_source="unknown",
                reason=f"Playbook '{force_playbook}' no encontrado",
                warnings=warnings,
            )
        pb = load_playbook(path)
        return AnalysisDecision(
            rasp_report=None,
            recommended_playbook=pb,
            playbook_source="forced",
            reason=f"Playbook forzado por usuario: {pb.name}",
            warnings=warnings,
        )

    # Caso: skip RASP check
    if skip_rasp_check:
        path = find_builtin_playbook(f"standard_{platform}", platform=platform)
        if not path:
            return AnalysisDecision(
                rasp_report=None,
                recommended_playbook=None,
                playbook_source="unknown",
                reason="Playbook 'standard' no encontrado",
                warnings=warnings,
            )
        return AnalysisDecision(
            rasp_report=None,
            recommended_playbook=load_playbook(path),
            playbook_source="standard",
            reason="RASP check saltado, usando playbook standard",
            warnings=warnings,
        )

    # Detección RASP
    log.info(f"Analizando RASP en {package_name}...")
    report = detect_from_device(package_name, device_manager, detector=detector)

    if report is None:
        return AnalysisDecision(
            rasp_report=None,
            recommended_playbook=None,
            playbook_source="unknown",
            reason="No se pudo obtener el APK del dispositivo",
            warnings=warnings,
        )

    # Sin RASP detectado → standard
    if not report.has_rasp:
        path = find_builtin_playbook(f"standard_{platform}", platform=platform)
        if not path:
            return AnalysisDecision(
                rasp_report=report,
                recommended_playbook=None,
                playbook_source="unknown",
                reason="Sin RASP detectado pero playbook standard no disponible",
                warnings=warnings,
            )
        return AnalysisDecision(
            rasp_report=report,
            recommended_playbook=load_playbook(path),
            playbook_source="standard",
            reason="No se detectó RASP, usando playbook standard",
            warnings=warnings,
        )

    # RASP detectado
    primary = report.primary_rasp
    if primary is None:
        return AnalysisDecision(
            rasp_report=report,
            recommended_playbook=None,
            playbook_source="unknown_rasp",
            reason="Detección ambigua de RASP",
            warnings=warnings,
        )

    rasp_id = primary.signature.id
    playbook_name = RASP_PLAYBOOK_MAP.get(rasp_id)

    if not playbook_name:
        warnings.append(
            f"RASP detectado ({primary.signature.name}) pero sin playbook específico disponible."
        )
        return AnalysisDecision(
            rasp_report=report,
            recommended_playbook=None,
            playbook_source="unknown_rasp",
            reason=f"{primary.signature.name} detectado sin playbook específico",
            warnings=warnings,
        )

    path = find_builtin_playbook(playbook_name, platform=platform)
    if not path:
        warnings.append(
            f"Playbook '{playbook_name}' mapeado a {rasp_id} pero archivo no existe"
        )
        return AnalysisDecision(
            rasp_report=report,
            recommended_playbook=None,
            playbook_source="unknown_rasp",
            reason=f"{primary.signature.name} detectado, playbook file no disponible",
            warnings=warnings,
        )

    return AnalysisDecision(
        rasp_report=report,
        recommended_playbook=load_playbook(path),
        playbook_source="rasp_specific",
        reason=f"{primary.signature.name} detectado (confianza {primary.confidence:.0%})",
        warnings=warnings,
    )
