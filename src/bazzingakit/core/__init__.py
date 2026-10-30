"""Lógica principal del framework."""

from bazzingakit.config.models import DeviceProfile, Platform

from .adb_manager import ADBError, ADBManager
from .burp_proxy import BurpProxyError, BurpProxyManager, CertInfo
from .device_manager import CommandResult, DeviceInfo, DeviceManager
from .event_analyzer import AnalysisResult, EventAnalyzer, Finding
from .frida_manager import FRIDA_AVAILABLE, FridaError, FridaManager, LoadedScript
from .ios_manager import IOSError, IOSManager
from .orchestrator import AnalysisDecision, analyze_and_decide
from .playbook_runner import (
    Playbook,
    PlaybookError,
    PlaybookExecutionResult,
    PlaybookRunner,
    PlaybookScript,
    ScriptExecutionResult,
    find_builtin_playbook,
    list_builtin_playbooks,
    load_playbook,
)
from .rasp_detector import (
    DetectionMatch,
    DetectionReport,
    RASPDetector,
    RASPSignature,
    detect_from_device,
)
from .recommender import Recommendation, Recommender
from .script_registry import (
    ScriptMetadata,
    ScriptParseError,
    ScriptRegistry,
    default_registry,
)
from .session_manager import Session, SessionManager, SessionMetadata


def get_device_manager(profile: DeviceProfile) -> DeviceManager:
    """Factory: devuelve el DeviceManager apropiado según la plataforma del perfil."""
    if profile.platform == Platform.ANDROID:
        return ADBManager(profile)
    elif profile.platform == Platform.IOS:
        return IOSManager(profile)
    raise ValueError(f"Plataforma no soportada: {profile.platform}")


__all__ = [
    "ADBError",
    "ADBManager",
    "BurpProxyError",
    "BurpProxyManager",
    "CertInfo",
    "CommandResult",
    "DeviceInfo",
    "DeviceManager",
    "IOSError",
    "IOSManager",
    "get_device_manager",
    "FRIDA_AVAILABLE",
    "FridaError",
    "FridaManager",
    "LoadedScript",
    "ScriptMetadata",
    "ScriptParseError",
    "ScriptRegistry",
    "default_registry",
    "DetectionMatch",
    "DetectionReport",
    "RASPDetector",
    "RASPSignature",
    "detect_from_device",
    "AnalysisResult",
    "EventAnalyzer",
    "Finding",
    "Recommendation",
    "Recommender",
    "Playbook",
    "PlaybookError",
    "PlaybookExecutionResult",
    "PlaybookRunner",
    "PlaybookScript",
    "ScriptExecutionResult",
    "find_builtin_playbook",
    "list_builtin_playbooks",
    "load_playbook",
    "Session",
    "SessionManager",
    "SessionMetadata",
]
