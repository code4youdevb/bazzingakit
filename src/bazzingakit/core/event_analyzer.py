"""Analizador de eventos en tiempo real del probe reactivo.

Recibe eventos del script Frida y los clasifica en findings estructurados
que luego el Recommender usa para sugerir scripts.
"""

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class Finding:
    """Hallazgo identificado durante el análisis."""

    category: str
    detail: str
    confidence: float = 0.5
    evidence: list[dict] = field(default_factory=list)
    suggested_script_categories: list[str] = field(default_factory=list)


@dataclass
class AnalysisResult:
    """Resultado del análisis completo."""

    total_events: int
    events_by_type: dict[str, int]
    findings: list[Finding]
    rasps_detected: list[str]
    raw_events: list[dict] = field(default_factory=list)


class EventAnalyzer:
    """Clasifica eventos del probe en findings accionables."""

    def __init__(self) -> None:
        self._events: list[dict] = []
        self._rasp_classes: dict[str, list[str]] = defaultdict(list)
        self._exception_types: Counter[str] = Counter()
        self._blocking_strings: list[dict] = []
        self._root_paths: list[str] = []
        self._root_commands: list[str] = []
        self._exits: list[dict] = []
        self._build_props: dict[str, str] = {}

    def ingest(self, event: dict) -> None:
        """Procesa un evento del probe."""
        self._events.append(event)
        evt_type = event.get("event")

        if evt_type == "rasp_indicator":
            rasp = event.get("rasp")
            cls = event.get("class")
            if rasp and cls and cls not in self._rasp_classes[rasp]:
                self._rasp_classes[rasp].append(cls)

        elif evt_type == "exception":
            ex_type = event.get("type", "Unknown")
            self._exception_types[ex_type] += 1
            if event.get("blocking_keyword"):
                self._blocking_strings.append({
                    "source": "exception",
                    "type": ex_type,
                    "message": event.get("message", ""),
                    "keyword": event.get("blocking_keyword"),
                })

        elif evt_type == "ui_text":
            self._blocking_strings.append({
                "source": event.get("widget", "ui"),
                "text": event.get("text", ""),
                "keyword": event.get("blocking_keyword"),
            })

        elif evt_type == "file_exists":
            path = event.get("path")
            if path and path not in self._root_paths:
                self._root_paths.append(path)

        elif evt_type == "runtime_exec":
            cmd = event.get("command")
            if cmd and cmd not in self._root_commands:
                self._root_commands.append(cmd)

        elif evt_type == "system_exit":
            self._exits.append(event)

        elif evt_type == "build_prop":
            for key, val in event.items():
                if key not in ("event", "t") and isinstance(val, str):
                    self._build_props[key] = val

    def analyze(self) -> AnalysisResult:
        """Genera findings desde los eventos acumulados."""
        findings: list[Finding] = []

        # 1. RASPs detectados
        for rasp_id, classes in self._rasp_classes.items():
            findings.append(Finding(
                category="rasp_detected",
                detail=rasp_id,
                confidence=min(0.5 + 0.1 * len(classes), 0.99),
                evidence=[{"class": c} for c in classes[:5]],
                suggested_script_categories=[f"rasp_{rasp_id}"],
            ))

        # 2. SSL pinning (por excepción o uso de OkHttp/TrustManager)
        ssl_exceptions = sum(
            cnt for ex, cnt in self._exception_types.items()
            if "SSL" in ex or "Certificate" in ex or "Trust" in ex
        )
        okhttp_used = any("trustkit" in r or "okhttp" in str(c).lower()
                         for r, classes in self._rasp_classes.items()
                         for c in classes)
        if ssl_exceptions > 0 or okhttp_used:
            findings.append(Finding(
                category="ssl_pinning",
                detail="ssl_exceptions" if ssl_exceptions else "ssl_libraries_present",
                confidence=0.85 if ssl_exceptions else 0.6,
                evidence=[
                    {"exception": ex, "count": cnt}
                    for ex, cnt in self._exception_types.items()
                    if "SSL" in ex or "Certificate" in ex or "Trust" in ex
                ],
                suggested_script_categories=["ssl_pinning"],
            ))

        # 3. Root detection (por File.exists, Runtime.exec)
        if self._root_paths or self._root_commands:
            findings.append(Finding(
                category="root_detection",
                detail="filesystem_or_exec_checks",
                confidence=0.9,
                evidence=(
                    [{"path": p} for p in self._root_paths[:5]]
                    + [{"command": c} for c in self._root_commands[:5]]
                ),
                suggested_script_categories=["root_detection"],
            ))

        # 4. Strings de bloqueo en UI
        ui_blocks = [b for b in self._blocking_strings if b.get("source") != "exception"]
        if ui_blocks:
            findings.append(Finding(
                category="ui_block_string",
                detail="blocking_text_in_ui",
                confidence=0.95,
                evidence=ui_blocks[:5],
                suggested_script_categories=["jailbreak_detection", "anti_kill"],
            ))

        # 5. App se mata a sí misma
        if self._exits:
            findings.append(Finding(
                category="self_kill",
                detail="system_exit_called",
                confidence=0.9,
                evidence=self._exits[:5],
                suggested_script_categories=["anti_kill"],
            ))

        # 6. Detección de emulador
        fp = self._build_props.get("fingerprint", "")
        model = self._build_props.get("model", "")
        if any(s in fp.lower() or s in model.lower()
               for s in ["generic", "sdk", "emulator", "vbox", "nox"]):
            findings.append(Finding(
                category="emulator_indicators",
                detail="suspicious_build_props",
                confidence=0.7,
                evidence=[{"build_prop": k, "value": v}
                         for k, v in self._build_props.items()],
                suggested_script_categories=["emulator_detection"],
            ))

        events_by_type = Counter(e.get("event", "?") for e in self._events)

        return AnalysisResult(
            total_events=len(self._events),
            events_by_type=dict(events_by_type),
            findings=findings,
            rasps_detected=list(self._rasp_classes.keys()),
            raw_events=list(self._events),
        )
