"""Recommender: mapea findings del EventAnalyzer a scripts a aplicar."""

from dataclasses import dataclass, field
from typing import Optional

from .event_analyzer import AnalysisResult, Finding
from .script_registry import ScriptMetadata, ScriptRegistry, default_registry


@dataclass
class Recommendation:
    """Recomendación de un script para abordar un finding."""

    script: ScriptMetadata
    reason: str
    related_findings: list[str] = field(default_factory=list)
    priority: int = 5  # 1=más urgente, 10=menos


# Mapeo: categoría sugerida del finding → categoría real en ScriptMetadata
CATEGORY_ALIASES: dict[str, list[str]] = {
    "ssl_pinning": ["ssl_pinning"],
    "root_detection": ["root_detection"],
    "jailbreak_detection": ["jailbreak_detection"],
    "anti_kill": ["anti_kill"],
    "emulator_detection": ["emulator_detection"],
    # RASP-specific (futuro: scripts en categorías rasp_<id>)
}


class Recommender:
    """Sugiere scripts en base a los findings del EventAnalyzer."""

    def __init__(self, registry: Optional[ScriptRegistry] = None):
        self.registry = registry or default_registry()

    def recommend(self, result: AnalysisResult) -> list[Recommendation]:
        """Devuelve lista ordenada de recomendaciones, sin duplicar scripts."""
        recommendations: dict[str, Recommendation] = {}

        for finding in result.findings:
            scripts = self._scripts_for_finding(finding)
            for script in scripts:
                if script.id in recommendations:
                    # Ya recomendado por otro finding, añadir referencia
                    recommendations[script.id].related_findings.append(finding.detail)
                    continue

                priority = self._priority_for_finding(finding)
                recommendations[script.id] = Recommendation(
                    script=script,
                    reason=f"{finding.category}: {finding.detail}",
                    related_findings=[finding.detail],
                    priority=priority,
                )

        return sorted(recommendations.values(), key=lambda r: r.priority)

    def _scripts_for_finding(self, finding: Finding) -> list[ScriptMetadata]:
        """Busca scripts en el registry que matcheen las categorías sugeridas."""
        scripts: list[ScriptMetadata] = []

        for category in finding.suggested_script_categories:
            real_categories = CATEGORY_ALIASES.get(category, [category])
            for real_cat in real_categories:
                matches = self.registry.find(
                    platform="android",  # TODO: hacer cross-platform
                    category=real_cat,
                )
                scripts.extend(matches)

        return scripts

    def _priority_for_finding(self, finding: Finding) -> int:
        """Asigna prioridad de carga (los críticos primero)."""
        priority_map = {
            "self_kill": 1,         # blocker absoluto
            "ui_block_string": 2,
            "rasp_detected": 3,
            "root_detection": 4,
            "jailbreak_detection": 4,
            "ssl_pinning": 5,
            "emulator_indicators": 6,
        }
        return priority_map.get(finding.category, 7)
