"""Output Analyzer: analiza outputs de Frida/logcat con IA."""

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from bazzingakit.ai.context import Redactor
from bazzingakit.ai.providers import AIProvider
from bazzingakit.core import Session
from bazzingakit.utils import get_logger

log = get_logger(__name__)


@dataclass
class AnalysisResult:
    """Resultado de un análisis de output."""

    content: str
    tokens_in: int
    tokens_out: int
    model: str
    redacted: bool


class OutputAnalyzer:
    """Agente que analiza outputs de sesiones de análisis."""

    # Límite de caracteres de output a enviar (aprox ~25k tokens)
    MAX_OUTPUT_CHARS = 100_000

    def __init__(self, provider: AIProvider, redact: bool = True):
        self.provider = provider
        self.redact = redact
        self.system_prompt = self._load_prompt()

    def _load_prompt(self) -> str:
        prompt_path = Path(__file__).parent.parent / "prompts" / "output_analyzer.md"
        return prompt_path.read_text(encoding="utf-8")

    def _truncate(self, text: str) -> tuple[str, bool]:
        """Trunca output si excede el límite, manteniendo inicio y final."""
        if len(text) <= self.MAX_OUTPUT_CHARS:
            return text, False

        half = self.MAX_OUTPUT_CHARS // 2
        truncated = (
            text[:half]
            + f"\n\n[... truncado {len(text) - self.MAX_OUTPUT_CHARS} caracteres ...]\n\n"
            + text[-half:]
        )
        return truncated, True

    def analyze(
        self,
        output: str,
        context: Optional[str] = None,
    ) -> AnalysisResult:
        """Analiza un output crudo.

        Args:
            output: contenido de logs Frida, logcat, etc.
            context: contexto adicional (package, playbook, findings previos)
        """
        if not output.strip():
            raise ValueError("Output vacío, nada que analizar")

        output_clean = Redactor.clean_if_enabled(output, self.redact)
        output_final, truncated = self._truncate(output_clean)

        context_block = f"\n\n### Contexto de la sesión:\n{context}\n" if context else ""
        truncation_note = (
            "\n\n(NOTA: el output fue truncado por longitud.)" if truncated else ""
        )

        user_message = (
            f"{context_block}"
            f"### Output a analizar:\n```\n{output_final}\n```"
            f"{truncation_note}\n\n"
            "Analiza el output siguiendo el formato indicado en las instrucciones."
        )

        log.info(f"Enviando análisis a {self.provider.name}...")
        response = self.provider.complete(
            system=self.system_prompt,
            user=user_message,
            max_tokens=2000,
        )

        return AnalysisResult(
            content=response.content,
            tokens_in=response.tokens_in,
            tokens_out=response.tokens_out,
            model=response.model,
            redacted=self.redact,
        )

    def analyze_session(self, session: Session) -> AnalysisResult:
        """Analiza una sesión completa leyendo sus logs."""
        frida_log = session.path("frida_output.log")

        if not frida_log.exists():
            raise FileNotFoundError(
                f"No se encontró frida_output.log en la sesión {session.id}. "
                "¿La sesión está vacía?"
            )

        output_content = frida_log.read_text(encoding="utf-8")

        context_parts = [
            f"- Package: {session.metadata.package_name}",
            f"- Plataforma: {session.metadata.platform}",
            f"- Iniciada: {session.metadata.started_at}",
        ]
        if session.metadata.playbook_name:
            context_parts.append(f"- Playbook: {session.metadata.playbook_name}")
        if session.metadata.scripts_loaded:
            context_parts.append(
                f"- Scripts cargados: {', '.join(session.metadata.scripts_loaded)}"
            )
        if session.metadata.rasp_detected:
            context_parts.append(f"- RASP detectado: {session.metadata.rasp_detected}")

        context = "\n".join(context_parts)

        result = self.analyze(output_content, context=context)

        # Guardar en la sesión
        analysis_path = session.path("ai_analysis.md")
        analysis_path.write_text(
            f"# Análisis IA\n\n"
            f"**Modelo:** {result.model}\n"
            f"**Tokens:** {result.tokens_in} in / {result.tokens_out} out\n"
            f"**Redactado:** {result.redacted}\n\n"
            f"---\n\n"
            f"{result.content}\n"
        )
        log.info(f"Análisis guardado en: {analysis_path}")

        return result
