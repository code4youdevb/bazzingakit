"""Provider de Anthropic (Claude)."""

from typing import Optional

import anthropic

from bazzingakit.utils import get_logger

from .base import AIProvider, AIResponse

log = get_logger(__name__)


class AnthropicProvider(AIProvider):
    """Provider para API de Anthropic."""

    def __init__(self, api_key: str, model: str = "claude-opus-4-7"):
        if not api_key:
            raise ValueError("API key de Anthropic requerida")
        self._client = anthropic.Anthropic(api_key=api_key)
        self._model = model

    @property
    def name(self) -> str:
        return f"anthropic:{self._model}"

    def complete(self, system: str, user: str, max_tokens: int = 2000) -> AIResponse:
        try:
            response = self._client.messages.create(
                model=self._model,
                max_tokens=max_tokens,
                system=system,
                messages=[{"role": "user", "content": user}],
            )
        except anthropic.APIError as e:
            log.error(f"Error API Anthropic: {e}")
            raise

        text = ""
        for block in response.content:
            if block.type == "text":
                text += block.text

        return AIResponse(
            content=text,
            tokens_in=response.usage.input_tokens,
            tokens_out=response.usage.output_tokens,
            model=self._model,
        )

    def test_connection(self) -> bool:
        try:
            self.complete(
                system="You are a test assistant.",
                user="Reply with exactly: OK",
                max_tokens=10,
            )
            return True
        except Exception as e:
            log.error(f"Test de conexión falló: {e}")
            return False
