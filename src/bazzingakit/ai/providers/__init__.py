"""Providers de IA."""

import os
from typing import Optional

from bazzingakit.config.models import AIConfig

from .anthropic_provider import AnthropicProvider
from .base import AIProvider, AIResponse


def get_provider(config: AIConfig) -> AIProvider:
    """Factory de providers desde AIConfig."""
    if config.provider == "anthropic":
        api_key = os.environ.get(config.api_key_env, "")
        if not api_key:
            raise ValueError(
                f"Variable de entorno {config.api_key_env} no está definida"
            )
        return AnthropicProvider(api_key=api_key, model=config.model)

    raise ValueError(f"Provider desconocido: {config.provider}")


__all__ = ["AIProvider", "AIResponse", "AnthropicProvider", "get_provider"]
