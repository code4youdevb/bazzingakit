"""Interfaz abstracta para providers de IA."""

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class AIResponse:
    content: str
    tokens_in: int
    tokens_out: int
    model: str


class AIProvider(ABC):
    """Interfaz que todo provider de IA debe implementar."""

    @abstractmethod
    def complete(self, system: str, user: str, max_tokens: int = 2000) -> AIResponse:
        """Completa un prompt y devuelve la respuesta."""
        ...

    @abstractmethod
    def test_connection(self) -> bool:
        """Verifica que el provider funcione (API key válida, modelo accesible)."""
        ...

    @property
    @abstractmethod
    def name(self) -> str:
        ...
