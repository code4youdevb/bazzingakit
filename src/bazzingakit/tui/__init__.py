"""Interfaz de texto (TUI) de bazzingakit, construida con Textual.

Es una capa de presentación sobre `bazzingakit.core`: no contiene lógica de
análisis propia, solo consume los managers y dataclasses del core y los muestra
de forma interactiva.
"""

from .app import BazzingakitTUI, run

__all__ = ["BazzingakitTUI", "run"]
