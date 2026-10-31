"""Comando `tui`: lanza la interfaz de texto interactiva."""

import click

from bazzingakit.utils import console


@click.command()
def tui() -> None:
    """Abre la interfaz de texto interactiva (TUI).

    Requiere el extra 'tui':  pip install "bazzingakit[tui]"
    """
    try:
        from bazzingakit.tui import run
    except ImportError:
        console.print(
            "[red]Textual no está instalado.[/red]\n"
            "Instálalo con:\n"
            '  [b]pip install "bazzingakit[tui]"[/b]'
        )
        raise SystemExit(1)

    run()
