"""Logging global con Rich para output bonito."""

import logging
from typing import Optional

from rich.console import Console
from rich.logging import RichHandler

console = Console()
_configured = False


def setup_logging(level: str = "INFO", log_file: Optional[str] = None) -> None:
    """Configura logging global. Idempotente."""
    global _configured
    if _configured:
        return

    handlers: list[logging.Handler] = [
        RichHandler(
            console=console,
            rich_tracebacks=True,
            show_path=False,
            show_time=True,
            markup=True,
        )
    ]

    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(
            logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        )
        handlers.append(file_handler)

    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=handlers,
    )

    # Silenciar libs ruidosas
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("anthropic").setLevel(logging.WARNING)

    _configured = True


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
