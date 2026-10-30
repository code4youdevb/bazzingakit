"""Redacción de datos sensibles antes de enviar a IA externa."""

import re


class Redactor:
    """Redacta información sensible en texto."""

    # Patrones ordenados: los más específicos primero
    PATTERNS: list[tuple[str, str]] = [
        # Paths con usuario
        (r"/home/[^/\s]+", "/home/USER"),
        (r"/Users/[^/\s]+", "/Users/USER"),
        (r"C:\\Users\\[^\\]+", r"C:\\Users\\USER"),
        # IPs privadas
        (
            r"\b(?:10|127|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}(?:\.\d{1,3})?\b",
            "X.X.X.X",
        ),
        # MAC addresses
        (r"\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\b", "XX:XX:XX:XX:XX:XX"),
        # Credenciales con formato key=value
        (
            r'(?i)(api[_-]?key|password|passwd|secret|token|bearer)["\']?\s*[:=]\s*["\']?([^"\'\s,}]{6,})',
            r"\1=[REDACTED]",
        ),
        # JWT tokens (3 segmentos base64 separados por .)
        (
            r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b",
            "[JWT_REDACTED]",
        ),
        # Strings hex muy largos (posibles llaves o hashes)
        (r"\b[a-fA-F0-9]{64,}\b", "[HEX_REDACTED]"),
    ]

    @classmethod
    def clean(cls, text: str) -> str:
        """Aplica todos los patrones de redacción."""
        for pattern, replacement in cls.PATTERNS:
            text = re.sub(pattern, replacement, text)
        return text

    @classmethod
    def clean_if_enabled(cls, text: str, enabled: bool) -> str:
        return cls.clean(text) if enabled else text
