"""Modelos de configuración."""

from enum import Enum
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field


class Platform(str, Enum):
    ANDROID = "android"
    IOS = "ios"


class DeviceProfile(BaseModel):
    """Perfil de dispositivo (Android emulador, físico, o iOS)."""

    name: str
    platform: Platform

    # Android
    adb_path: Optional[str] = None
    adb_host: str = "127.0.0.1"
    adb_port: int = 5037
    device_serial: Optional[str] = None

    # iOS
    ssh_host: Optional[str] = None
    ssh_port: int = 22
    ssh_user: str = "root"
    ssh_key: Optional[str] = None

    # Frida
    frida_server_path: str = "/data/local/tmp/frida-server"
    frida_port: int = 27042


class AIConfig(BaseModel):
    """Configuración del módulo IA."""

    enabled: bool = False
    provider: str = "anthropic"
    model: str = "claude-opus-4-7"
    api_key_env: str = "ANTHROPIC_API_KEY"

    max_tokens: int = 2000
    max_requests_per_session: int = 50
    redact_sensitive: bool = True


class PathsConfig(BaseModel):
    """Rutas del framework."""

    config_dir: Path = Field(default_factory=lambda: Path.home() / ".bazzingakit")
    sessions_dir: Path = Field(
        default_factory=lambda: Path.home() / ".bazzingakit" / "sessions"
    )
    user_scripts_dir: Path = Field(
        default_factory=lambda: Path.home() / ".bazzingakit" / "scripts"
    )


class BazzingakitConfig(BaseModel):
    """Configuración raíz."""

    active_profile: Optional[str] = None
    profiles: dict[str, DeviceProfile] = Field(default_factory=dict)
    ai: AIConfig = Field(default_factory=AIConfig)
    paths: PathsConfig = Field(default_factory=PathsConfig)

    log_level: str = "INFO"

    def get_active_profile(self) -> Optional[DeviceProfile]:
        if self.active_profile and self.active_profile in self.profiles:
            return self.profiles[self.active_profile]
        return None
