"""Interfaz abstracta para gestión de dispositivos."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional


@dataclass
class DeviceInfo:
    """Información básica del dispositivo."""

    platform: str
    identifier: str  # serial para Android, host para iOS
    model: Optional[str] = None
    os_version: Optional[str] = None
    arch: Optional[str] = None  # arm64, x86_64, etc.
    is_rooted: Optional[bool] = None
    is_online: bool = False


@dataclass
class CommandResult:
    """Resultado de ejecutar un comando en el dispositivo."""

    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


class DeviceManager(ABC):
    """Interfaz común para Android e iOS."""

    @abstractmethod
    def is_available(self) -> bool:
        """Verifica si las herramientas necesarias están disponibles (adb/ssh)."""
        ...

    @abstractmethod
    def is_connected(self) -> bool:
        """Verifica si hay al menos un dispositivo conectado/alcanzable."""
        ...

    @abstractmethod
    def list_devices(self) -> list[DeviceInfo]:
        """Lista dispositivos disponibles."""
        ...

    @abstractmethod
    def get_device_info(self) -> Optional[DeviceInfo]:
        """Devuelve info del dispositivo activo (el del perfil)."""
        ...

    @abstractmethod
    def shell(self, command: str, timeout: int = 10) -> CommandResult:
        """Ejecuta un comando en el dispositivo."""
        ...

    @abstractmethod
    def push(self, local: str, remote: str) -> CommandResult:
        """Sube un archivo al dispositivo."""
        ...

    @abstractmethod
    def pull(self, remote: str, local: str) -> CommandResult:
        """Descarga un archivo del dispositivo."""
        ...

    @property
    @abstractmethod
    def platform(self) -> str:
        ...
