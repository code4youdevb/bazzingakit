"""Gestión de dispositivos Android vía ADB (incluye soporte para nox_adb)."""

import subprocess
from pathlib import Path
from typing import Optional

from bazzingakit.config.models import DeviceProfile
from bazzingakit.utils import get_logger

from .device_manager import CommandResult, DeviceInfo, DeviceManager

log = get_logger(__name__)


class ADBError(Exception):
    """Error en operación ADB."""


class ADBManager(DeviceManager):
    """Gestor de dispositivos Android vía adb (o nox_adb)."""

    def __init__(self, profile: DeviceProfile):
        self._profile = profile
        self._adb_binary = profile.adb_path or "adb"
        self._serial = profile.device_serial

    @property
    def platform(self) -> str:
        return "android"

    @property
    def adb_binary(self) -> str:
        return self._adb_binary

    def _base_args(self) -> list[str]:
        """Args base para cada invocación de adb."""
        args = [self._adb_binary]
        if self._serial:
            args += ["-s", self._serial]
        return args

    def _run(self, args: list[str], timeout: int = 10) -> CommandResult:
        """Ejecuta adb con los args dados."""
        full_args = self._base_args() + args
        try:
            result = subprocess.run(
                full_args,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return CommandResult(
                returncode=result.returncode,
                stdout=result.stdout,
                stderr=result.stderr,
            )
        except FileNotFoundError:
            raise ADBError(f"Binario no encontrado: {self._adb_binary}")
        except subprocess.TimeoutExpired:
            return CommandResult(returncode=-1, stdout="", stderr="timeout")

    def is_available(self) -> bool:
        """Verifica que el binario adb exista y responda."""
        if self._profile.adb_path:
            if not Path(self._profile.adb_path).exists():
                return False

        try:
            result = subprocess.run(
                [self._adb_binary, "version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def is_connected(self) -> bool:
        devices = self.list_devices()
        return any(d.is_online for d in devices)

    def list_devices(self) -> list[DeviceInfo]:
        """Parsea 'adb devices -l' y devuelve info de cada dispositivo."""
        try:
            result = subprocess.run(
                [self._adb_binary, "devices", "-l"],
                capture_output=True,
                text=True,
                timeout=10,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return []

        devices: list[DeviceInfo] = []
        for line in result.stdout.splitlines()[1:]:  # skip "List of devices attached"
            line = line.strip()
            if not line:
                continue

            parts = line.split()
            if len(parts) < 2:
                continue

            serial = parts[0]
            status = parts[1]

            # Parse model de la línea completa si está
            model = None
            for part in parts[2:]:
                if part.startswith("model:"):
                    model = part.split(":", 1)[1]

            devices.append(
                DeviceInfo(
                    platform="android",
                    identifier=serial,
                    model=model,
                    is_online=status == "device",
                )
            )

        return devices

    def get_device_info(self) -> Optional[DeviceInfo]:
        """Info del dispositivo activo, con datos de getprop."""
        devices = self.list_devices()
        if not devices:
            return None

        # Si hay serial configurado, usar ese; si no, el primero online
        target = None
        if self._serial:
            target = next(
                (d for d in devices if d.identifier == self._serial), None
            )
        else:
            target = next((d for d in devices if d.is_online), None)

        if not target or not target.is_online:
            return target

        # Enriquecer con getprop
        try:
            arch = self.shell("getprop ro.product.cpu.abi", timeout=5)
            if arch.ok:
                target.arch = arch.stdout.strip()

            version = self.shell("getprop ro.build.version.release", timeout=5)
            if version.ok:
                target.os_version = version.stdout.strip()

            # Check root básico: 'su -c id' o existencia de /system/xbin/su
            root_check = self.shell(
                "[ -f /system/xbin/su ] || [ -f /system/bin/su ] && echo ROOTED",
                timeout=5,
            )
            target.is_rooted = "ROOTED" in root_check.stdout
        except Exception as e:
            log.debug(f"No se pudo enriquecer info del dispositivo: {e}")

        return target

    def shell(self, command: str, timeout: int = 10) -> CommandResult:
        return self._run(["shell", command], timeout=timeout)

    def push(self, local: str, remote: str) -> CommandResult:
        return self._run(["push", local, remote], timeout=60)

    def pull(self, remote: str, local: str) -> CommandResult:
        return self._run(["pull", remote, local], timeout=60)

    def list_packages(self, filter_user: bool = True) -> list[str]:
        """Lista paquetes instalados. Por defecto solo apps de usuario."""
        flag = "-3" if filter_user else ""
        result = self.shell(f"pm list packages {flag}", timeout=10)
        if not result.ok:
            return []

        packages = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("package:"):
                packages.append(line.replace("package:", "", 1))
        return sorted(packages)

    def get_apk_path(self, package: str) -> Optional[str]:
        """Devuelve el path del APK instalado en el dispositivo."""
        result = self.shell(f"pm path {package}", timeout=5)
        if not result.ok:
            return None

        for line in result.stdout.splitlines():
            if line.startswith("package:"):
                return line.replace("package:", "", 1).strip()
        return None
