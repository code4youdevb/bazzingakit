"""Gestión de dispositivos iOS vía SSH."""

import shlex
import subprocess
from pathlib import Path
from typing import Optional

from bazzingakit.config.models import DeviceProfile
from bazzingakit.utils import get_logger

from .device_manager import CommandResult, DeviceInfo, DeviceManager

log = get_logger(__name__)


class IOSError(Exception):
    """Error en operación iOS/SSH."""


class IOSManager(DeviceManager):
    """Gestor de dispositivos iOS vía SSH (requiere jailbreak)."""

    def __init__(self, profile: DeviceProfile):
        if not profile.ssh_host:
            raise IOSError("ssh_host no configurado en el perfil")
        self._profile = profile

    @property
    def platform(self) -> str:
        return "ios"

    def _ssh_args(self, extra: list[str]) -> list[str]:
        """Args base para cada invocación de ssh."""
        args = [
            "ssh",
            "-o",
            "ConnectTimeout=5",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "LogLevel=ERROR",
            "-p",
            str(self._profile.ssh_port),
        ]
        if self._profile.ssh_key:
            args += ["-i", self._profile.ssh_key]
            args += ["-o", "BatchMode=yes"]
        args.append(f"{self._profile.ssh_user}@{self._profile.ssh_host}")
        args += extra
        return args

    def _run_ssh(self, command: str, timeout: int = 10) -> CommandResult:
        full_args = self._ssh_args([command])
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
            raise IOSError("ssh no encontrado en el PATH")
        except subprocess.TimeoutExpired:
            return CommandResult(returncode=-1, stdout="", stderr="timeout")

    def is_available(self) -> bool:
        """Verifica que ssh esté instalado."""
        try:
            result = subprocess.run(
                ["ssh", "-V"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.returncode == 0 or "OpenSSH" in result.stderr
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def is_connected(self) -> bool:
        result = self._run_ssh("echo OK", timeout=5)
        return result.ok and "OK" in result.stdout

    def list_devices(self) -> list[DeviceInfo]:
        """En iOS el 'dispositivo' es siempre el host configurado."""
        info = self.get_device_info()
        return [info] if info else []

    def get_device_info(self) -> Optional[DeviceInfo]:
        if not self._profile.ssh_host:
            return None

        info = DeviceInfo(
            platform="ios",
            identifier=self._profile.ssh_host,
            is_online=False,
        )

        if not self.is_connected():
            return info

        info.is_online = True

        # Obtener info vía comandos standard de iOS jailbroken
        try:
            version = self._run_ssh(
                "sw_vers -productVersion 2>/dev/null || "
                "uname -r",
                timeout=5,
            )
            if version.ok:
                info.os_version = version.stdout.strip()

            arch = self._run_ssh("uname -m", timeout=5)
            if arch.ok:
                info.arch = arch.stdout.strip()

            model = self._run_ssh(
                "gssc 2>/dev/null | grep -i product | head -1 || echo",
                timeout=5,
            )
            if model.ok and model.stdout.strip():
                info.model = model.stdout.strip()

            # En iOS jailbroken asumimos root (es requisito)
            info.is_rooted = True
        except Exception as e:
            log.debug(f"No se pudo enriquecer info iOS: {e}")

        return info

    def shell(self, command: str, timeout: int = 10) -> CommandResult:
        return self._run_ssh(command, timeout=timeout)

    def push(self, local: str, remote: str) -> CommandResult:
        """Usa scp para subir archivos."""
        scp_args = [
            "scp",
            "-o",
            "ConnectTimeout=5",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-P",
            str(self._profile.ssh_port),
        ]
        if self._profile.ssh_key:
            scp_args += ["-i", self._profile.ssh_key]

        scp_args += [
            local,
            f"{self._profile.ssh_user}@{self._profile.ssh_host}:{remote}",
        ]

        try:
            result = subprocess.run(
                scp_args, capture_output=True, text=True, timeout=60
            )
            return CommandResult(
                returncode=result.returncode,
                stdout=result.stdout,
                stderr=result.stderr,
            )
        except Exception as e:
            return CommandResult(returncode=-1, stdout="", stderr=str(e))

    def pull(self, remote: str, local: str) -> CommandResult:
        scp_args = [
            "scp",
            "-o",
            "ConnectTimeout=5",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-P",
            str(self._profile.ssh_port),
        ]
        if self._profile.ssh_key:
            scp_args += ["-i", self._profile.ssh_key]

        scp_args += [
            f"{self._profile.ssh_user}@{self._profile.ssh_host}:{remote}",
            local,
        ]

        try:
            result = subprocess.run(
                scp_args, capture_output=True, text=True, timeout=60
            )
            return CommandResult(
                returncode=result.returncode,
                stdout=result.stdout,
                stderr=result.stderr,
            )
        except Exception as e:
            return CommandResult(returncode=-1, stdout="", stderr=str(e))

    def list_apps(self) -> list[dict]:
        """Lista apps instaladas (requiere 'ipainstaller' o 'lsappinfo')."""
        # Approach 1: ipainstaller -l (si está instalado)
        result = self._run_ssh(
            "which ipainstaller >/dev/null 2>&1 && ipainstaller -l",
            timeout=15,
        )
        if result.ok and result.stdout.strip():
            apps = []
            for line in result.stdout.splitlines():
                if " : " in line:
                    bundle_id = line.split(" : ", 1)[0].strip()
                    name = line.split(" : ", 1)[1].strip()
                    apps.append({"bundle_id": bundle_id, "name": name})
            return apps

        # Fallback: listar /var/containers/Bundle/Application/
        result = self._run_ssh(
            "ls /var/containers/Bundle/Application/ 2>/dev/null",
            timeout=10,
        )
        if result.ok:
            return [{"bundle_id": uuid, "name": "?"} for uuid in result.stdout.split()]

        return []
