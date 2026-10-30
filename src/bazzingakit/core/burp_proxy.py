"""Gestión de certificados de Burp Suite en dispositivos Android.

Soporta dos modos:
- Bind mount (default): no permanente, se pierde al reboot pero no requiere reiniciar.
- Magisk module (--permanent): genera y instala módulo Magisk, requiere reboot.

Pre-requisitos:
- Burp corriendo en localhost:8080 con proxy activo
- openssl en PATH
- Dispositivo rooteado con Magisk (Android 10+)
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from bazzingakit.utils import get_logger

from .device_manager import DeviceManager

log = get_logger(__name__)


SYSTEM_CERTS_DIR = "/apex/com.android.conscrypt/cacerts"
LEGACY_CERTS_DIR = "/system/etc/security/cacerts"


class BurpProxyError(Exception):
    """Error en operación de proxy/cert."""


@dataclass
class CertInfo:
    """Información del certificado procesado."""

    pem_path: Path
    hash_name: str  # ej. "9a5ba575.0"
    der_bytes: bytes


class BurpProxyManager:
    """Maneja la descarga del cert de Burp y su instalación en Android."""

    def __init__(self, device_manager: DeviceManager):
        self._device = device_manager

    # ---------- Validaciones ----------

    @staticmethod
    def check_openssl() -> tuple[bool, str]:
        """Verifica que openssl esté en PATH."""
        if not shutil.which("openssl"):
            return False, (
                "openssl no encontrado en PATH. Instálalo:\n"
                "  - Windows: choco install openssl  (o descarga de slproweb.com)\n"
                "  - Linux:   sudo apt install openssl\n"
                "  - Mac:     brew install openssl"
            )
        return True, "openssl OK"

    @staticmethod
    def check_burp(host: str = "127.0.0.1", port: int = 8080) -> tuple[bool, str]:
        """Verifica que Burp esté accesible en host:port/cert."""
        url = f"http://{host}:{port}/cert"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "bazzingakit"})
            with urllib.request.urlopen(req, timeout=5) as response:
                data = response.read()
                if not data or len(data) < 100:
                    return False, f"Burp respondió pero el cert parece vacío ({len(data)} bytes)"
                return True, f"Burp accesible ({len(data)} bytes)"
        except Exception as e:
            return False, (
                f"No se pudo descargar cert de {url}: {e}\n"
                "Verifica:\n"
                "  - Burp Suite está abierto\n"
                "  - Proxy listener activo en 127.0.0.1:8080 "
                "(Proxy → Settings → Proxy Listeners)\n"
                "  - El listener debe ser 'invisible' o normal, no SOCKS"
            )

    def check_device_ready(self) -> tuple[bool, str]:
        """Verifica que el dispositivo esté conectado y rooteado."""
        if not self._device.is_connected():
            return False, "Dispositivo no conectado"

        # Verificar root
        result = self._device.shell("su -c 'id' 2>&1", timeout=5)
        if not result.ok or "uid=0" not in result.stdout:
            return False, (
                "El dispositivo no tiene root (su -c id no devuelve uid=0).\n"
                "Necesitas un dispositivo rooteado con Magisk."
            )
        return True, "Dispositivo rooteado OK"

    def check_magisk(self) -> tuple[bool, str]:
        """Verifica que Magisk esté presente."""
        result = self._device.shell("which magisk 2>/dev/null || echo NO", timeout=5)
        if "NO" in result.stdout or not result.stdout.strip():
            return False, (
                "Magisk no encontrado en el dispositivo.\n"
                "Esta funcionalidad requiere root vía Magisk."
            )
        return True, f"Magisk: {result.stdout.strip()}"

    # ---------- Descarga y conversión del cert ----------

    def download_cert(
        self, host: str = "127.0.0.1", port: int = 8080
    ) -> bytes:
        """Descarga el cert de Burp en formato DER."""
        url = f"http://{host}:{port}/cert"
        log.info(f"Descargando cert de {url}")
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "bazzingakit"})
            with urllib.request.urlopen(req, timeout=10) as response:
                return response.read()
        except Exception as e:
            raise BurpProxyError(f"No se pudo descargar cert de Burp: {e}")

    def process_cert(self, der_bytes: bytes, work_dir: Path) -> CertInfo:
        """Convierte DER → PEM → calcula hash → renombra a <hash>.0.

        Equivalente al flujo manual:
          openssl x509 -inform DER -in cacert.der -out cacert.pem
          openssl x509 -inform PEM -subject_hash_old -in cacert.pem
        """
        work_dir.mkdir(parents=True, exist_ok=True)
        der_path = work_dir / "burp.der"
        der_path.write_bytes(der_bytes)

        # DER → PEM
        pem_path = work_dir / "burp.pem"
        result = subprocess.run(
            ["openssl", "x509", "-inform", "DER",
             "-in", str(der_path), "-out", str(pem_path)],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            raise BurpProxyError(f"openssl DER→PEM falló: {result.stderr}")

        # Hash
        result = subprocess.run(
            ["openssl", "x509", "-inform", "PEM",
             "-subject_hash_old", "-in", str(pem_path)],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            raise BurpProxyError(f"openssl hash falló: {result.stderr}")

        hash_value = result.stdout.strip().splitlines()[0].strip()
        if not hash_value or len(hash_value) != 8:
            raise BurpProxyError(f"Hash inválido: '{hash_value}'")

        # Renombrar a <hash>.0
        hash_name = f"{hash_value}.0"
        final_path = work_dir / hash_name
        shutil.copy(pem_path, final_path)

        log.info(f"Cert procesado: {hash_name}")
        return CertInfo(pem_path=final_path, hash_name=hash_name, der_bytes=der_bytes)

    # ---------- Instalación: bind mount (no permanente) ----------

    def install_via_bind_mount(self, cert: CertInfo) -> None:
        """Instala el cert vía bind mount sobre /apex/com.android.conscrypt/cacerts/.

        Pasos:
          1. Push del cert al device
          2. Crear directorio temporal /data/local/tmp/cacerts/
          3. Copiar todos los certs originales del system + el nuevo
          4. mount --bind sobre el directorio system
        """
        device_tmp = "/data/local/tmp/burp_cert_install"
        cert_target = f"{device_tmp}/{cert.hash_name}"

        # Push del cert
        log.info("Subiendo cert al dispositivo...")
        self._device.shell(f"mkdir -p {device_tmp}")
        push_result = self._device.push(str(cert.pem_path), cert_target)
        if not push_result.ok:
            raise BurpProxyError(f"Push falló: {push_result.stderr}")

        # Detectar dónde están los certs del sistema actualmente
        check = self._device.shell(
            f"[ -d {SYSTEM_CERTS_DIR} ] && echo APEX || "
            f"[ -d {LEGACY_CERTS_DIR} ] && echo LEGACY || echo NONE",
            timeout=5,
        )
        if "APEX" in check.stdout:
            target_dir = SYSTEM_CERTS_DIR
            log.info(f"Usando directorio APEX: {target_dir}")
        elif "LEGACY" in check.stdout:
            target_dir = LEGACY_CERTS_DIR
            log.info(f"Usando directorio legacy: {target_dir}")
        else:
            raise BurpProxyError(
                "No se encontraron directorios de certs del sistema "
                f"({SYSTEM_CERTS_DIR} ni {LEGACY_CERTS_DIR})"
            )

        # Setup del bind mount
        # 1. Copiamos todos los certs originales a un staging dir
        # 2. Añadimos el nuevo
        # 3. Bind mount del staging dir sobre el target
        staging_dir = "/data/local/tmp/cacerts_staging"

        bind_script = (
            f"set -e; "
            f"rm -rf {staging_dir}; "
            f"mkdir -p {staging_dir}; "
            f"cp -a {target_dir}/* {staging_dir}/ 2>/dev/null || true; "
            f"cp {cert_target} {staging_dir}/{cert.hash_name}; "
            f"chmod 644 {staging_dir}/*; "
            f"chown root:root {staging_dir}/* 2>/dev/null || true; "
            f"mount --bind {staging_dir} {target_dir}"
        )

        log.info("Aplicando bind mount...")
        result = self._device.shell(f"su -c '{bind_script}'", timeout=15)
        if not result.ok:
            raise BurpProxyError(
                f"Bind mount falló: {result.stderr or result.stdout}"
            )

        # Verificar que el cert está visible
        verify = self._device.shell(
            f"su -c 'ls {target_dir}/{cert.hash_name}'", timeout=5
        )
        if cert.hash_name not in verify.stdout:
            raise BurpProxyError(
                f"El cert no se instaló correctamente: {verify.stderr or verify.stdout}"
            )

        log.info(f"Cert instalado en {target_dir}/{cert.hash_name}")

    def unmount_bind(self) -> None:
        """Deshace el bind mount (revierte el cert)."""
        for target in [SYSTEM_CERTS_DIR, LEGACY_CERTS_DIR]:
            self._device.shell(
                f"su -c 'umount {target}' 2>/dev/null; true", timeout=5
            )
        log.info("Bind mounts removidos (si existían)")

    # ---------- Instalación: módulo Magisk (permanente) ----------

    def install_via_magisk_module(self, cert: CertInfo, work_dir: Path) -> str:
        """Genera e instala módulo Magisk con el cert.

        Returns:
            Path en el device del .zip instalado.
        """
        # 1. Construir estructura del módulo
        module_dir = work_dir / "burp_cert_module"
        module_dir.mkdir(exist_ok=True)

        # module.prop
        module_prop = (
            "id=burp_cert\n"
            "name=Burp Suite CA Cert\n"
            "version=v1.0\n"
            "versionCode=1\n"
            "author=bazzingakit\n"
            "description=Installs Burp Suite CA certificate as a system trusted CA.\n"
        )
        (module_dir / "module.prop").write_text(module_prop, encoding="utf-8")

        # Estructura: system/etc/security/cacerts/<hash>.0
        cacerts_path = module_dir / "system" / "etc" / "security" / "cacerts"
        cacerts_path.mkdir(parents=True, exist_ok=True)
        shutil.copy(cert.pem_path, cacerts_path / cert.hash_name)

        # Para Android 10+ con APEX, también copiamos a la ruta apex
        # Magisk con MagiskSU 24+ replica esto automáticamente, pero por si acaso
        apex_path = module_dir / "system" / "apex" / "com.android.conscrypt" / "cacerts"
        apex_path.mkdir(parents=True, exist_ok=True)
        shutil.copy(cert.pem_path, apex_path / cert.hash_name)

        # 2. Empaquetar en zip
        zip_path = work_dir / "burp_cert_module.zip"
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for file_path in module_dir.rglob("*"):
                if file_path.is_file():
                    arcname = file_path.relative_to(module_dir)
                    zf.write(file_path, arcname)

        # 3. Push al device
        device_zip_path = "/sdcard/Download/burp_cert_module.zip"
        log.info(f"Subiendo módulo: {device_zip_path}")
        push_result = self._device.push(str(zip_path), device_zip_path)
        if not push_result.ok:
            raise BurpProxyError(f"Push del módulo falló: {push_result.stderr}")

        # 4. Instalar con magisk --install-module
        log.info("Instalando módulo en Magisk...")
        result = self._device.shell(
            f"su -c 'magisk --install-module {device_zip_path}'",
            timeout=60,
        )
        if not result.ok or "Done" not in (result.stdout + result.stderr):
            log.warning(
                f"Magisk install salida ambigua. stdout: {result.stdout[:300]} "
                f"stderr: {result.stderr[:300]}"
            )
            # No abortamos: a veces magisk no imprime "Done" en stdout

        return device_zip_path

    # ---------- Status ----------

    def status(self, hash_name: Optional[str] = None) -> dict:
        """Devuelve estado actual: cert instalado? bind activo?"""
        info = {
            "device_connected": self._device.is_connected(),
            "cert_in_apex": False,
            "cert_in_legacy": False,
            "bind_mount_active": False,
            "cert_hash_searched": hash_name,
        }

        if not info["device_connected"]:
            return info

        # Buscar cualquier .0 en los directorios system
        for dir_path, key in [(SYSTEM_CERTS_DIR, "cert_in_apex"),
                               (LEGACY_CERTS_DIR, "cert_in_legacy")]:
            if hash_name:
                check = self._device.shell(
                    f"[ -f {dir_path}/{hash_name} ] && echo YES || echo NO",
                    timeout=5,
                )
                if "YES" in check.stdout:
                    info[key] = True

        # Bind mount activo?
        check = self._device.shell(
            "mount | grep cacerts || echo NO", timeout=5
        )
        info["bind_mount_active"] = "cacerts" in check.stdout and "NO" not in check.stdout

        return info
