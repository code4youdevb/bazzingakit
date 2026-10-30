"""Gestión de Frida: auto-setup de frida-server, attach/spawn, carga de scripts."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

from bazzingakit.config.models import DeviceProfile, Platform
from bazzingakit.utils import get_logger

from .device_manager import DeviceManager

log = get_logger(__name__)

try:
    import frida  # type: ignore
    FRIDA_AVAILABLE = True
except ImportError:
    FRIDA_AVAILABLE = False


class FridaError(Exception):
    """Error en operación Frida."""


@dataclass
class LoadedScript:
    """Handle a un script cargado en una sesión Frida."""

    name: str
    source_path: Optional[Path]
    script: Any  # frida.core.Script
    config: dict = field(default_factory=dict)


class FridaManager:
    """Orquesta la interacción con Frida en un dispositivo."""

    def __init__(self, profile: DeviceProfile, device_manager: DeviceManager):
        if not FRIDA_AVAILABLE:
            raise FridaError("frida no está instalado. pip install frida frida-tools")
        self._profile = profile
        self._device_manager = device_manager
        self._frida_device: Optional[Any] = None
        self._session: Optional[Any] = None
        self._loaded_scripts: list[LoadedScript] = []
        self._message_handlers: list[Callable] = []

    # ---------- Version & compatibility ----------

    @property
    def client_version(self) -> str:
        """Versión del cliente frida (pip)."""
        if not FRIDA_AVAILABLE:
            return "unknown"
        import frida as _frida
        return _frida.__version__

    def server_version(self) -> Optional[str]:
        """Versión de frida-server en el dispositivo, o None si no responde."""
        if self._profile.platform != Platform.ANDROID:
            # En iOS frida viene con el paquete de Cydia; intentamos extraer igual
            result = self._device_manager.shell("frida-server --version 2>&1", timeout=5)
            if result.ok:
                return result.stdout.strip().split()[0] if result.stdout.strip() else None
            return None

        server_path = self._profile.frida_server_path
        result = self._device_manager.shell(
            f"{server_path} --version 2>&1 || echo FAIL", timeout=5
        )
        if not result.ok or "FAIL" in result.stdout or "No such" in result.stdout:
            return None
        line = result.stdout.strip().splitlines()[0] if result.stdout.strip() else ""
        # La salida típica es solo "16.1.11" o similar
        return line.strip() if line and not line.startswith("FAIL") else None

    def check_version_compat(self) -> tuple[bool, str]:
        """Verifica compatibilidad cliente/server.

        Returns:
            (compat, message): True si major version coincide.
        """
        client = self.client_version
        server = self.server_version()

        if server is None:
            return False, f"frida-server no detectado en el dispositivo (cliente: {client})"

        client_major = client.split(".")[0]
        server_major = server.split(".")[0]

        if client_major != server_major:
            return False, (
                f"Versiones incompatibles — cliente: {client}, server: {server}. "
                f"Los majors deben coincidir ({client_major} vs {server_major})."
            )
        return True, f"Compatible — cliente: {client}, server: {server}"

    # ---------- Download & install ----------

    def get_device_arch(self) -> Optional[str]:
        """Detecta la arquitectura del dispositivo para elegir el binario correcto."""
        if self._profile.platform != Platform.ANDROID:
            return None
        result = self._device_manager.shell("getprop ro.product.cpu.abi", timeout=5)
        if not result.ok:
            return None
        return result.stdout.strip()

    @staticmethod
    def _frida_arch_name(android_abi: str) -> Optional[str]:
        """Mapea ABI de Android al nombre de arch en releases de Frida."""
        mapping = {
            "arm64-v8a": "arm64",
            "armeabi-v7a": "arm",
            "armeabi": "arm",
            "x86": "x86",
            "x86_64": "x86_64",
        }
        return mapping.get(android_abi)

    def download_server(self, version: Optional[str] = None, cache_dir: Optional[Path] = None) -> Path:
        """Descarga el binario frida-server desde GitHub releases.

        Args:
            version: versión a bajar. Default: versión del cliente actual.
            cache_dir: directorio donde guardar. Default: ~/.bazzingakit/cache/frida/
        """
        import lzma
        import urllib.request

        if self._profile.platform != Platform.ANDROID:
            raise FridaError("Auto-download solo soporta Android")

        version = version or self.client_version
        arch = self.get_device_arch()
        if not arch:
            raise FridaError("No se pudo detectar arquitectura del dispositivo")

        frida_arch = self._frida_arch_name(arch)
        if not frida_arch:
            raise FridaError(f"Arquitectura no soportada: {arch}")

        cache_dir = cache_dir or (Path.home() / ".bazzingakit" / "cache" / "frida")
        cache_dir.mkdir(parents=True, exist_ok=True)

        binary_name = f"frida-server-{version}-android-{frida_arch}"
        xz_path = cache_dir / f"{binary_name}.xz"
        bin_path = cache_dir / binary_name

        # Reutilizar cache si existe
        if bin_path.exists():
            log.info(f"Usando frida-server cacheado: {bin_path}")
            return bin_path

        url = f"https://github.com/frida/frida/releases/download/{version}/{binary_name}.xz"
        log.info(f"Descargando {url}")

        try:
            with urllib.request.urlopen(url, timeout=60) as response:
                xz_path.write_bytes(response.read())
        except Exception as e:
            raise FridaError(f"Download falló: {e}")

        log.info(f"Descomprimiendo...")
        with lzma.open(xz_path) as f:
            bin_path.write_bytes(f.read())
        xz_path.unlink()
        bin_path.chmod(0o755)

        log.info(f"frida-server listo en: {bin_path}")
        return bin_path

    def setup_server(self, version: Optional[str] = None, force: bool = False) -> bool:
        """Flow completo: descarga + push + chmod + (no arranca).

        Si ya hay un server con la versión correcta, no hace nada salvo force=True.
        """
        if self._profile.platform != Platform.ANDROID:
            raise FridaError("setup_server solo soporta Android")

        target_version = version or self.client_version
        current = self.server_version()

        if current == target_version and not force:
            log.info(f"frida-server {current} ya instalado")
            return True

        local_binary = self.download_server(version=target_version)
        return self.install_server(str(local_binary))

    @staticmethod
    def _compatible_tools_spec(frida_version: str) -> str:
        """Devuelve la spec de pip para frida-tools compatible con una versión de frida.

        Evita el backtracking prolongado de pip al no dejarle resolver solo.
        """
        try:
            major = int(frida_version.split(".")[0])
        except (ValueError, IndexError):
            return "frida-tools"

        # Matrix conocida:
        # frida 14.x → frida-tools 9.x
        # frida 15.x → frida-tools 10.x-11.x
        # frida 16.x → frida-tools 12.x-13.x
        # frida 17.x → frida-tools 14.x
        matrix = {
            14: "frida-tools>=9,<10",
            15: "frida-tools>=10,<12",
            16: "frida-tools>=12,<14",
            17: "frida-tools>=14,<15",
        }
        return matrix.get(major, "frida-tools")

    def sync_client_to_server(self) -> tuple[bool, str]:
        """Instala en el PC la misma versión de frida que el device.

        Útil para iOS donde actualizar el server es engorroso.
        Retorna (ok, mensaje).
        """
        server = self.server_version()
        if not server:
            return False, "No se detectó frida-server en el dispositivo"

        if server == self.client_version:
            return True, f"Cliente ya está en {server}"

        import subprocess
        import sys

        tools_spec = self._compatible_tools_spec(server)
        log.info(f"Instalando frida=={server} + {tools_spec} (puede tardar 1-3 min)...")

        try:
            process = subprocess.Popen(
                [sys.executable, "-m", "pip", "install", "--upgrade",
                 f"frida=={server}", tools_spec],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )

            for line in process.stdout:  # type: ignore[union-attr]
                line = line.rstrip()
                if line:
                    log.info(f"pip: {line}")

            try:
                returncode = process.wait(timeout=600)
            except subprocess.TimeoutExpired:
                process.kill()
                return False, "pip install excedió el timeout de 10 minutos"

        except Exception as e:
            return False, f"pip install falló: {e}"

        if returncode != 0:
            return False, f"pip terminó con código {returncode}"

        return True, (
            f"Cliente actualizado a frida=={server}. "
            "Reinicia el proceso para que el cambio tome efecto."
        )

    # ---------- frida-server management (Android) ----------

    def is_server_running(self) -> bool:
        """Verifica si frida-server está corriendo en el dispositivo.

        Importante: hay que evitar que el propio comando aparezca en la búsqueda
        (auto-detección). Usamos `pgrep -x` que solo matchea el nombre exacto del
        proceso, no la línea de comandos completa.
        """
        if self._profile.platform == Platform.ANDROID:
            # pgrep -x: match exacto del nombre, no aparece a sí mismo
            # El nombre del proceso de frida-server suele truncarse a 15 chars
            result = self._device_manager.shell(
                "pgrep -x frida-server || pgrep -x frida-serv || echo NO",
                timeout=5,
            )
            if not result.ok:
                return False
            output = result.stdout.strip()
            # Si hay PID(s), está corriendo. "NO" significa que ningún pgrep matcheó.
            return output != "" and output != "NO" and "NO" not in output
        else:  # iOS
            # En iOS el binario suele llamarse frida-server o re.frida.server
            result = self._device_manager.shell(
                "ps aux 2>/dev/null | grep -i frida-server | grep -v grep || echo NO",
                timeout=5,
            )
            return (
                result.ok
                and "frida-server" in result.stdout
                and "NO" not in result.stdout
            )

    def start_server(self) -> bool:
        """Arranca frida-server en el dispositivo (Android) usando su -c.

        Asume que el binario ya está en frida_server_path.
        """
        if self._profile.platform != Platform.ANDROID:
            log.warning("start_server solo aplica a Android; en iOS frida viene con el paquete")
            return self.is_server_running()

        if self.is_server_running():
            log.info("frida-server ya está corriendo")
            return True

        server_path = self._profile.frida_server_path
        check = self._device_manager.shell(f"[ -f {server_path} ] && echo OK || echo NO")
        if "NO" in check.stdout:
            raise FridaError(
                f"frida-server no encontrado en {server_path}. "
                "Descárgalo manualmente o usa 'bazzingakit frida setup'."
            )

        # Asegurar permisos
        self._device_manager.shell(f"su -c 'chmod 755 {server_path}'")

        # Arrancar como root con su -c (forma estándar para emuladores rooteados).
        # Usamos nohup + & + redirect para que sobreviva al cierre del shell.
        self._device_manager.shell(
            f"su -c 'nohup {server_path} >/dev/null 2>&1 &'",
            timeout=5,
        )

        # Esperar a que el proceso aparezca
        import time
        for _ in range(6):  # hasta 3s
            time.sleep(0.5)
            if self.is_server_running():
                log.info("frida-server iniciado correctamente")
                return True

        log.warning(
            "frida-server no apareció tras start. "
            "Prueba manualmente: adb shell \"su -c '/data/local/tmp/frida-server &'\""
        )
        return False

    def stop_server(self) -> bool:
        """Detiene frida-server en el dispositivo (Android) usando su -c."""
        if self._profile.platform != Platform.ANDROID:
            return True

        # Si fue lanzado como root, hay que matarlo como root
        self._device_manager.shell(
            "su -c 'pkill -9 -x frida-server' 2>/dev/null; "
            "su -c 'pkill -9 -x frida-serv' 2>/dev/null; true",
            timeout=5,
        )

        # Verificar
        import time
        time.sleep(0.5)
        return not self.is_server_running()

    def install_server(self, local_binary_path: str) -> bool:
        """Sube el binario de frida-server al dispositivo y le da permisos."""
        if self._profile.platform != Platform.ANDROID:
            raise FridaError("install_server solo soporta Android")

        target = self._profile.frida_server_path
        log.info(f"Subiendo {local_binary_path} → {target}")
        push_result = self._device_manager.push(local_binary_path, target)
        if not push_result.ok:
            raise FridaError(f"push falló: {push_result.stderr}")

        chmod_result = self._device_manager.shell(f"chmod 755 {target}")
        if not chmod_result.ok:
            log.warning(f"chmod falló: {chmod_result.stderr}")
        return True

    # ---------- iOS server management ----------

    # Rutas comunes donde puede estar frida-server en iOS
    IOS_FRIDA_PATHS = [
        "/var/jb/usr/sbin/frida-server",   # rootless (Dopamine, palera1n rootless)
        "/usr/sbin/frida-server",           # tradicional (unc0ver, checkra1n)
        "/var/jb/usr/bin/frida-server",     # alguna variante rootless
    ]

    def detect_ios_frida_path(self) -> Optional[str]:
        """Busca dónde está el binario frida-server en el iPhone."""
        if self._profile.platform != Platform.IOS:
            return None
        for path in self.IOS_FRIDA_PATHS:
            result = self._device_manager.shell(
                f"[ -f {path} ] && echo OK || echo NO", timeout=5
            )
            if "OK" in result.stdout:
                return path
        return None

    def is_ios_server_listening(self, bind_addr: str = "") -> tuple[bool, str]:
        """Verifica si frida-server escucha en el puerto.

        Args:
            bind_addr: si se especifica (p.e. "0.0.0.0"), verifica que escuche
                       en esa interfaz. Vacío = solo verifica el puerto.

        Returns:
            (escuchando, info): info incluye la dirección detectada.
        """
        if self._profile.platform != Platform.IOS:
            return False, "no es iOS"

        port = self._profile.frida_port

        # lsof es lo más fiable en iOS jailbroken
        result = self._device_manager.shell(
            f"lsof -i :{port} 2>/dev/null | grep LISTEN || echo NO",
            timeout=5,
        )
        if "NO" in result.stdout or not result.stdout.strip():
            # Fallback con netstat
            result = self._device_manager.shell(
                f"netstat -an 2>/dev/null | grep ':{port}' | grep -i listen || echo NO",
                timeout=5,
            )

        output = result.stdout.strip()
        if "NO" in output or not output:
            return False, "no escucha"

        # Verificar dirección si se pidió
        listening_on = "127.0.0.1" if "127.0.0.1" in output else (
            "0.0.0.0" if "0.0.0.0" in output or "*:" in output else "?"
        )

        if bind_addr and bind_addr not in output and not (
            bind_addr == "0.0.0.0" and ("0.0.0.0" in output or "*:" in output)
        ):
            return False, f"escucha pero en {listening_on}, no en {bind_addr}"

        return True, listening_on

    def setup_ios_network(self, bind: str = "0.0.0.0") -> dict:
        """Mata frida-server existente y lo relanza escuchando en `bind`:port.

        Por defecto en 0.0.0.0 para permitir conexión desde la red (PC vía -H).
        Usar 127.0.0.1 para volver al modo seguro (solo conexión local).

        Returns:
            dict con info: {path, pid, bind, port, listening_on}
        """
        if self._profile.platform != Platform.IOS:
            raise FridaError("setup_ios_network solo aplica a iOS")

        path = self.detect_ios_frida_path()
        if not path:
            raise FridaError(
                "frida-server no encontrado en el iPhone.\n"
                "Rutas buscadas: " + ", ".join(self.IOS_FRIDA_PATHS) + "\n"
                "Instala frida desde Cydia/Sileo (paquete 'Frida' del repo de frida.re)."
            )

        port = self._profile.frida_port

        # 1. Matar lo que esté corriendo
        log.info("Matando frida-server existente...")
        self._device_manager.shell(
            "pkill -x frida-server 2>/dev/null; "
            "pkill -x frida-serv 2>/dev/null; true",
            timeout=5,
        )
        import time
        time.sleep(0.5)

        # 2. Relanzar con bind address
        log.info(f"Lanzando {path} -l {bind}:{port}")
        # nohup + & + disown para que sobreviva al cierre de la sesión SSH
        cmd = (
            f"nohup {path} -l {bind}:{port} >/dev/null 2>&1 &\n"
            f"disown 2>/dev/null || true"
        )
        result = self._device_manager.shell(cmd, timeout=5)
        if not result.ok:
            log.warning(f"shell devolvió: {result.stderr}")

        # 3. Verificar que arrancó y escucha donde queremos
        for _ in range(6):
            time.sleep(0.5)
            listening, info = self.is_ios_server_listening(bind_addr=bind)
            if listening:
                log.info(f"frida-server escuchando en {info}:{port}")
                return {
                    "path": path,
                    "bind": bind,
                    "port": port,
                    "listening_on": info,
                }

        raise FridaError(
            f"frida-server no logró escuchar en {bind}:{port} tras 3s.\n"
            "Verifica con: ssh mobile@<ip> 'lsof -i :27042'"
        )

    # ---------- Attach / Spawn ----------

    def _get_frida_device(self) -> Any:
        """Obtiene el objeto device de Frida.

        Para Android: USB device.
        Para iOS: si el perfil tiene ssh_host, usa network device en {ssh_host}:{frida_port}.
                  Si no, USB.
        """
        if self._frida_device:
            return self._frida_device

        import frida as _frida

        try:
            if self._profile.platform == Platform.ANDROID:
                self._frida_device = _frida.get_usb_device(timeout=5)
            else:
                # iOS: preferimos network device si hay ssh_host configurado
                if self._profile.ssh_host:
                    host_port = f"{self._profile.ssh_host}:{self._profile.frida_port}"
                    mgr = _frida.get_device_manager()
                    # Buscar device existente
                    existing = None
                    for d in mgr.enumerate_devices():
                        if d.id == host_port:
                            existing = d
                            break
                    if existing is not None:
                        self._frida_device = existing
                    else:
                        # add_remote_device retorna el device. En caso de fallar
                        # (host no responde), lanza excepción.
                        self._frida_device = mgr.add_remote_device(host_port)
                    log.info(f"Conectado a iOS via network: {host_port}")
                else:
                    self._frida_device = _frida.get_usb_device(timeout=5)
        except Exception as e:
            raise FridaError(f"No se pudo obtener dispositivo Frida: {e}")

        return self._frida_device

    def attach(self, target: str) -> None:
        """Attach a un proceso ya corriendo (por PID o nombre)."""
        # Pre-flight: compatibilidad de versión
        if self._profile.platform == Platform.ANDROID:
            compat, msg = self.check_version_compat()
            if not compat:
                raise FridaError(
                    f"{msg}\n"
                    f"Arregla con: bazzingakit frida setup --force"
                )

        device = self._get_frida_device()
        try:
            # Intentar PID primero
            pid = int(target)
            self._session = device.attach(pid)
        except ValueError:
            # Es un nombre/package
            self._session = device.attach(target)

        log.info(f"Attach exitoso: {target}")

    def spawn(self, package: str) -> int:
        """Spawnea una app y retorna su PID (no la resumea aún)."""
        # Pre-flight: compatibilidad de versión
        if self._profile.platform == Platform.ANDROID:
            compat, msg = self.check_version_compat()
            if not compat:
                raise FridaError(
                    f"{msg}\n"
                    f"Arregla con: bazzingakit frida setup --force"
                )

        device = self._get_frida_device()
        pid = device.spawn([package])
        self._session = device.attach(pid)
        log.info(f"Spawn exitoso: {package} (pid={pid})")
        return pid

    def resume(self, pid: int) -> None:
        """Resume un proceso spawneado."""
        device = self._get_frida_device()
        device.resume(pid)
        log.debug(f"Resume pid={pid}")

    def detach(self) -> None:
        """Descarga todos los scripts y cierra la sesión."""
        for loaded in self._loaded_scripts:
            try:
                loaded.script.unload()
            except Exception as e:
                log.debug(f"Error descargando {loaded.name}: {e}")
        self._loaded_scripts.clear()

        if self._session:
            try:
                self._session.detach()
            except Exception as e:
                log.debug(f"Error en detach: {e}")
            self._session = None

    # ---------- Scripts ----------

    def load_script(
        self,
        source: str,
        name: str = "unnamed",
        source_path: Optional[Path] = None,
        config: Optional[dict] = None,
    ) -> LoadedScript:
        """Carga un script Frida en la sesión activa."""
        if not self._session:
            raise FridaError("No hay sesión activa. Llama attach() o spawn() primero.")

        script = self._session.create_script(source)
        script.on("message", self._build_message_handler(name))
        # Capturar console.log del JS (en Frida llega via 'message' con type='log'
        # cuando usas console.log directamente, pero también hay un hook específico)
        script.load()

        # Si el script expone rpc.exports y hay config, invocar init
        if config:
            try:
                if hasattr(script.exports_sync, "init"):
                    script.exports_sync.init(config)
            except Exception as e:
                log.debug(f"Script {name} no expone init(): {e}")

        loaded = LoadedScript(
            name=name,
            source_path=source_path,
            script=script,
            config=config or {},
        )
        self._loaded_scripts.append(loaded)
        log.info(f"Script cargado: [{name}]")
        return loaded

    def load_script_file(
        self,
        path: Path,
        name: Optional[str] = None,
        config: Optional[dict] = None,
    ) -> LoadedScript:
        """Carga un script desde archivo."""
        source = path.read_text(encoding="utf-8")
        return self.load_script(
            source=source,
            name=name or path.stem,
            source_path=path,
            config=config,
        )

    def _build_message_handler(self, script_name: str) -> Callable:
        """Construye un handler de mensajes que prefija por nombre de script."""
        def handler(message: dict, data: Optional[bytes]) -> None:
            msg_type = message.get("type", "?")
            if msg_type == "send":
                payload = message.get("payload", "")
                # Si es un evento estructurado del probe, no lo logueamos (ruido)
                # — los handlers custom lo procesan
                is_structured_event = (
                    isinstance(payload, dict) and "event" in payload
                )
                if not is_structured_event:
                    log.info(f"[{script_name}] {payload}")
            elif msg_type == "log":
                # console.log/warn/error del JS
                level = message.get("level", "info")
                payload = message.get("payload", "")
                if level == "error":
                    log.error(f"[{script_name}] {payload}")
                elif level == "warning":
                    log.warning(f"[{script_name}] {payload}")
                else:
                    log.info(f"[{script_name}] {payload}")
            elif msg_type == "error":
                desc = message.get("description", "?")
                file_name = message.get("fileName", "?")
                line = message.get("lineNumber", "?")
                col = message.get("columnNumber", "?")
                log.error(f"[{script_name}] JS ERROR: {desc} ({file_name}:{line}:{col})")
                stack = message.get("stack")
                if stack:
                    log.error(f"[{script_name}] stack:\n{stack}")

            for custom_handler in self._message_handlers:
                try:
                    custom_handler(script_name, message, data)
                except Exception as e:
                    log.debug(f"Handler custom falló: {e}")

        return handler

    def on_message(self, handler: Callable) -> None:
        """Registra un handler extra para mensajes (para capturar a sesión, etc.)."""
        self._message_handlers.append(handler)

    @property
    def loaded_scripts(self) -> list[LoadedScript]:
        return list(self._loaded_scripts)
