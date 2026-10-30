# bazzingakit

Framework de análisis de seguridad móvil para Android y iOS. Combina Frida, objection, detección de RASP y técnicas de bypass en una sola herramienta CLI.

## Características

- Detección estática y runtime de protecciones (RASP, SSL pinning, root/jailbreak detection, anti-tamper)
- Loop adaptativo: probe reactivo → análisis → recomendación → bypass → re-validación
- Soporte para Android (USB/adb) e iOS (USB o network vía SSH)
- Wrapper para objection con detección automática de modo
- Instalación de certificados de Burp Suite (bind mount o módulo Magisk)
- Sistema de scripts: built-in + carpeta personal con auto-registro

---

## Instalación

### Recomendado: usar venv

Se recomienda **fuertemente** instalar bazzingakit en un virtualenv para evitar conflictos con otras herramientas Python (mitmproxy, semgrep, etc.) que comparten dependencias.

#### Windows

```bash
python -m venv C:\bazzingakit-env
C:\bazzingakit-env\Scripts\activate
cd C:\ruta\a\bazzingakit
pip install -e .
pip install frida frida-tools objection
```

Para usar después: abre cualquier terminal y ejecuta `C:\bazzingakit-env\Scripts\activate`.

**Tip:** crea un `.bat` en tu escritorio:

```bat
@echo off
cd C:\Users\<tu_usuario>\Desktop\Movil
call C:\bazzingakit-env\Scripts\activate
cmd /k
```

#### Linux / Mac

```bash
python3 -m venv ~/bazzingakit-env
source ~/bazzingakit-env/bin/activate
cd ~/path/to/bazzingakit
pip install -e .
pip install frida frida-tools objection
```

Añade al `~/.bashrc` o `~/.zshrc`:
```bash
alias bzk-env="source ~/bazzingakit-env/bin/activate"
```

### Verificación

```bash
bazzingakit --version
bazzingakit doctor
```

### Dependencias externas opcionales

- **adb**: para Android. Viene con Android Studio platform-tools o desde [developer.android.com](https://developer.android.com/tools/releases/platform-tools).
- **nox_adb**: para emulador Nox. Viene con Nox.
- **openssl**: para `proxy setup-burp`. Windows: `choco install openssl` o slproweb.com.
- **frida-server en iPhone**: Sileo/Cydia con fuente `https://build.frida.re`.
- **OpenSSH en iPhone**: Sileo/Cydia (paquete `openssh`), solo si vas a usar modo network.
- **libimobiledevice**: para iOS USB. Windows: imobiledevice-net; Linux: `apt install libimobiledevice-utils`; Mac: `brew install libimobiledevice`.

---

## Comandos: referencia completa

### `bazzingakit doctor`

Diagnóstico integral del entorno: Python, dependencias, adb, frida, perfil activo, conexión.

```bash
bazzingakit doctor
```

### `bazzingakit config` — gestión de perfiles

| Comando | Descripción |
|---|---|
| `config init` | Inicializa `~/.bazzingakit/config.yaml` |
| `config show` | Muestra perfiles y cuál está activo |
| `config add-profile <nombre> --platform <android\|ios> [opciones]` | Añade perfil |
| `config use <nombre>` | Cambia perfil activo |
| `config remove <nombre>` | Elimina perfil |
| `config test` | Prueba conexión del perfil activo |
| `config setup-ssh-key [perfil]` | (iOS) SSH sin password automáticamente |
| `config path` | Imprime ruta del archivo config |

**Ejemplos:**

```bash
# Android con Nox
bazzingakit config add-profile nox --platform android \
    --adb-path C:\adb\nox_adb.exe --adb-port 62001

# Android genérico (avd, dispositivo físico)
bazzingakit config add-profile fisico --platform android

# iOS modo USB (sin SSH)
bazzingakit config add-profile iphone --platform ios

# iOS modo network (con SSH)
bazzingakit config add-profile iphone --platform ios \
    --ssh-host 192.168.43.17 --ssh-user mobile

bazzingakit config use iphone
bazzingakit config setup-ssh-key iphone
```

### `bazzingakit device`

| Comando | Descripción |
|---|---|
| `device list` | Lista dispositivos detectados |
| `device info` | Modelo, OS, arch, root |
| `device shell <comando>` | Comando shell remoto |
| `device packages` | Paquetes/apps de usuario |

### `bazzingakit frida` — gestión de frida-server

| Comando | Descripción |
|---|---|
| `frida status` | Versión cliente/server, compatibilidad |
| `frida setup` | (Android) Descarga + push + arranca |
| `frida start` / `frida stop` | (Android) Arranca/detiene |
| `frida install <ruta>` | (Android) Sube binario local |
| `frida sync [--direction]` | Iguala versiones cliente↔server |
| `frida setup-ios` | (iOS network) Relanza en 0.0.0.0:27042 |
| `frida setup-ios --usb` | (iOS) Lanza iproxy USB→TCP |
| `frida setup-ios --bind 127.0.0.1` | (iOS) Modo seguro local |

### `bazzingakit ios`

| Comando | Descripción |
|---|---|
| `ios info` | Estado del iPhone (USB o network según perfil) |
| `ios apps [--filter X]` | Lista bundle IDs de apps |

### `bazzingakit rasp` — detección de RASP

| Comando | Descripción |
|---|---|
| `rasp detect <package>` | Análisis estático del APK |
| `rasp analyze <ruta.apk>` | Igual con APK local |
| `rasp scan-runtime <package> [--spawn]` | Runtime via Frida |
| `rasp list` | Firmas conocidas |

### `bazzingakit analyze` y `bazzingakit run`

```bash
# Solo análisis (sin ejecutar)
bazzingakit analyze com.app

# Modo orquestado (detecta RASP + ejecuta playbook recomendado)
bazzingakit run com.app

# Modo simple: cargar uno o más scripts personalizados
bazzingakit run com.app --script C:\ruta\miscript.js
bazzingakit run com.app --script a.js --script b.js
bazzingakit run com.app --script miscript.js --attach
bazzingakit run com.app --script miscript.js --duration 30
```

El modo `--script` es equivalente a `frida -U -f <pkg> -l script.js` pero con sesión, captura de logs y soporte multi-script.

### `bazzingakit investigate` — loop adaptativo

```bash
bazzingakit investigate com.app
bazzingakit investigate com.app --auto-apply
bazzingakit investigate com.app --auto-apply --bisect
bazzingakit investigate com.app --kill-when-done
bazzingakit investigate com.app --duration 15 --max-iterations 3
```

**Cómo funciona:**

1. **Iteración 1**: spawn con probe reactivo. Observa clases cargadas, excepciones SSL, checks de root, strings de bloqueo, `System.exit`, etc.
2. **Análisis**: clasifica eventos en findings categorizados.
3. **Recomendación**: mapea findings a scripts del registry.
4. **Pregunta interactiva** (o `--auto-apply`): aplicar y re-probar.
5. **Iteración 2+**: spawn con bypasses combinados (sin probe), valida supervivencia.
6. **Por defecto** la app queda corriendo lista para usar.

### `bazzingakit objection` (alias: `obj`)

```bash
bazzingakit objection com.app
bazzingakit obj com.app
bazzingakit obj com.app -c "ios sslpinning disable"
bazzingakit obj com.app -c "android root disable" -c "android sslpinning disable"
bazzingakit obj com.app --usb
bazzingakit obj com.app --network
bazzingakit obj com.app --print-cmd
```

Detección automática del modo:

| Perfil | Modo |
|---|---|
| Android | USB |
| iOS sin `ssh_host` | USB |
| iOS con `ssh_host` | network |

### `bazzingakit proxy` — certificado de Burp en Android

```bash
# Bind mount (default, no permanente)
bazzingakit proxy setup-burp

# Permanente: módulo Magisk (requiere reboot)
bazzingakit proxy setup-burp --permanent

bazzingakit proxy setup-burp --port 8080 --host 127.0.0.1
bazzingakit proxy setup-burp --skip-burp-check

bazzingakit proxy status --hash 9a5ba575.0
bazzingakit proxy clean
```

**Pre-requisitos:**
- Burp Suite abierto en `127.0.0.1:8080`
- `openssl` en PATH
- Dispositivo con Magisk
- Configura el proxy de la WiFi del Android manualmente

### `bazzingakit scripts`

```bash
bazzingakit scripts list
bazzingakit scripts list --category root_detection
bazzingakit scripts show "Passive App Observer"
```

### `bazzingakit playbook`

```bash
bazzingakit playbook list
bazzingakit playbook show standard_android
```

### `bazzingakit session`

```bash
bazzingakit session list
bazzingakit session show <session_id>
bazzingakit session path <session_id>
```

### `bazzingakit ai`

```bash
bazzingakit ai setup
bazzingakit ai test
bazzingakit ai analyze <session_id>
```

---

## Flujo típico

### Android (Nox emulator)

```bash
bazzingakit config init
bazzingakit config add-profile nox --platform android --adb-path C:\adb\nox_adb.exe --adb-port 62001
bazzingakit config use nox
bazzingakit doctor
bazzingakit frida setup

bazzingakit rasp detect com.banco.app
bazzingakit run com.banco.app --script C:\Users\<tu_usuario>\.bazzingakit\scripts\android\observer.js
bazzingakit investigate com.banco.app --auto-apply
```

### iOS modo USB (recomendado para uso normal)

```bash
bazzingakit config add-profile iphone --platform ios
bazzingakit config use iphone

# Conecta el iPhone por USB y confía en el equipo

bazzingakit ios info
bazzingakit ios apps --filter banco
bazzingakit run com.banpais.mbanking --script observer.js
bazzingakit obj com.banpais.mbanking -c "ios sslpinning disable"
```

### iOS modo network (avanzado, requiere SSH)

```bash
bazzingakit config add-profile iphone --platform ios --ssh-host 192.168.43.17 --ssh-user mobile
bazzingakit config use iphone
bazzingakit config setup-ssh-key

bazzingakit frida setup-ios
bazzingakit ios apps --filter banco
bazzingakit run com.banpais.mbanking --script observer.js
```

---

## Estructura de scripts

**Built-in** (`src/bazzingakit/scripts/`):
```
android/basic/        ssl_bypass_universal, root_bypass, ui_block_hider, exit_blocker, antifrida_generic
android/analysis/     crypto_hook
android/detection/    rasp_probe, reactive_probe
ios/basic/            ssl_bypass_ios, jailbreak_bypass
```

**Personales** (`~/.bazzingakit/scripts/`): cualquier `.js` con header `@name @platform @category` se auto-registra. Ver `docs/scripts_guide.md`.

---

## Troubleshooting

### Android

**`frida start` dice "ya corriendo" pero `run` falla:**
```bash
bazzingakit device shell "ps -ef | grep -v grep | grep frida-server"
bazzingakit frida stop && bazzingakit frida start
```

**App muere con los bypasses combinados:**
```bash
bazzingakit investigate com.app --auto-apply --bisect
```

**Conflictos de dependencias al instalar:**
- Estás en Python global. Crea un venv como se describe arriba.

### iOS

**SSH pide password en cada operación:**
```bash
bazzingakit config setup-ssh-key
```

**`unable to connect to remote frida-server`:**
- frida-server escucha solo en `127.0.0.1`. Ejecuta `bazzingakit frida setup-ios`.

**En modo USB no aparece el iPhone:**
- Instala libimobiledevice
- Conecta el iPhone, desbloquéalo, y confía en el equipo
- Verifica con `frida-ls-devices`

**`frida-ps -U` funciona pero bazzingakit no encuentra el iPhone:**
- Tu perfil tiene `ssh_host` configurado pero el iPhone solo está accesible por USB.
- Crea un perfil USB-only: `bazzingakit config add-profile iphone-usb --platform ios` (sin ssh).

---

## Documentación adicional

- [`docs/scripts_guide.md`](docs/scripts_guide.md) — Cómo escribir e integrar scripts personales
- [`docs/ios_guide.md`](docs/ios_guide.md) — Guía completa de setup iOS
