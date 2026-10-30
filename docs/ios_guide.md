# Guía rápida — iOS

Cómo usar bazzingakit con un iPhone jailbroken.

## Pre-requisitos en el iPhone

1. **Jailbreak activo** (Dopamine, palera1n, unc0ver, checkra1n)
2. **OpenSSH** instalado (Cydia → buscar "OpenSSH"; Sileo lo trae prácticamente igual)
3. **Frida** instalado:
   - En Sileo/Cydia: añade fuente `https://build.frida.re` y busca el paquete "Frida"
4. **iPhone y PC en la misma red WiFi**
5. **Anota la IP** del iPhone: Settings → WiFi → toca tu red → IP Address

> Tip: si la IP cambia en cada reconexión, considera reservar IP por MAC en tu router, o usar el modo `--usb` de bazzingakit.

## Setup en bazzingakit

```bash
# 1. Crear perfil (cambia 192.168.1.50 por la IP real)
bazzingakit config add-profile iphone \
    --platform ios \
    --ssh-host 192.168.1.50 \
    --ssh-user mobile

# 2. Activar el perfil
bazzingakit config use iphone

# 3. Verificar conexión SSH y estado
bazzingakit ios info
```

`ios info` te dice:
- Si el SSH conecta
- Modelo y versión iOS
- Si frida-server está corriendo
- Si está bindeado a 127.0.0.1 (modo local) o 0.0.0.0 (red)

## Configurar SSH sin password (recomendado)

Para no tener que escribir password en cada operación:

```bash
# En tu PC, genera clave si no tienes
ssh-keygen -t ed25519

# Copia la pública al iPhone (te pedirá password una sola vez)
ssh-copy-id mobile@192.168.1.50
```

Después actualiza el perfil para que use la clave:

```bash
bazzingakit config remove iphone
bazzingakit config add-profile iphone \
    --platform ios \
    --ssh-host 192.168.1.50 \
    --ssh-user mobile \
    --ssh-key C:\Users\tu_usuario\.ssh\id_ed25519
```

## Lanzar frida-server para que la PC pueda conectar

Por defecto, frida-server en iPhone escucha **solo en `127.0.0.1`**, lo que impide que tu PC conecte por la red. Hay que relanzarlo:

```bash
# Modo network (default) — relanza frida-server en 0.0.0.0:27042
bazzingakit frida setup-ios

# Modo USB con iproxy (más seguro, requiere libimobiledevice instalado)
bazzingakit frida setup-ios --usb

# Volver al modo seguro (solo conexión local)
bazzingakit frida setup-ios --bind 127.0.0.1
```

> Atención: `0.0.0.0` expone frida a toda la red. Solo usa esto en redes confiables (tu casa, hotspot personal). En cafetería o oficina, prefiere `--usb`.

## Listar apps instaladas

```bash
bazzingakit ios apps
bazzingakit ios apps --filter banco
```

Te da los bundle IDs que necesitas para los siguientes comandos.

## Análisis de una app

Igual que en Android:

```bash
# Ejecutar un script personalizado
bazzingakit run com.banpais.mbanking --script C:\ruta\observer_ios.js

# Loop iterativo adaptativo (cuando los analyzers iOS estén)
bazzingakit investigate com.banpais.mbanking
```

## Troubleshooting

**SSH no conecta:**
- ¿La IP cambió? `Settings → WiFi → toca red → IP Address`
- ¿OpenSSH instalado en el iPhone?
- Prueba manual: `ssh mobile@<ip>`

**`frida-ls-devices` no muestra el iPhone:**
- frida-server está bindeado a `127.0.0.1` solo. Ejecuta `bazzingakit frida setup-ios`
- Verifica con: `ssh mobile@<ip> "lsof -i :27042"`

**"Address already in use":**
- Ya hay otro frida-server corriendo. `bazzingakit frida setup-ios` lo mata y relanza.

**iproxy no encontrado (modo `--usb`):**
- Windows: instala libimobiledevice-win32
- Linux: `sudo apt install libimobiledevice-utils`
- Mac: `brew install libimobiledevice`
