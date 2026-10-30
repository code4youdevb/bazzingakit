# Cómo añadir scripts al kit

Esta guía describe el flujo recomendado para iterar técnicas nuevas: empezar con un script Frida manual, validarlo, y eventualmente integrarlo a bazzingakit.

## Flujo en 4 pasos

### 1. Escribe el script y pruébalo con Frida directo

Sin tocar el framework. Solo Frida + tu emulador o dispositivo:

```bash
frida -U -f com.app.objetivo -l miscript.js
```

Itera hasta que el script haga lo que quieres.

### 2. Añade el header de bazzingakit (5 líneas mínimo)

Cuando el script funciona, ponle un header en formato JSDoc al inicio. Ejemplo mínimo:

```javascript
/**
 * @name Nombre Descriptivo del Script
 * @platform android
 * @category root_detection
 * @author tu_nombre
 * @version 1.0
 */

Java.perform(function () {
    // ... tu código ...
});
```

Campos del header:

| Campo | Obligatorio | Ejemplo | Notas |
|---|---|---|---|
| `@name` | sí | `Mi Bypass Custom` | Nombre legible único |
| `@platform` | sí | `android` o `ios` | |
| `@category` | sí | `root_detection` | Ver categorías abajo |
| `@technique` | no | `okhttp_pinner_v3` | Identificador técnico |
| `@targets` | no | `okhttp3.CertificatePinner, com.app.X` | Clases que hookea |
| `@author` | no | `tu_nombre` | |
| `@version` | no | `1.0` | |
| `@description` | no | `Bypass de pinning custom de la app X` | |

**Categorías reconocidas por el framework:**

- `ssl_pinning`
- `root_detection`
- `jailbreak_detection`
- `emulator_detection`
- `anti_kill`
- `anti_detection`
- `crypto_analysis`
- `detection` (probes/observadores)

Puedes inventar nuevas categorías; solo recuerda que el `Recommender` del comando `investigate` solo sugiere las que conoce. Para que tu script sea sugerido automáticamente, usa una de las de arriba o extiende el `recommender.py`.

### 3. Pruébalo en bazzingakit con `--script`

Sin moverlo aún. Solo apunta al archivo:

```bash
bazzingakit run com.app.objetivo --script C:\ruta\miscript.js
```

Esto:
- Spawnea la app (igual que `frida -U -f`)
- Carga tu script
- Captura el output en una sesión (`~/.bazzingakit/sessions/...`)
- Mantiene viva la sesión hasta Ctrl+C

Si quieres attach en vez de spawn:

```bash
bazzingakit run com.app.objetivo --script miscript.js --attach
```

Múltiples scripts:

```bash
bazzingakit run com.app.objetivo --script a.js --script b.js
```

Duración fija (sin Ctrl+C):

```bash
bazzingakit run com.app.objetivo --script miscript.js --duration 30
```

### 4. Cuando esté listo, deja el script en la carpeta de usuario

Cópialo a:

```
Linux/Mac:  ~/.bazzingakit/scripts/
Windows:    C:\Users\<tu_usuario>\.bazzingakit\scripts\
```

Subcarpetas opcionales para organizarte (`android/`, `ios/`, etc.). El registry escanea recursivo.

A partir de ahí:

- `bazzingakit scripts list` lo muestra
- `bazzingakit scripts show "Nombre Descriptivo"` muestra detalles
- Si la categoría es reconocida, `investigate` lo sugiere automáticamente cuando detecte un finding relacionado

## Ejemplo: ciclo completo

```bash
# 1. Escribe + prueba con Frida directo
notepad miscript.js
frida -U -f com.app.test -l miscript.js
# ... iteras hasta que funciona ...

# 2. Añades header (editas miscript.js)

# 3. Prueba en bazzingakit
bazzingakit run com.app.test --script miscript.js

# 4. Lo dejas en la carpeta de usuario
copy miscript.js %USERPROFILE%\.bazzingakit\scripts\android\

# A partir de aquí, el script es visible al framework:
bazzingakit scripts list
bazzingakit investigate com.app.test --auto-apply
# (si el Recommender mapea su categoría, lo sugerirá)
```

## Convenciones de scripts

Para que tu script juegue bien con bazzingakit:

**1. Logging.** Usa `console.log` para mensajes humanos. Si quieres datos estructurados (que `investigate` analice), usa `send({event: "tipo", ...})`. El framework distingue automáticamente entre log textual y eventos estructurados.

**2. Hooks defensivos.** Envuelve cada hook en try/catch para que si una clase no existe, los demás hooks sigan funcionando:

```javascript
Java.perform(function () {
    try {
        var Pinner = Java.use("okhttp3.CertificatePinner");
        Pinner.check.implementation = function () { /* ... */ };
        console.log("[miscript] OkHttp pinner hookeado");
    } catch (e) {
        console.log("[miscript] OkHttp no presente, saltando");
    }
});
```

**3. Prefija logs.** `console.log("[mi_script] mensaje")` ayuda a identificar de dónde viene cada línea cuando hay varios scripts cargados juntos.

**4. Si combinas con otros scripts via `investigate`**, evita variables/funciones a nivel top con nombres genéricos (`var helper = ...`). El framework envuelve cada script en un IIFE para aislar scopes, pero algunos casos pueden filtrar.

## Ver scripts existentes como referencia

Los scripts built-in son ejemplos vivos:

```
src/bazzingakit/scripts/android/basic/
src/bazzingakit/scripts/android/analysis/
src/bazzingakit/scripts/android/detection/
src/bazzingakit/scripts/ios/basic/
```

`reactive_probe.js` es el más completo, ahí ves el formato de `send({event: ...})` que el `EventAnalyzer` consume.
