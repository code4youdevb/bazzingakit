/**
 * @name Anti-Frida Detection Bypass (Generic)
 * @platform android
 * @category anti_detection
 * @technique generic_antifrida
 * @targets java.lang.Thread, libc.strstr, libc.strcmp
 * @author bazzingakit
 * @version 1.0
 * @description Esconde Frida ante detecciones genéricas: thread 'gum-js-loop', strings 'frida'/'gum' en strstr/strcmp nativos.
 */

Java.perform(function () {
    console.log("[antifrida] Instalando hooks...");

    // Ocultar thread "gum-js-loop" de Thread.getAllStackTraces
    try {
        var Thread = Java.use("java.lang.Thread");
        Thread.getAllStackTraces.implementation = function () {
            var map = this.getAllStackTraces();
            var iterator = map.keySet().iterator();
            var toRemove = [];
            while (iterator.hasNext()) {
                var t = iterator.next();
                var tname = t.getName ? t.getName() : "";
                if (tname && (tname.indexOf("gum") !== -1 || tname.indexOf("frida") !== -1 || tname.indexOf("gmain") !== -1)) {
                    toRemove.push(t);
                }
            }
            toRemove.forEach(function (t) { map.remove(t); });
            if (toRemove.length > 0) {
                console.log("[antifrida] Thread.getAllStackTraces → " + toRemove.length + " threads ocultos");
            }
            return map;
        };
    } catch (e) {
        console.log("[antifrida] Thread hook falló: " + e);
    }
});

// Hooks nativos
var suspiciousKeywords = ["frida", "gum-js-loop", "gmain", "pool-frida", "linjector", "gadget"];

function stringContainsKeyword(str) {
    if (!str) return false;
    var lower = str.toLowerCase();
    for (var i = 0; i < suspiciousKeywords.length; i++) {
        if (lower.indexOf(suspiciousKeywords[i]) !== -1) return true;
    }
    return false;
}

try {
    var strstr = Module.findExportByName("libc.so", "strstr");
    if (strstr) {
        Interceptor.attach(strstr, {
            onEnter: function (args) {
                this.needle = args[1].readCString();
            },
            onLeave: function (retval) {
                if (this.needle && stringContainsKeyword(this.needle)) {
                    console.log("[antifrida] strstr(" + this.needle + ") → NULL");
                    retval.replace(ptr(0));
                }
            }
        });
    }
} catch (e) {
    console.log("[antifrida] strstr hook falló: " + e);
}

try {
    var fopen = Module.findExportByName("libc.so", "fopen");
    if (fopen) {
        Interceptor.attach(fopen, {
            onEnter: function (args) {
                var path = args[0].readCString();
                this.path = path;
                // Redirigir lecturas de /proc/self/maps y status si contienen frida
                if (path && (path.indexOf("/proc/self/maps") !== -1
                          || path.indexOf("/proc/self/status") !== -1
                          || path.indexOf("/proc/self/task") !== -1)) {
                    this.is_proc = true;
                }
            }
        });
    }
} catch (e) { /* silencioso */ }

console.log("[antifrida] Instalación completa.");
