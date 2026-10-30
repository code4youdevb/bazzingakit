/**
 * @name UI Block Strings Hider
 * @platform android
 * @category jailbreak_detection
 * @technique ui_string_replace
 * @targets android.widget.TextView, android.widget.Toast
 * @author bazzingakit
 * @version 1.0
 * @description Reemplaza strings tipo JAILBREAK_DETECTED, "Dispositivo no permitido", etc. en TextView y Toast para evitar que la app muestre pantallas de bloqueo.
 */

Java.perform(function () {
    var blockingKeywords = [
        "JAILBREAK", "ROOT_DETECTED", "EMULATOR_DETECTED", "FRIDA_DETECTED",
        "Dispositivo no permitido", "Device not allowed",
        "rooted device", "modified device", "unsafe environment",
        "Magisk", "SuperSU"
    ];

    function isBlocking(s) {
        if (!s) return false;
        for (var i = 0; i < blockingKeywords.length; i++) {
            if (s.indexOf(blockingKeywords[i]) !== -1) return true;
        }
        return false;
    }

    try {
        var TextView = Java.use("android.widget.TextView");
        TextView.setText.overload("java.lang.CharSequence").implementation = function (cs) {
            try {
                var s = cs ? cs.toString() : "";
                if (isBlocking(s)) {
                    console.log("[ui_block_hider] TextView blocked: " + s.substring(0, 80));
                    return this.setText("");
                }
            } catch (e) { /* */ }
            return this.setText(cs);
        };
    } catch (e) {
        console.log("[ui_block_hider] TextView hook failed: " + e);
    }

    try {
        var Toast = Java.use("android.widget.Toast");
        Toast.makeText.overload(
            "android.content.Context", "java.lang.CharSequence", "int"
        ).implementation = function (ctx, text, duration) {
            try {
                var s = text ? text.toString() : "";
                if (isBlocking(s)) {
                    console.log("[ui_block_hider] Toast blocked: " + s.substring(0, 80));
                    return this.makeText(ctx, "", duration);
                }
            } catch (e) { /* */ }
            return this.makeText(ctx, text, duration);
        };
    } catch (e) {
        console.log("[ui_block_hider] Toast hook failed: " + e);
    }

    console.log("[ui_block_hider] Hooks instalados.");
});
