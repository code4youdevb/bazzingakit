/**
 * @name System Exit Blocker
 * @platform android
 * @category anti_kill
 * @technique system_exit_block
 * @targets java.lang.System.exit, android.os.Process.killProcess
 * @author bazzingakit
 * @version 1.0
 * @description Bloquea llamadas a System.exit y Process.killProcess para evitar que la app se mate cuando detecta condiciones inseguras.
 */

Java.perform(function () {
    try {
        var System = Java.use("java.lang.System");
        System.exit.implementation = function (code) {
            console.log("[exit_blocker] System.exit(" + code + ") bloqueado");
            // No llamamos a this.exit, simplemente retornamos
        };
    } catch (e) {
        console.log("[exit_blocker] System.exit hook failed: " + e);
    }

    try {
        var Process = Java.use("android.os.Process");
        Process.killProcess.implementation = function (pid) {
            console.log("[exit_blocker] Process.killProcess(" + pid + ") bloqueado");
            // No matar
        };
    } catch (e) {
        console.log("[exit_blocker] killProcess hook failed: " + e);
    }

    console.log("[exit_blocker] Hooks instalados.");
});
