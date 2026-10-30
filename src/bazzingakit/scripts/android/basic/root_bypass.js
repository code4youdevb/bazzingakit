/**
 * @name Root Detection Bypass
 * @platform android
 * @category root_detection
 * @technique multi_rootcheck_bypass
 * @targets com.scottyab.rootbeer.RootBeer, java.io.File.exists, java.lang.Runtime.exec
 * @author bazzingakit
 * @version 1.0
 * @description Bypass de checks de root más comunes: RootBeer, existencia de binarios su/magisk, Build.TAGS.
 */

Java.perform(function () {
    console.log("[root_bypass] Instalando hooks...");

    // 1. RootBeer
    try {
        var RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
        [
            "isRooted", "isRootedWithBusyBoxCheck",
            "detectRootManagementApps", "detectPotentiallyDangerousApps",
            "checkForSuBinary", "checkForDangerousProps",
            "detectTestKeys", "checkForMagiskBinary",
            "checkSuExists", "checkForBusyBoxBinary"
        ].forEach(function (method) {
            try {
                RootBeer[method].overloads.forEach(function (overload) {
                    overload.implementation = function () {
                        console.log("[root_bypass] RootBeer." + method + " → false");
                        return false;
                    };
                });
            } catch (e) { /* método no existe en esta versión */ }
        });
    } catch (e) {
        // RootBeer no presente
    }

    // 2. File.exists con paths sospechosos
    var File = Java.use("java.io.File");
    var suspiciousPaths = [
        "/system/bin/su", "/system/xbin/su", "/sbin/su",
        "/system/app/Superuser.apk", "/data/local/tmp/su",
        "/system/bin/magisk", "/sbin/magisk",
        "/data/adb/magisk", "/system/etc/init.d/99SuperSUDaemon"
    ];
    File.exists.implementation = function () {
        var path = this.getAbsolutePath();
        for (var i = 0; i < suspiciousPaths.length; i++) {
            if (path.indexOf(suspiciousPaths[i]) !== -1) {
                console.log("[root_bypass] File.exists(" + path + ") → false");
                return false;
            }
        }
        return this.exists();
    };

    // 3. Runtime.exec con "su" o "which su"
    var Runtime = Java.use("java.lang.Runtime");
    Runtime.exec.overload("java.lang.String").implementation = function (cmd) {
        if (cmd && (cmd.indexOf("su") === 0 || cmd.indexOf("which su") !== -1
                   || cmd.indexOf("magisk") !== -1)) {
            console.log("[root_bypass] Runtime.exec(" + cmd + ") bloqueado");
            throw Java.use("java.io.IOException").$new("Permission denied");
        }
        return this.exec(cmd);
    };

    // 4. Build.TAGS para detectar "test-keys"
    try {
        var Build = Java.use("android.os.Build");
        Build.TAGS.value = "release-keys";
        console.log("[root_bypass] Build.TAGS → release-keys");
    } catch (e) {
        console.log("[root_bypass] No se pudo modificar Build.TAGS: " + e);
    }

    console.log("[root_bypass] Hooks instalados.");
});
