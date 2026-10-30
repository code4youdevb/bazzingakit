/**
 * @name iOS Jailbreak Detection Bypass
 * @platform ios
 * @category jailbreak_detection
 * @technique multi_jb_bypass
 * @targets NSFileManager, fopen, stat, canOpenURL
 * @author bazzingakit
 * @version 1.0
 * @description Bypass de checks comunes de jailbreak: filesystem, URL schemes, syscalls.
 */

if (ObjC.available) {
    console.log("[jb_bypass] Instalando hooks...");

    var suspiciousPaths = [
        "/Applications/Cydia.app", "/Applications/Sileo.app", "/Applications/Zebra.app",
        "/private/var/lib/apt", "/private/var/lib/cydia",
        "/bin/bash", "/bin/sh", "/usr/sbin/sshd",
        "/etc/apt", "/etc/ssh",
        "/usr/bin/ssh", "/var/jb", "/var/mobile/Library/SBSettings",
        "/Library/MobileSubstrate/MobileSubstrate.dylib"
    ];

    var suspiciousURLs = ["cydia://", "sileo://", "zbra://", "undecimus://", "filza://"];

    function isSuspicious(str) {
        if (!str) return false;
        for (var i = 0; i < suspiciousPaths.length; i++) {
            if (str.indexOf(suspiciousPaths[i]) !== -1) return true;
        }
        return false;
    }

    // NSFileManager fileExistsAtPath:
    try {
        var NSFileManager = ObjC.classes.NSFileManager;
        var origFileExists = NSFileManager["- fileExistsAtPath:"];
        Interceptor.attach(origFileExists.implementation, {
            onEnter: function (args) {
                this.path = new ObjC.Object(args[2]).toString();
            },
            onLeave: function (retval) {
                if (isSuspicious(this.path)) {
                    console.log("[jb_bypass] fileExistsAtPath(" + this.path + ") → NO");
                    retval.replace(ptr(0));
                }
            }
        });
    } catch (e) {
        console.log("[jb_bypass] NSFileManager hook falló: " + e);
    }

    // canOpenURL:
    try {
        var UIApplication = ObjC.classes.UIApplication;
        var canOpen = UIApplication["- canOpenURL:"];
        Interceptor.attach(canOpen.implementation, {
            onEnter: function (args) {
                this.url = new ObjC.Object(args[2]).absoluteString().toString();
            },
            onLeave: function (retval) {
                for (var i = 0; i < suspiciousURLs.length; i++) {
                    if (this.url.indexOf(suspiciousURLs[i]) === 0) {
                        console.log("[jb_bypass] canOpenURL(" + this.url + ") → NO");
                        retval.replace(ptr(0));
                        return;
                    }
                }
            }
        });
    } catch (e) { /* UIApplication no disponible en todos los contextos */ }

    // fopen/stat nativos
    try {
        var fopen = Module.findExportByName(null, "fopen");
        Interceptor.attach(fopen, {
            onEnter: function (args) {
                this.path = args[0].readCString();
            },
            onLeave: function (retval) {
                if (this.path && isSuspicious(this.path)) {
                    console.log("[jb_bypass] fopen(" + this.path + ") → NULL");
                    retval.replace(ptr(0));
                }
            }
        });
    } catch (e) { /* silencioso */ }

    try {
        var stat = Module.findExportByName(null, "stat");
        Interceptor.attach(stat, {
            onEnter: function (args) {
                this.path = args[0].readCString();
            },
            onLeave: function (retval) {
                if (this.path && isSuspicious(this.path)) {
                    console.log("[jb_bypass] stat(" + this.path + ") → -1");
                    retval.replace(ptr(-1));
                }
            }
        });
    } catch (e) { /* silencioso */ }

    console.log("[jb_bypass] Hooks instalados.");
} else {
    console.log("[jb_bypass] ObjC no disponible.");
}
