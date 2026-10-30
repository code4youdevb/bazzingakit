/**
 * @name Reactive Analysis Probe
 * @platform android
 * @category detection
 * @technique multi_hook_observer
 * @author bazzingakit
 * @version 1.0
 * @description Probe pasivo que observa la app sin bypassear nada. Captura excepciones, checks de root, llamadas a System.exit, strings de UI, clases cargadas y RASP indicators.
 */

(function () {
    var EVENT_LIMITS = {
        loaded_class: 50,
        exception: 30,
        file_exists: 50,
        runtime_exec: 20,
        system_exit: 10,
        ui_text: 30,
        build_prop: 20,
        rasp_indicator: 50,
    };
    var counters = {};

    function emit(type, data) {
        counters[type] = (counters[type] || 0) + 1;
        var limit = EVENT_LIMITS[type] || 100;
        if (counters[type] > limit) return;
        data.event = type;
        data.t = Date.now();
        send(data);
    }

    var raspPatterns = [
        { id: "promon_shield", re: /no\.promon\.|com\.promon\.sse|libshield/i },
        { id: "guardsquare_dexguard", re: /com\.guardsquare|dexguard/i },
        { id: "appdome", re: /com\.appdome|adc_platform/i },
        { id: "talsec_freerasp", re: /com\.aheaditec\.(talsec|freerasp)/i },
        { id: "zimperium", re: /com\.zimperium|com\.zdefend/i },
        { id: "build38_tak", re: /com\.build38/i },
        { id: "verimatrix", re: /com\.verimatrix|whitecryption/i },
        { id: "hst_vcs", re: /br\.com\.hst\.vcs/i },
        { id: "jscrambler", re: /com\.jscrambler/i },
        { id: "rootbeer", re: /com\.scottyab\.rootbeer/i },
        { id: "trustkit", re: /com\.datatheorem\.(android|mobile)\.trustkit/i },
    ];

    function classifyRasp(name) {
        for (var i = 0; i < raspPatterns.length; i++) {
            if (raspPatterns[i].re.test(name)) return raspPatterns[i].id;
        }
        return null;
    }

    var suspiciousRootPaths = [
        "/system/bin/su", "/system/xbin/su", "/sbin/su",
        "/system/app/Superuser", "/data/local/tmp/su",
        "/system/bin/magisk", "/sbin/magisk", "/data/adb/magisk",
        "/system/etc/init.d/99SuperSUDaemon"
    ];

    function isRootPath(path) {
        if (!path) return false;
        for (var i = 0; i < suspiciousRootPaths.length; i++) {
            if (path.indexOf(suspiciousRootPaths[i]) !== -1) return true;
        }
        return false;
    }

    var blockingKeywords = [
        "JAILBREAK", "ROOT_DETECTED", "EMULATOR_DETECTED", "FRIDA_DETECTED",
        "Dispositivo no permitido", "Device not allowed",
        "rooted device", "modified device", "unsafe environment",
        "Magisk", "SuperSU"
    ];

    function hasBlockingKeyword(s) {
        if (!s) return null;
        for (var i = 0; i < blockingKeywords.length; i++) {
            if (s.indexOf(blockingKeywords[i]) !== -1) return blockingKeywords[i];
        }
        return null;
    }

    Java.perform(function () {
        send({ event: "probe_start", t: Date.now() });

        // 1. Enumerar clases cargadas (snapshot inicial)
        try {
            Java.enumerateLoadedClasses({
                onMatch: function (name) {
                    var rasp = classifyRasp(name);
                    if (rasp) {
                        emit("rasp_indicator", { rasp: rasp, class: name });
                    }
                },
                onComplete: function () {
                    send({ event: "enumerate_done", t: Date.now() });
                }
            });
        } catch (e) {
            send({ event: "probe_error", phase: "enumerate", error: String(e) });
        }

        // 2. Hook Throwable.<init> para capturar excepciones relevantes
        try {
            var Throwable = Java.use("java.lang.Throwable");
            Throwable.$init.overload("java.lang.String").implementation = function (msg) {
                if (msg) {
                    var blocking = hasBlockingKeyword(msg);
                    var typeName = this.$className;
                    if (blocking
                        || /SSL|Certificate|Trust|Pinning|UnverifiedCert/.test(typeName)
                        || /Root|Jailbreak|Emulator|Frida/.test(msg)) {
                        emit("exception", {
                            type: typeName,
                            message: msg,
                            blocking_keyword: blocking,
                        });
                    }
                }
                return this.$init(msg);
            };
        } catch (e) { /* */ }

        // 3. Hook File.exists para detectar checks de root
        try {
            var File = Java.use("java.io.File");
            File.exists.implementation = function () {
                var path = this.getAbsolutePath();
                if (isRootPath(path)) {
                    emit("file_exists", { path: path, kind: "root_check" });
                }
                return this.exists();
            };
        } catch (e) { /* */ }

        // 4. Hook Runtime.exec
        try {
            var Runtime = Java.use("java.lang.Runtime");
            Runtime.exec.overload("java.lang.String").implementation = function (cmd) {
                if (cmd && (cmd.indexOf("su") === 0 || cmd.indexOf("which su") !== -1
                          || cmd.indexOf("magisk") !== -1)) {
                    emit("runtime_exec", { command: cmd, kind: "root_check" });
                }
                return this.exec(cmd);
            };
        } catch (e) { /* */ }

        // 5. Hook System.exit y Process.killProcess
        try {
            var System = Java.use("java.lang.System");
            System.exit.implementation = function (code) {
                emit("system_exit", { code: code, source: "System.exit" });
                return this.exit(code);
            };
        } catch (e) { /* */ }
        try {
            var Process = Java.use("android.os.Process");
            Process.killProcess.implementation = function (pid) {
                emit("system_exit", { pid: pid, source: "Process.killProcess" });
                return this.killProcess(pid);
            };
        } catch (e) { /* */ }

        // 6. Hook TextView.setText y Toast para capturar UI strings sospechosas
        try {
            var TextView = Java.use("android.widget.TextView");
            TextView.setText.overload("java.lang.CharSequence").implementation = function (cs) {
                try {
                    var s = cs ? cs.toString() : "";
                    var blocking = hasBlockingKeyword(s);
                    if (blocking) {
                        emit("ui_text", {
                            text: s.substring(0, 200),
                            blocking_keyword: blocking,
                            widget: "TextView"
                        });
                    }
                } catch (e) { /* */ }
                return this.setText(cs);
            };
        } catch (e) { /* */ }

        try {
            var Toast = Java.use("android.widget.Toast");
            Toast.makeText.overload(
                "android.content.Context", "java.lang.CharSequence", "int"
            ).implementation = function (ctx, text, duration) {
                try {
                    var s = text ? text.toString() : "";
                    var blocking = hasBlockingKeyword(s);
                    if (blocking) {
                        emit("ui_text", {
                            text: s.substring(0, 200),
                            blocking_keyword: blocking,
                            widget: "Toast"
                        });
                    }
                } catch (e) { /* */ }
                return this.makeText(ctx, text, duration);
            };
        } catch (e) { /* */ }

        // 7. Hook Build properties (detección de emulador)
        try {
            var Build = Java.use("android.os.Build");
            // Capturar lecturas de campos sensibles (no podemos hookear field reads directamente,
            // pero sí podemos reportar el valor inicial)
            emit("build_prop", { fingerprint: Build.FINGERPRINT.value });
            emit("build_prop", { model: Build.MODEL.value });
            emit("build_prop", { tags: Build.TAGS.value });
            emit("build_prop", { hardware: Build.HARDWARE.value });
        } catch (e) { /* */ }

        // 8. Hook ClassLoader.loadClass para detectar carga tardía de RASP
        try {
            var ClassLoader = Java.use("java.lang.ClassLoader");
            ClassLoader.loadClass.overload("java.lang.String").implementation = function (name) {
                var rasp = classifyRasp(name);
                if (rasp) {
                    emit("rasp_indicator", { rasp: rasp, class: name, source: "loadClass" });
                }
                return this.loadClass(name);
            };
        } catch (e) { /* */ }

        send({ event: "probe_ready", t: Date.now() });
    });
})();
