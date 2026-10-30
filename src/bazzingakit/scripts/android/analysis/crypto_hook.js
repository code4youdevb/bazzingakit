/**
 * @name Crypto Operations Hook
 * @platform android
 * @category crypto_analysis
 * @technique javax_crypto_hook
 * @targets javax.crypto.Cipher, javax.crypto.spec.SecretKeySpec, javax.crypto.spec.IvParameterSpec, java.security.MessageDigest
 * @author bazzingakit
 * @version 1.0
 * @description Loguea operaciones crypto (AES, DES, HMAC, hashes) con key, IV, input, output y stack trace.
 */

Java.perform(function () {
    console.log("[crypto_hook] Instalando hooks...");

    var Base64 = Java.use("android.util.Base64");
    function b64(bytes) {
        if (bytes === null || bytes === undefined) return null;
        return Base64.encodeToString(bytes, 2).trim();  // NO_WRAP
    }

    function getStack() {
        var Exception = Java.use("java.lang.Exception");
        var Log = Java.use("android.util.Log");
        return Log.getStackTraceString(Exception.$new()).split("\n").slice(2, 8).join(" ← ");
    }

    // 1. Cipher.init: captura algoritmo, modo, llave, IV
    try {
        var Cipher = Java.use("javax.crypto.Cipher");
        Cipher.init.overload("int", "java.security.Key").implementation = function (mode, key) {
            var algo = this.getAlgorithm();
            var keyBytes = key.getEncoded ? key.getEncoded() : null;
            send({
                type: "crypto_init",
                algorithm: algo,
                mode: mode,
                key: b64(keyBytes)
            });
            return this.init(mode, key);
        };

        Cipher.init.overload(
            "int", "java.security.Key", "java.security.spec.AlgorithmParameterSpec"
        ).implementation = function (mode, key, spec) {
            var algo = this.getAlgorithm();
            var keyBytes = key.getEncoded ? key.getEncoded() : null;
            var ivBytes = null;
            try {
                var IvSpec = Java.use("javax.crypto.spec.IvParameterSpec");
                if (spec && spec.$className === "javax.crypto.spec.IvParameterSpec") {
                    ivBytes = Java.cast(spec, IvSpec).getIV();
                }
            } catch (e) { /* spec no es IvParameterSpec */ }
            send({
                type: "crypto_init",
                algorithm: algo,
                mode: mode,
                key: b64(keyBytes),
                iv: b64(ivBytes)
            });
            return this.init(mode, key, spec);
        };

        // 2. Cipher.doFinal: captura input/output
        Cipher.doFinal.overload("[B").implementation = function (input) {
            var output = this.doFinal(input);
            send({
                type: "crypto_doFinal",
                algorithm: this.getAlgorithm(),
                input: b64(input),
                output: b64(output),
                stack: getStack()
            });
            return output;
        };
    } catch (e) {
        console.log("[crypto_hook] Cipher hook falló: " + e);
    }

    // 3. MessageDigest (SHA, MD5, etc.)
    try {
        var MD = Java.use("java.security.MessageDigest");
        MD.digest.overload().implementation = function () {
            var output = this.digest();
            send({
                type: "digest",
                algorithm: this.getAlgorithm(),
                output: b64(output),
                stack: getStack()
            });
            return output;
        };
    } catch (e) {
        console.log("[crypto_hook] MessageDigest hook falló: " + e);
    }

    // 4. MAC (HMAC)
    try {
        var Mac = Java.use("javax.crypto.Mac");
        Mac.doFinal.overload("[B").implementation = function (input) {
            var output = this.doFinal(input);
            send({
                type: "mac",
                algorithm: this.getAlgorithm(),
                input: b64(input),
                output: b64(output),
                stack: getStack()
            });
            return output;
        };
    } catch (e) {
        console.log("[crypto_hook] Mac hook falló: " + e);
    }

    console.log("[crypto_hook] Hooks instalados.");
});
