/**
 * @name SSL Pinning Universal Bypass
 * @platform android
 * @category ssl_pinning
 * @technique universal_ssl_bypass
 * @targets javax.net.ssl.SSLContext, okhttp3.CertificatePinner, com.android.org.conscrypt.TrustManagerImpl
 * @author bazzingakit
 * @version 1.0
 * @description Bypass de SSL pinning combinando hooks de múltiples implementaciones comunes.
 */

Java.perform(function () {
    console.log("[ssl_bypass] Instalando hooks universales...");

    // 1. SSLContext.init: sustituye TrustManager por uno permisivo
    try {
        var SSLContext = Java.use("javax.net.ssl.SSLContext");
        var TrustManager = Java.registerClass({
            name: "com.bazzingakit.TrustAll",
            implements: [Java.use("javax.net.ssl.X509TrustManager")],
            methods: {
                checkClientTrusted: function (chain, authType) {},
                checkServerTrusted: function (chain, authType) {},
                getAcceptedIssuers: function () { return []; }
            }
        });
        var tmArray = [TrustManager.$new()];
        SSLContext.init.overload(
            "[Ljavax.net.ssl.KeyManager;",
            "[Ljavax.net.ssl.TrustManager;",
            "java.security.SecureRandom"
        ).implementation = function (km, tm, sr) {
            console.log("[ssl_bypass] SSLContext.init → TrustManager reemplazado");
            this.init(km, tmArray, sr);
        };
    } catch (e) {
        console.log("[ssl_bypass] SSLContext.init no disponible: " + e);
    }

    // 2. OkHttp3 CertificatePinner.check
    ["okhttp3.CertificatePinner", "com.squareup.okhttp3.CertificatePinner"].forEach(function (className) {
        try {
            var Pinner = Java.use(className);
            Pinner.check.overload("java.lang.String", "java.util.List").implementation = function () {
                console.log("[ssl_bypass] OkHttp CertificatePinner.check bypass");
            };
        } catch (e) {
            // clase no presente
        }
    });

    // 3. Conscrypt TrustManagerImpl (Android 7+)
    try {
        var TMImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
        TMImpl.checkTrustedRecursive.implementation = function () {
            console.log("[ssl_bypass] TrustManagerImpl.checkTrustedRecursive bypass");
            return Java.use("java.util.ArrayList").$new();
        };
    } catch (e) {
        // no aplicable
    }

    // 4. TrustKit (si está presente)
    try {
        var TrustKit = Java.use("com.datatheorem.android.trustkit.pinning.OkHostnameVerifier");
        TrustKit.verify.overload("java.lang.String", "javax.net.ssl.SSLSession").implementation = function () {
            console.log("[ssl_bypass] TrustKit.verify bypass");
            return true;
        };
    } catch (e) {
        // no aplicable
    }

    console.log("[ssl_bypass] Hooks instalados.");
});
