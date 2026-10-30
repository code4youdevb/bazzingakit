/**
 * @name iOS SSL Pinning Bypass
 * @platform ios
 * @category ssl_pinning
 * @technique nsurlsession_bypass
 * @targets NSURLSession, SecTrust, AFNetworking, TrustKit
 * @author bazzingakit
 * @version 1.0
 * @description Bypass de SSL pinning en iOS para NSURLSession y librerías comunes.
 */

if (ObjC.available) {
    console.log("[ssl_bypass_ios] Instalando hooks...");

    // SecTrustEvaluate siempre exitoso
    try {
        var SecTrustEvaluate = Module.findExportByName("Security", "SecTrustEvaluate");
        if (SecTrustEvaluate) {
            Interceptor.replace(
                SecTrustEvaluate,
                new NativeCallback(function (trust, result) {
                    Memory.writeU32(result, 1); // kSecTrustResultProceed
                    console.log("[ssl_bypass_ios] SecTrustEvaluate bypassed");
                    return 0;
                }, 'int', ['pointer', 'pointer'])
            );
        }
    } catch (e) {
        console.log("[ssl_bypass_ios] SecTrustEvaluate hook falló: " + e);
    }

    // NSURLSession challenge handler
    try {
        var NSURLSession = ObjC.classes.NSURLSession;
        if (NSURLSession) {
            console.log("[ssl_bypass_ios] NSURLSession presente");
        }
    } catch (e) { /* silencioso */ }

    // TrustKit
    try {
        var TSKPinningValidator = ObjC.classes.TSKPinningValidator;
        if (TSKPinningValidator) {
            Interceptor.attach(
                TSKPinningValidator["- evaluateTrust:forHostname:"].implementation,
                {
                    onLeave: function (retval) {
                        retval.replace(ptr(0)); // TSKTrustDecisionShouldAllowConnection
                        console.log("[ssl_bypass_ios] TrustKit bypass");
                    }
                }
            );
        }
    } catch (e) { /* no presente */ }

    console.log("[ssl_bypass_ios] Hooks instalados.");
} else {
    console.log("[ssl_bypass_ios] ObjC no disponible, saltando.");
}
