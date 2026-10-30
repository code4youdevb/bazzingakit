/**
 * @name RASP Runtime Probe
 * @platform android
 * @category detection
 * @technique enumerate_loaded_classes
 * @author bazzingakit
 * @version 1.0
 * @description Enumera clases cargadas en runtime y reporta patrones de RASPs conocidos y sospechosos.
 */

Java.perform(function () {
    var patterns = [
        { rasp: "promon_shield", regex: /no\.promon\.|com\.promon\.sse|shield/i },
        { rasp: "guardsquare_dexguard", regex: /com\.guardsquare|dexguard/i },
        { rasp: "appdome", regex: /com\.appdome|adc_|\.appdome\./i },
        { rasp: "talsec_freerasp", regex: /com\.aheaditec\.(talsec|freerasp)/i },
        { rasp: "zimperium", regex: /com\.zimperium|com\.zdefend/i },
        { rasp: "build38_tak", regex: /com\.build38/i },
        { rasp: "verimatrix", regex: /com\.verimatrix|com\.insidesecure|whitecryption/i },
        { rasp: "hst_vcs", regex: /br\.com\.hst\.vcs/i },
        { rasp: "jscrambler", regex: /com\.jscrambler/i },
        { rasp: "rootbeer", regex: /com\.scottyab\.rootbeer/i },
        { rasp: "trustkit", regex: /com\.datatheorem\.(android|mobile)\.trustkit/i },
    ];

    var findings = {};
    var total = 0;

    Java.enumerateLoadedClasses({
        onMatch: function (className) {
            total++;
            for (var i = 0; i < patterns.length; i++) {
                if (patterns[i].regex.test(className)) {
                    var rasp_id = patterns[i].rasp;
                    if (!findings[rasp_id]) findings[rasp_id] = [];
                    findings[rasp_id].push(className);
                    break;
                }
            }
        },
        onComplete: function () {
            send({
                type: "rasp_probe_result",
                total_classes: total,
                findings: findings,
            });
        }
    });
});
