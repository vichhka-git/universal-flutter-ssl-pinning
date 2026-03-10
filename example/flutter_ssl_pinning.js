"use strict";

var TARGET_MODULE = "libflutter.so";

var HOOK_CANDIDATES = [
  { name: "FUN_00bc7a5c", rva: "0xac7a5c", params: 3, sig: "void FUN_00bc7a5c(undefined8 param_1,undefined8 param_2,undefined1 *param_3);" }
];

function hookCandidate(mod, candidate) {
    var addr = mod.base.add(candidate.rva);
    if (addr.compare(mod.base.add(mod.size)) >= 0) {
        console.log("[-] " + candidate.name + ": RVA " + candidate.rva + " outside module bounds");
        return;
    }
    try {
        Interceptor.attach(addr, {
            onLeave: function (retval) {
                retval.replace(ptr(1));
            }
        });
        console.log("[+] Hooked " + candidate.name + " @ " + addr);
    } catch (e) {
        console.log("[-] Failed to hook " + candidate.name + ": " + e.message);
    }
}

function bypassSslPinning() {
    var mod = Process.findModuleByName(TARGET_MODULE);
    if (!mod) {
        console.log("[-] Module not found: " + TARGET_MODULE);
        return;
    }
    console.log("[*] SSL pinning bypass starting (" + HOOK_CANDIDATES.length + " candidate(s))");
    HOOK_CANDIDATES.forEach(function (c) { hookCandidate(mod, c); });
    console.log("[+] Done.");
}

setTimeout(bypassSslPinning, 1000);
