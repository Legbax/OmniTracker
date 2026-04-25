/**
 * Layer 4 — OmniShield Hook Scanner / Detector (Lightweight)
 *
 * Fast scans that won't timeout on heavy apps like Snapchat:
 *   1. Native module enumeration — find injected .so files
 *   2. Native inline hook detection — scan function prologues for trampolines
 *   3. System property snapshot — read real vs spoofed values
 *   4. RWX memory region scan — detect code injection
 *   5. Xposed hook registry — quick check (no class enumeration)
 *   6. /proc/self/maps parsing — find hidden modules
 */

(function () {

  // ─── Re-attach dedup ──────────────────────────────────────────────────────
  // When the agent is re-attached to an already-instrumented process (script
  // reload, target crash-recover), repeating the one-shot scans duplicates
  // every finding. Use a globalThis marker so a fresh load from Frida resets,
  // but a reload of the same VM skips.
  if (globalThis._OT_SCANNER_RAN) {
    send({
      layer: "scanner",
      type: "__SKIP__",
      value: "Scanner already ran in this VM; skipping duplicate one-shot scans",
      ts: Date.now(),
      backtrace: []
    });
    return;
  }
  globalThis._OT_SCANNER_RAN = true;

  function emit(type, value, extra) {
    var payload = {
      layer: "scanner",
      type: type,
      value: value !== undefined && value !== null ? String(value) : null,
      ts: Date.now()
    };
    if (extra) {
      for (var k in extra) payload[k] = extra[k];
    }
    send(payload);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // 1. LOADED NATIVE MODULES — find OmniShield's injected .so files
  // ═══════════════════════════════════════════════════════════════════════════

  var allModules = Process.enumerateModules();
  var suspiciousModules = [];
  var suspiciousKeywords = [
    "omnishield", "xposed", "lsposed", "edxposed", "riru", "zygisk",
    "substrate", "frida", "gadget", "libhook", "sandhook", "whale",
    "pine", "dobby", "reveny", "lspd", "epic",
    // A13+ framework keywords
    "shamiko", "zygisk_next", "zn_module", "lsplant", "tricky",
    "hmapatch", "suspend_hide", "tee_simulator", "teesimulator"
  ];

  for (var i = 0; i < allModules.length; i++) {
    var mod = allModules[i];
    var nameLower = mod.name.toLowerCase();
    var pathLower = mod.path.toLowerCase();

    var isSuspicious = false;
    var matchedKeyword = "";
    for (var ki = 0; ki < suspiciousKeywords.length; ki++) {
      if (nameLower.indexOf(suspiciousKeywords[ki]) !== -1 ||
          pathLower.indexOf(suspiciousKeywords[ki]) !== -1) {
        isSuspicious = true;
        matchedKeyword = suspiciousKeywords[ki];
        break;
      }
    }
    // Also flag modules from unusual paths
    if (!isSuspicious && (pathLower.indexOf("/data/adb/") !== -1 ||
        (pathLower.indexOf("/data/data/") !== -1 && nameLower.indexOf("lib") === -1))) {
      isSuspicious = true;
      matchedKeyword = "unusual_path";
    }

    if (isSuspicious) {
      suspiciousModules.push(mod);
      emit("SCANNER_MODULE_SUSPICIOUS", mod.name, {
        path: mod.path,
        base: mod.base.toString(),
        size: mod.size,
        matchedKeyword: matchedKeyword
      });
    }
  }

  emit("SCANNER_MODULES_TOTAL", allModules.length + " modules loaded", {
    total: allModules.length,
    suspicious: suspiciousModules.length,
    suspiciousNames: suspiciousModules.map(function (m) { return m.name; })
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // 2. NATIVE INLINE HOOK DETECTION — scan function prologues
  // ═══════════════════════════════════════════════════════════════════════════

  var nativeFuncsToCheck = [
    { lib: "libc.so", funcs: [
      "open", "openat", "read", "close", "stat", "lstat", "fstat",
      "access", "execve", "ioctl", "connect", "recvmsg", "getifaddrs",
      "uname", "sysinfo", "ptrace", "prctl", "mmap", "mprotect",
      "__system_property_get", "opendir", "readdir", "socket", "kill"
    ]},
    { lib: "libdl.so", funcs: ["dlopen", "android_dlopen_ext", "dlsym"] },
    { lib: "libEGL.so", funcs: ["eglQueryString"] },
    { lib: "libGLESv2.so", funcs: ["glGetString"] }
  ];

  var nativeHookedCount = 0;
  var nativeHookedList = [];

  for (var ni = 0; ni < nativeFuncsToCheck.length; ni++) {
    var libEntry = nativeFuncsToCheck[ni];
    for (var nj = 0; nj < libEntry.funcs.length; nj++) {
      var funcName = libEntry.funcs[nj];
      try {
        var addr = Module.findExportByName(libEntry.lib, funcName);
        if (!addr) continue;

        var bytes = new Uint8Array(addr.readByteArray(16));
        var isHooked = false;
        var hookType = "";

        // ARM64: LDR + BR trampoline
        if (bytes[3] === 0x58 || bytes[3] === 0xD6) {
          isHooked = true; hookType = "ARM64_TRAMPOLINE";
        }
        // ARM64: B (unconditional branch)
        if ((bytes[3] & 0xFC) === 0x14) {
          isHooked = true; hookType = "ARM64_BRANCH";
        }
        // ARM64: BRK/SVC (Frida-style breakpoint)
        if (bytes[3] === 0xD4) {
          isHooked = true; hookType = "ARM64_BRK";
        }
        // x86: JMP/CALL at start
        if (bytes[0] === 0xE9 || bytes[0] === 0xE8) {
          isHooked = true; hookType = "X86_JMP";
        }
        // x64: MOV RAX, IMM64 + JMP RAX
        if (bytes[0] === 0x48 && bytes[1] === 0xB8) {
          isHooked = true; hookType = "X64_MOV_JMP";
        }

        if (isHooked) {
          nativeHookedCount++;
          var fullName = libEntry.lib + "!" + funcName;
          nativeHookedList.push(fullName);
          emit("SCANNER_NATIVE_HOOK", fullName, {
            lib: libEntry.lib, func: funcName, hookType: hookType,
            address: addr.toString(),
            prologueHex: Array.from(bytes.slice(0, 8)).map(function (b) {
              return ("0" + b.toString(16)).slice(-2);
            }).join(" ")
          });
        }
      } catch (e) {}
    }
  }

  emit("SCANNER_NATIVE_HOOKS_TOTAL", nativeHookedCount + " native functions appear hooked", {
    total: nativeHookedCount,
    functions: nativeHookedList
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // 3. SYSTEM PROPERTY SNAPSHOT — compare real vs spoofed
  // ═══════════════════════════════════════════════════════════════════════════

  // v1.52.2 additions — all variants must match their canonical sibling (see
  // OmniShield invariants #41 serials, #42 fingerprints+build-ids, #44 carrier).
  // Ordering groups canonical-sibling clusters together for readability in logs.
  var propsToCheck = [
    // Serials — invariant #41 (6 variants must equal Build.SERIAL)
    "ro.serialno", "ro.boot.serialno",
    "ro.vendor.product.serial", "persist.sys.serialno",
    "vendor.serialno", "ril.serialnumber",
    // Model / brand / device
    "ro.product.model", "ro.product.manufacturer", "ro.product.brand",
    "ro.product.device", "ro.product.name", "ro.product.board",
    // Fingerprints — invariant #42 (7 variants must be identical)
    "ro.build.fingerprint", "ro.bootimage.build.fingerprint",
    "ro.vendor.build.fingerprint", "ro.odm.build.fingerprint",
    "ro.system.build.fingerprint", "ro.system_ext.build.fingerprint",
    "ro.product.build.fingerprint",
    // Build IDs — invariant #42 (7 variants must equal kCoherentBuildId)
    "ro.build.id", "ro.bootimage.build.id",
    "ro.vendor.build.id", "ro.odm.build.id",
    "ro.system.build.id", "ro.system_ext.build.id", "ro.product.build.id",
    // Build metadata
    "ro.build.display.id", "ro.build.tags", "ro.build.type",
    "ro.build.version.security_patch", "ro.build.version.incremental",
    // Hardware
    "ro.hardware", "ro.board.platform",
    "ro.secure", "ro.debuggable",
    "ro.boot.verifiedbootstate", "ro.boot.flash.locked",
    // Telephony — invariant #44 (MCC/MNC must match US_CARRIERS[idx])
    "gsm.sim.operator.numeric", "gsm.sim.operator.iso-country",
    "gsm.sim.operator.alpha", "gsm.operator.numeric",
    "gsm.operator.iso-country", "gsm.operator.alpha",
    // Misc
    "net.hostname", "wifi.interface", "ro.sf.lcd_density"
  ];

  var propGetPtr = Module.findExportByName("libc.so", "__system_property_get");
  if (propGetPtr) {
    var propGetFunc = new NativeFunction(propGetPtr, "int", ["pointer", "pointer"]);
    var propNameBuf = Memory.alloc(256);
    var propValBuf = Memory.alloc(256);

    var propValues = {};
    for (var pi = 0; pi < propsToCheck.length; pi++) {
      try {
        propNameBuf.writeUtf8String(propsToCheck[pi]);
        propValBuf.writeByteArray(new ArrayBuffer(256)); // clear buffer
        propGetFunc(propNameBuf, propValBuf);
        var val = propValBuf.readCString();
        if (val && val.length > 0) {
          propValues[propsToCheck[pi]] = val;
        }
      } catch (e) {}
    }

    emit("SCANNER_PROP_SNAPSHOT", Object.keys(propValues).length + " properties read", {
      properties: propValues,
      note: "Compare with Build fields to detect OmniShield spoofing"
    });

    // ═════════════════════════════════════════════════════════════════════════
    // 3b. OMNISHIELD v1.52.2 COHERENCE CHECKS — cross-variant divergence
    // ═════════════════════════════════════════════════════════════════════════
    // Any divergence here indicates a coverage gap in OmniShield's
    // multi-partition sysprop handler or a cache-drift between layers.
    // Emits one alert per group so log readers can triage quickly.

    // --- Fingerprint variants (invariant #42: all 7 must be identical) ---
    var fpVariants = [
      "ro.build.fingerprint", "ro.bootimage.build.fingerprint",
      "ro.vendor.build.fingerprint", "ro.odm.build.fingerprint",
      "ro.system.build.fingerprint", "ro.system_ext.build.fingerprint",
      "ro.product.build.fingerprint"
    ];
    var fpSeen = {};
    var fpPresent = [];
    for (var fi = 0; fi < fpVariants.length; fi++) {
      var v = propValues[fpVariants[fi]];
      if (v) { fpSeen[v] = (fpSeen[v] || []).concat([fpVariants[fi]]); fpPresent.push(fpVariants[fi]); }
    }
    var fpDistinct = Object.keys(fpSeen);
    if (fpDistinct.length > 1) {
      emit("COHERENCE_FINGERPRINT_DIVERGENCE",
        fpDistinct.length + " distinct fingerprints across " + fpPresent.length + " variants", {
        distinctCount: fpDistinct.length,
        groups: fpSeen,
        note: "OmniShield invariant #42 broken — all 7 fingerprint partitions must be identical"
      });
    } else if (fpDistinct.length === 1) {
      emit("COHERENCE_FINGERPRINT_OK", "all " + fpPresent.length + " fingerprint variants match", {
        fingerprint: fpDistinct[0], variantsCovered: fpPresent.length
      });
    }

    // --- Build-ID variants (invariant #42: all 7 must equal kCoherentBuildId) ---
    var bidVariants = [
      "ro.build.id", "ro.bootimage.build.id", "ro.vendor.build.id",
      "ro.odm.build.id", "ro.system.build.id",
      "ro.system_ext.build.id", "ro.product.build.id"
    ];
    var bidSeen = {};
    var bidPresent = [];
    for (var bi = 0; bi < bidVariants.length; bi++) {
      var bv = propValues[bidVariants[bi]];
      if (bv) { bidSeen[bv] = (bidSeen[bv] || []).concat([bidVariants[bi]]); bidPresent.push(bidVariants[bi]); }
    }
    var bidDistinct = Object.keys(bidSeen);
    if (bidDistinct.length > 1) {
      emit("COHERENCE_BUILDID_DIVERGENCE",
        bidDistinct.length + " distinct build-ids across " + bidPresent.length + " variants", {
        distinctCount: bidDistinct.length,
        groups: bidSeen,
        note: "OmniShield invariant #42 broken — all 7 build-id partitions must equal kCoherentBuildId"
      });
    } else if (bidDistinct.length === 1) {
      emit("COHERENCE_BUILDID_OK", "all " + bidPresent.length + " build-id variants match", {
        buildId: bidDistinct[0], variantsCovered: bidPresent.length
      });
    }

    // --- Serial variants (invariant #41: all 6 must equal Build.SERIAL) ---
    var serVariants = [
      "ro.serialno", "ro.boot.serialno", "ro.vendor.product.serial",
      "persist.sys.serialno", "vendor.serialno", "ril.serialnumber"
    ];
    var serSeen = {};
    var serPresent = [];
    for (var srv = 0; srv < serVariants.length; srv++) {
      var sv = propValues[serVariants[srv]];
      if (sv) { serSeen[sv] = (serSeen[sv] || []).concat([serVariants[srv]]); serPresent.push(serVariants[srv]); }
    }
    var serDistinct = Object.keys(serSeen);
    if (serDistinct.length > 1) {
      emit("COHERENCE_SERIAL_DIVERGENCE",
        serDistinct.length + " distinct serials across " + serPresent.length + " variants", {
        distinctCount: serDistinct.length,
        groups: serSeen,
        note: "OmniShield invariant #41 broken — serial variants must all equal Build.SERIAL (Java layer)"
      });
    } else if (serDistinct.length === 1) {
      emit("COHERENCE_SERIAL_OK", "all " + serPresent.length + " serial variants match", {
        serial: serDistinct[0], variantsCovered: serPresent.length
      });
    }

    // --- Fingerprint internal-coherence (invariant #42 tag/type retail pair) ---
    // Format: brand/product/device:release/BUILD_ID/INCREMENTAL:TYPE/TAGS
    // Cross-check BUILD_ID against ro.build.id, TYPE against ro.build.type,
    // TAGS against ro.build.tags. A mismatch means one hook is missing.
    if (fpDistinct.length === 1) {
      var fp = fpDistinct[0];
      var slash = fp.split("/");
      // ["brand","product","device:release","BUILDID","INCREMENTAL:TYPE,TAGS"]
      if (slash.length === 5) {
        var fpBuildId = slash[3];
        var tail = slash[4].split(":");   // ["INCREMENTAL", "TYPE,TAGS"]
        var typeTag = tail.length >= 2 ? tail[1].split("/") : [];
        var fpType = typeTag[0] || "";
        var fpTags = typeTag[1] || "";
        var mismatches = [];
        if (propValues["ro.build.id"] && propValues["ro.build.id"] !== fpBuildId) {
          mismatches.push("buildId:fp=" + fpBuildId + " vs prop=" + propValues["ro.build.id"]);
        }
        if (propValues["ro.build.type"] && propValues["ro.build.type"] !== fpType) {
          mismatches.push("type:fp=" + fpType + " vs prop=" + propValues["ro.build.type"]);
        }
        if (propValues["ro.build.tags"] && propValues["ro.build.tags"] !== fpTags) {
          mismatches.push("tags:fp=" + fpTags + " vs prop=" + propValues["ro.build.tags"]);
        }
        // Retail coherence: the pair must be user/release-keys for a
        // locked-bootloader pretense (ro.secure=1, ro.debuggable=0).
        if (fpType && fpTags && (fpType !== "user" || fpTags !== "release-keys")) {
          mismatches.push("retailPair:" + fpType + "/" + fpTags + " (expected user/release-keys)");
        }
        if (mismatches.length > 0) {
          emit("COHERENCE_FINGERPRINT_INTERNAL_MISMATCH",
            mismatches.length + " field(s) mismatch between fingerprint and sibling sysprops", {
            mismatches: mismatches,
            fingerprint: fp,
            note: "OmniShield hook misses one of ro.build.id / ro.build.type / ro.build.tags — invariant #42 C6/C7"
          });
        }
      }
    }

    // --- Telephony carrier coherence (invariant #44 MCC/MNC US table) ---
    // US_CARRIERS[]: T-Mobile 310260, AT&T 310410, Verizon 311480, US Cellular 311580
    var US_MNC_WHITELIST = { "310260": "T-Mobile", "310410": "AT&T",
                             "311480": "Verizon", "311580": "US Cellular" };
    var simNumeric = propValues["gsm.sim.operator.numeric"];
    var netNumeric = propValues["gsm.operator.numeric"];
    var simIso = propValues["gsm.sim.operator.iso-country"];
    var netIso = propValues["gsm.operator.iso-country"];
    var telMismatches = [];
    if (simNumeric && !US_MNC_WHITELIST[simNumeric]) {
      telMismatches.push("gsm.sim.operator.numeric=" + simNumeric + " (not in US_CARRIERS table)");
    }
    if (netNumeric && !US_MNC_WHITELIST[netNumeric]) {
      telMismatches.push("gsm.operator.numeric=" + netNumeric + " (not in US_CARRIERS table)");
    }
    if (simNumeric && netNumeric && simNumeric !== netNumeric) {
      telMismatches.push("SIM/network MCC+MNC mismatch: sim=" + simNumeric + " net=" + netNumeric);
    }
    if (simIso && simIso.toLowerCase() !== "us") {
      telMismatches.push("gsm.sim.operator.iso-country=" + simIso + " (expected 'us')");
    }
    if (netIso && netIso.toLowerCase() !== "us") {
      telMismatches.push("gsm.operator.iso-country=" + netIso + " (expected 'us')");
    }
    if (telMismatches.length > 0) {
      emit("COHERENCE_TELEPHONY_LEAK",
        telMismatches.length + " carrier field(s) incoherent with US_CARRIERS table", {
        mismatches: telMismatches,
        note: "OmniShield invariant #44 broken — seed-derived MCC/MNC must match US_CARRIERS entry"
      });
    }

    // --- Security posture coherence (retail attestation pretense) ---
    // ro.secure=1 + ro.debuggable=0 + ro.boot.verifiedbootstate=green required
    // to make user/release-keys + Build.FINGERPRINT credible to Snap/Argos.
    var secMismatches = [];
    if (propValues["ro.secure"] && propValues["ro.secure"] !== "1") {
      secMismatches.push("ro.secure=" + propValues["ro.secure"] + " (expected 1)");
    }
    if (propValues["ro.debuggable"] && propValues["ro.debuggable"] !== "0") {
      secMismatches.push("ro.debuggable=" + propValues["ro.debuggable"] + " (expected 0)");
    }
    if (propValues["ro.boot.verifiedbootstate"] &&
        propValues["ro.boot.verifiedbootstate"] !== "green") {
      secMismatches.push("ro.boot.verifiedbootstate=" + propValues["ro.boot.verifiedbootstate"] + " (expected 'green')");
    }
    if (propValues["ro.boot.flash.locked"] && propValues["ro.boot.flash.locked"] !== "1") {
      secMismatches.push("ro.boot.flash.locked=" + propValues["ro.boot.flash.locked"] + " (expected 1)");
    }
    if (secMismatches.length > 0) {
      emit("COHERENCE_SECURITY_POSTURE_LEAK",
        secMismatches.length + " security field(s) inconsistent with retail build pretense", {
        mismatches: secMismatches,
        note: "user/release-keys + spoofed fingerprint require locked-bootloader triad — gap undermines attestation"
      });
    }

    // ═════════════════════════════════════════════════════════════════════════
    // 3c. JAVA ↔ NATIVE CROSS-LAYER COHERENCE (Build.* vs ro.*)
    // ═════════════════════════════════════════════════════════════════════════
    // The JNI Build.* field spoof (main.cpp ~L12813) and the native sysprop
    // hook (main.cpp my_system_property_get) are independent code paths.
    // Snap calls both — once via Build.FINGERPRINT (Java) and again via
    // __system_property_get("ro.build.fingerprint") through PackageManager /
    // DroidGuard helpers. Any divergence between them is a tell.
    Java.perform(function () {
      try {
        var Build = Java.use("android.os.Build");
        var VERSION = Java.use("android.os.Build$VERSION");
        var javaVals = {
          "Build.SERIAL":       Build.SERIAL.value,
          "Build.FINGERPRINT":  Build.FINGERPRINT.value,
          "Build.ID":           Build.ID.value,
          "Build.TAGS":         Build.TAGS.value,
          "Build.TYPE":         Build.TYPE.value,
          "Build.BRAND":        Build.BRAND.value,
          "Build.MODEL":        Build.MODEL.value,
          "Build.DEVICE":       Build.DEVICE.value,
          "Build.PRODUCT":      Build.PRODUCT.value,
          "Build.MANUFACTURER": Build.MANUFACTURER.value,
          "Build.HARDWARE":     Build.HARDWARE.value,
          "VERSION.SECURITY_PATCH": VERSION.SECURITY_PATCH.value,
          "VERSION.INCREMENTAL":    VERSION.INCREMENTAL.value,
          "VERSION.RELEASE":        VERSION.RELEASE.value
        };
        // Java → native expected-pair mapping.
        var crossMap = [
          ["Build.SERIAL",       "ro.serialno"],
          ["Build.FINGERPRINT",  "ro.build.fingerprint"],
          ["Build.ID",           "ro.build.id"],
          ["Build.TAGS",         "ro.build.tags"],
          ["Build.TYPE",         "ro.build.type"],
          ["Build.BRAND",        "ro.product.brand"],
          ["Build.MODEL",        "ro.product.model"],
          ["Build.DEVICE",       "ro.product.device"],
          ["Build.PRODUCT",      "ro.product.name"],
          ["Build.MANUFACTURER", "ro.product.manufacturer"],
          ["Build.HARDWARE",     "ro.hardware"],
          ["VERSION.SECURITY_PATCH", "ro.build.version.security_patch"],
          ["VERSION.INCREMENTAL",    "ro.build.version.incremental"],
          ["VERSION.RELEASE",        "ro.build.version.release"]
        ];
        var xlMismatches = [];
        for (var xi = 0; xi < crossMap.length; xi++) {
          var jKey = crossMap[xi][0], nKey = crossMap[xi][1];
          var jVal = javaVals[jKey], nVal = propValues[nKey];
          if (jVal && nVal && jVal !== nVal) {
            xlMismatches.push({ javaField: jKey, javaValue: jVal,
                                nativeKey: nKey, nativeValue: nVal });
          }
        }
        emit("COHERENCE_JAVA_NATIVE_SNAPSHOT",
          Object.keys(javaVals).length + " Java Build fields vs native sysprops", {
          javaValues: javaVals,
          crossChecked: crossMap.length,
          mismatchCount: xlMismatches.length
        });
        if (xlMismatches.length > 0) {
          emit("COHERENCE_JAVA_NATIVE_DIVERGENCE",
            xlMismatches.length + " Java/native Build-field mismatch(es)", {
            mismatches: xlMismatches,
            note: "Snap reads both layers — divergence = OmniShield hook gap (Java or native)"
          });
        }
      } catch (eBld) {
        emit("COHERENCE_JAVA_READ_FAIL", String(eBld), {
          note: "android.os.Build class unavailable — ART may not be ready yet"
        });
      }
    });
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // 4. RWX MEMORY REGIONS — detect code injection
  // ═══════════════════════════════════════════════════════════════════════════

  try {
    var ranges = Process.enumerateRanges("rwx");
    var suspiciousRanges = [];

    for (var ri = 0; ri < ranges.length; ri++) {
      var range = ranges[ri];
      if (range.file && range.file.path &&
          (range.file.path.indexOf("dalvik") !== -1 ||
           range.file.path.indexOf("jit") !== -1 ||
           range.file.path.indexOf("ashmem") !== -1)) {
        continue;
      }
      suspiciousRanges.push({
        base: range.base.toString(),
        size: range.size,
        file: range.file ? range.file.path : "anonymous"
      });
    }

    if (suspiciousRanges.length > 0) {
      emit("SCANNER_RWX_REGIONS", suspiciousRanges.length + " suspicious RWX regions", {
        count: suspiciousRanges.length,
        regions: suspiciousRanges.slice(0, 20)
      });
    }
  } catch (e) {}

  // ═══════════════════════════════════════════════════════════════════════════
  // 5. XPOSED HOOK REGISTRY — quick check without class enumeration
  // ═══════════════════════════════════════════════════════════════════════════

  Java.perform(function () {
    // Quick check: try to access XposedBridge directly (no enumeration)
    var xposedFound = false;

    try {
      var XposedBridge = Java.use("de.robv.android.xposed.XposedBridge");
      var field = XposedBridge.class.getDeclaredField("sHookedMethodCallbacks");
      field.setAccessible(true);
      var map = field.get(null);

      if (map !== null) {
        var size = map.size();
        xposedFound = true;
        emit("SCANNER_XPOSED_REGISTRY", size + " methods hooked via Xposed", {
          total: size
        });

        // Iterate hooks (limited to 50 to avoid timeout)
        if (size > 0) {
          var iterator = map.entrySet().iterator();
          var count = 0;
          var hookedMethods = [];
          while (iterator.hasNext() && count < 50) {
            var entry = iterator.next();
            var method = entry.getKey().toString();
            hookedMethods.push(method.substring(0, 200));
            count++;
          }
          emit("SCANNER_XPOSED_HOOKS_LIST", count + " hooks enumerated", {
            methods: hookedMethods,
            truncated: size > 50
          });
        }
      }
    } catch (e) {}

    // Try LSPosed/Pine if Xposed not found
    if (!xposedFound) {
      var frameworks = [
        "io.github.lsposed.lspd.yahfa.hooker.YahfaHooker",
        "top.canyie.pine.Pine",
        "me.weishu.epic.art.Epic",
        "com.swift.sandhook.SandHook"
      ];
      for (var fi = 0; fi < frameworks.length; fi++) {
        try {
          Java.use(frameworks[fi]);
          emit("SCANNER_HOOK_FRAMEWORK", frameworks[fi], {
            note: "Hook framework class found in process"
          });
          break;
        } catch (e) {}
      }
    }

    // Quick OmniShield detection: try known class names directly
    var omnishieldCandidates = [
      "com.omnishield.core.HookManager",
      "com.omnishield.spoof.DeviceSpoofer",
      "com.omnishield.spoof.IdentityManager",
      "com.omnishield.Module",
      "com.omnishield.MainHook",
      "com.omnishield.OmniShield"
    ];
    for (var oi = 0; oi < omnishieldCandidates.length; oi++) {
      try {
        Java.use(omnishieldCandidates[oi]);
        emit("SCANNER_OMNISHIELD_CLASS", omnishieldCandidates[oi], {
          note: "OmniShield class found!"
        });
      } catch (e) {}
    }
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // 6. /proc/self/maps — find hidden modules not in Frida's module list
  // ═══════════════════════════════════════════════════════════════════════════

  try {
    var openFunc = new NativeFunction(
      Module.findExportByName("libc.so", "open"), "int", ["pointer", "int"]);
    var readFunc = new NativeFunction(
      Module.findExportByName("libc.so", "read"), "int", ["int", "pointer", "int"]);
    var closeFunc = new NativeFunction(
      Module.findExportByName("libc.so", "close"), "int", ["int"]);

    var pathBuf = Memory.alloc(64);
    pathBuf.writeUtf8String("/proc/self/maps");
    var fd = openFunc(pathBuf, 0); // O_RDONLY

    if (fd > 0) {
      var chunk = Memory.alloc(65536);
      var totalRead = "";
      var n;
      while ((n = readFunc(fd, chunk, 65535)) > 0) {
        totalRead += chunk.readUtf8String(n);
        if (totalRead.length > 500000) break; // safety limit
      }
      closeFunc(fd);

      // Parse maps for suspicious entries
      var lines = totalRead.split("\n");
      var moduleSet = {};
      for (var mi = 0; mi < allModules.length; mi++) {
        moduleSet[allModules[mi].path] = true;
      }

      var hiddenModules = [];
      var suspiciousKeywordsMap = [
        "omnishield", "xposed", "lsposed", "edxposed", "riru", "zygisk",
        "frida", "gadget", "hook", "inject", "substrate", "pine", "dobby",
        // A13+ frameworks
        "shamiko", "zn_module", "lsplant", "tricky", "teesimulator"
      ];

      for (var li = 0; li < lines.length; li++) {
        var line = lines[li];
        if (!line || line.length < 10) continue;

        // Extract path (last column after spaces)
        var parts = line.trim().split(/\s+/);
        if (parts.length < 6) continue;
        var mapPath = parts[parts.length - 1];
        if (!mapPath || mapPath.charAt(0) !== "/") continue;

        // Check if it's a .so not in Frida's module list
        if (mapPath.indexOf(".so") !== -1 && !moduleSet[mapPath]) {
          var mapLower = mapPath.toLowerCase();
          for (var ski = 0; ski < suspiciousKeywordsMap.length; ski++) {
            if (mapLower.indexOf(suspiciousKeywordsMap[ski]) !== -1) {
              if (hiddenModules.indexOf(mapPath) === -1) {
                hiddenModules.push(mapPath);
              }
              break;
            }
          }
        }
      }

      if (hiddenModules.length > 0) {
        emit("SCANNER_HIDDEN_MODULES", hiddenModules.length + " hidden modules in /proc/self/maps", {
          modules: hiddenModules
        });
      }
    }
  } catch (e) {}

  // ═══════════════════════════════════════════════════════════════════════════
  // 7. APEX MODULE SNAPSHOT — A12+ system modules live under /apex/
  // ═══════════════════════════════════════════════════════════════════════════

  try {
    var apexModules = [];
    for (var ami = 0; ami < allModules.length; ami++) {
      var amod = allModules[ami];
      if (amod.path && amod.path.indexOf("/apex/") === 0) {
        apexModules.push({ name: amod.name, path: amod.path, base: amod.base.toString(), size: amod.size });
      }
    }
    if (apexModules.length > 0) {
      emit("SCANNER_APEX_MODULES", apexModules.length + " APEX-loaded modules", {
        count: apexModules.length,
        modules: apexModules.slice(0, 40),
        note: "A12+ relocated many system libs under /apex/*"
      });
    }
  } catch (e) {}

  // ═══════════════════════════════════════════════════════════════════════════
  // 8. DELAYED RE-SCAN — catch hooks installed post-init + ART deoptimization
  // ═══════════════════════════════════════════════════════════════════════════

  setTimeout(function () {
    try {
      var rescanFuncs = [
        { lib: "libc.so", funcs: ["open", "openat", "read", "ioctl", "__system_property_get", "getifaddrs", "connect"] },
        { lib: "libdl.so", funcs: ["dlopen", "dlsym"] },
        { lib: "libbinder.so", funcs: ["_ZN7android14IPCThreadState8transactEijRKNS_6ParcelEPS1_j"] }
      ];
      var lateHooks = [];
      for (var ri = 0; ri < rescanFuncs.length; ri++) {
        var libEntry2 = rescanFuncs[ri];
        for (var rj = 0; rj < libEntry2.funcs.length; rj++) {
          var funcName2 = libEntry2.funcs[rj];
          try {
            var addr2 = Module.findExportByName(libEntry2.lib, funcName2);
            if (!addr2) continue;
            var bytes2 = new Uint8Array(addr2.readByteArray(16));
            var isHooked2 = false;
            if (bytes2[3] === 0x58 || bytes2[3] === 0xD6) isHooked2 = true;
            if ((bytes2[3] & 0xFC) === 0x14) isHooked2 = true;
            if (bytes2[3] === 0xD4) isHooked2 = true;
            if (bytes2[0] === 0xE9 || bytes2[0] === 0xE8) isHooked2 = true;
            if (isHooked2) {
              lateHooks.push(libEntry2.lib + "!" + funcName2);
            }
          } catch (e) {}
        }
      }
      if (lateHooks.length > 0) {
        emit("SCANNER_LATE_HOOKS", lateHooks.length + " functions hooked after init", {
          functions: lateHooks,
          note: "Hooks installed between init scan and +3s — may indicate lazy Dobby install or ART deopt"
        });
      }
    } catch (e) {}
  }, 3000);

  // ═══════════════════════════════════════════════════════════════════════════
  // 9. ART DEOPTIMIZATION PROBE — A13+ can force methods back to interpreter
  // ═══════════════════════════════════════════════════════════════════════════

  Java.perform(function () {
    try {
      var Debug = Java.use("android.os.Debug");
      // If android.os.Debug.isDebuggerConnected is frequently queried, apps
      // are probing for instrumentation — log the fact.
      hookIfExists(Debug, "isDebuggerConnected", function () {
        emit("SCANNER_DEBUGGER_PROBE", "isDebuggerConnected()", {
          method: "android.os.Debug.isDebuggerConnected()",
          note: "App queried debugger state — anti-instrumentation probe"
        });
        return Debug.isDebuggerConnected();
      });
    } catch (e) {}

    function hookIfExists(cls, name, impl) {
      try { cls[name].implementation = impl; } catch (e) {}
    }
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // 10. SYSTEM_SERVER BINDER REACHABILITY — confirms Binder is open to us
  // ═══════════════════════════════════════════════════════════════════════════

  try {
    var readlinkPtr2 = Module.findExportByName("libc.so", "readlink");
    if (readlinkPtr2) {
      var readlinkFn = new NativeFunction(readlinkPtr2, "int", ["pointer", "pointer", "int"]);
      var linkBuf2 = Memory.alloc(256);
      var pathBuf2 = Memory.alloc(64);
      pathBuf2.writeUtf8String("/proc/self/fd/0");  // stdin typically
      // Scan low fds for /dev/binder
      var binderOpen = 0;
      for (var fd = 0; fd < 256; fd++) {
        pathBuf2.writeUtf8String("/proc/self/fd/" + fd);
        linkBuf2.writeByteArray(new ArrayBuffer(256));
        var ln = readlinkFn(pathBuf2, linkBuf2, 255);
        if (ln > 0) {
          var target2 = linkBuf2.readCString();
          if (target2 && target2.indexOf("/dev/binder") !== -1) binderOpen++;
        }
      }
      emit("SCANNER_BINDER_OPEN_FDS", "binder_fds=" + binderOpen, {
        count: binderOpen,
        note: "Number of /dev/binder fds open in this process"
      });
    }
  } catch (e) {}

  // ═══════════════════════════════════════════════════════════════════════════
  // 11. SNAP-SPECIFIC NATIVE LIB INVENTORY + ANTI-TAMPER CHECKS
  // ═══════════════════════════════════════════════════════════════════════════
  // From reports/snap_v13.88.1.0_dump/REPORT.md §6 + FORENSIC_REPORT.md:
  // Snap ships a multi-lib native surface with well-known name stems. Ferrite
  // libs (launcher + tracer) are Snap-internal anti-tamper helpers that
  // independently read /proc/self/maps. Map their presence + base/size and
  // probe for get_argos_token export as a cheap "Argos-live" signal.
  try {
    var SNAP_LIB_STEMS = [
      { stem: "libclient.so",          role: "core" },
      { stem: "libcamplat+.",          role: "camera_pipeline" },
      { stem: "libsigx.so",            role: "signature_verification" },
      { stem: "libscplugin.so",        role: "snap_camera_plugin_loader" },
      { stem: "libnloader.so",         role: "native_loader_stub" },
      { stem: "libferrite-launcher",   role: "process_helper" },
      { stem: "libferrite-tracer",     role: "in_process_tracer_AT" },
      { stem: "libbloops",             role: "bloops_sdk" },
      { stem: "libdav1dJNI.so",        role: "av1_decoder" },
      { stem: "libmimalloc.so",        role: "allocator" },
      { stem: "libGWP-ASan.so",        role: "asan_sampler" },
      { stem: "libarcore_sdk_c.so",    role: "arcore" },
      { stem: "libarcore_sdk_jni.so",  role: "arcore_jni" },
      { stem: "libstatic-webp.so",     role: "webp_codec" },
      { stem: "libcpec.",              role: "cpec_extension" }
    ];
    var foundSnapLibs = [];
    var tracerPresent = false;
    var scpluginPresent = false;
    var argosExport = null;
    // Re-enumerate modules to catch ones loaded post-init.
    var modsNow = Process.enumerateModules();
    for (var mi = 0; mi < modsNow.length; mi++) {
      var m = modsNow[mi];
      for (var si = 0; si < SNAP_LIB_STEMS.length; si++) {
        var entry = SNAP_LIB_STEMS[si];
        if (m.name.indexOf(entry.stem) !== -1) {
          foundSnapLibs.push({
            name: m.name,
            role: entry.role,
            base: m.base.toString(),
            size: m.size,
            path: m.path
          });
          if (entry.role === "in_process_tracer_AT") tracerPresent = true;
          if (m.name.indexOf("libscplugin.so") !== -1) scpluginPresent = true;
          // Probe for get_argos_token inside libclient.so / libscplugin.so
          if (entry.role === "core" || m.name.indexOf("libscplugin.so") !== -1) {
            try {
              var exp = Module.findExportByName(m.name, "get_argos_token");
              if (exp && !argosExport) argosExport = { lib: m.name, addr: exp.toString() };
            } catch (eExp) {}
          }
          break;
        }
      }
    }
    if (foundSnapLibs.length > 0) {
      emit("SNAP_NATIVE_LIBS", "count=" + foundSnapLibs.length, {
        libraries: foundSnapLibs,
        tracerPresent: tracerPresent,
        scpluginPresent: scpluginPresent,
        argosExport: argosExport,
        note: "Snap-specific native libs detected in-process"
      });
    }
    if (tracerPresent) {
      emit("SNAP_ANTI_TAMPER_TRACER", "libferrite-tracer present", {
        note: "Snap in-process tracer/watchdog reads /proc/self/maps — OmniShield §1 Layer 7 must hide module"
      });
    }
    if (scpluginPresent) {
      emit("SNAP_SCPLUGIN_LOADED", "libscplugin.so present", {
        note: "Snap camera plugin loader — Argos Runtime.nativeLoad block target per CLAUDE.md §5"
      });
    }
    if (argosExport) {
      emit("SNAP_ARGOS_SYMBOL", "get_argos_token@" + argosExport.lib, argosExport);
    }

    // Structural path-presence check: libcamplat hardcodes /system/lib64/libart.so etc.
    // Log whether those paths resolve (they do on a real Redmi; absence is a red flag for Snap).
    var SNAP_EXPECTED_PATHS = [
      "/system/lib64/libart.so",
      "/system/lib64/egl/libGLES_mali.so",
      "/system/lib64/libOpenCL.so",
      "/system/lib64/libOpenCL-pixel.so"
    ];
    try {
      var statFn = Module.findExportByName("libc.so", "access");
      if (statFn) {
        var accessFn = new NativeFunction(statFn, "int", ["pointer", "int"]);
        var pbuf = Memory.alloc(256);
        var presence = {};
        for (var pi = 0; pi < SNAP_EXPECTED_PATHS.length; pi++) {
          pbuf.writeUtf8String(SNAP_EXPECTED_PATHS[pi]);
          var rc = accessFn(pbuf, 0);  // F_OK
          presence[SNAP_EXPECTED_PATHS[pi]] = (rc === 0);
        }
        emit("SNAP_EXPECTED_SYSLIBS", "checked=" + SNAP_EXPECTED_PATHS.length, {
          presence: presence,
          note: "Snap libcamplat expects these /system/lib64/* paths to exist"
        });
      }
    } catch (eAcc) {}
  } catch (eSnap) {}

  // ═══════════════════════════════════════════════════════════════════════════
  // DONE
  // ═══════════════════════════════════════════════════════════════════════════

  send({
    layer: "scanner",
    type: "__INIT__",
    value: "Layer 4 (Scanner v3 / OmniShield v1.52.2) loaded — module scan, native hook detection, property snapshot(44 keys incl. 7 fingerprint + 7 build-id + 6 serial variants), OmniShield coherence checks (fingerprint-divergence, build-id-divergence, serial-divergence, fingerprint-internal-mismatch, telephony-leak vs US_CARRIERS, security-posture retail-pretense, Java-vs-native Build.* cross-layer divergence), RWX scan, Xposed registry, /proc/self/maps, A13+ framework keywords(Shamiko/ZygiskNext/LSPlant/TrickyStore/TEESimulator), APEX module snapshot, delayed +3s re-scan for late hooks, ART deoptimization probe, Binder fd count, Snap native-lib inventory (libclient/libcamplat/libsigx/libscplugin/libnloader/libferrite-{launcher,tracer}/libbloops/libdav1dJNI/libmimalloc/libGWP-ASan/libarcore/libstatic-webp/libcpec) + get_argos_token symbol probe + expected /system/lib64 path presence",
    ts: Date.now(),
    backtrace: []
  });

})();
