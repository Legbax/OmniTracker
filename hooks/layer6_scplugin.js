/**
 * Layer 6 — libscplugin.so deep capture (Snapchat-specific, opt-in)
 *
 * Target: libscplugin.so (Snap Argos crypto + identity bulk-reader)
 *
 *   BuildID:    d571075d59f93e57764571dc964b291783614593
 *   Version:    13.89  (string baked at .rodata @ 0x6d073)
 *   APK:        com.snapchat.android v13.89.0.47 (versionCode 283422)
 *   Verified:   bit-identical to dump 2026-04-27 (no update touched the .so).
 *
 * Hookea dos puntos para responder "qué identidad lee el módulo nativo
 * desde sus 44 sysprop callsites, y qué strings cifradas descifra el
 * deobfuscator central":
 *
 *   1) fcn.00088ab4 — el string deobfuscator central (448 xrefs).
 *      Convención: x8 = std::string* destino (libc++ small-string).
 *      Capturamos el output con onLeave y emitimos el plaintext.
 *
 *   2) __system_property_get / find — filtrado por returnAddress dentro
 *      del módulo libscplugin. Capturamos {key, value, caller_offset}
 *      para mapear cada lectura a uno de los 44 callsites enumerados
 *      por el análisis estático del 29-abr.
 *
 * Lista de callsites conocidos (cluster identity 23 + extra 4 + telephony 7
 * + init/otros 3 + find 4 + read 3 = 44). Los offsets quedan anotados en
 * cada evento como `caller_offset` (relativo a libscplugin.base).
 *
 * NO toca libscplugin.text fuera de los hooks Interceptor de Frida (no
 * patches inline). Anti-tamper de la lib se reduce a fcn.001ce02c —
 * lazy/one-shot via dl_iterate_phdr; no monitorea estos puntos.
 *
 * Cap por sesión: 800 deobf strings + ilimitado sysprop reads (típico ~60
 * por signup full).
 */

(function () {
  var LIB_NAME = "libscplugin.so";
  var DEOBF_OFFSET = 0x00088ab4;          // fcn.00088ab4 — deobfuscator
  var MAX_DEOBF_EMITS = 800;

  var deobfCount = 0;
  var seenStrings = {};
  var lib = null;

  function findLib() {
    try {
      lib = Process.getModuleByName(LIB_NAME);
      return true;
    } catch (e) {
      return false;
    }
  }

  function emit(type, value, extra) {
    var payload = {
      layer: "scplugin",
      type: type,
      value: value === null || value === undefined ? null : String(value),
      caller: type,
      stack: [],
      ts: Date.now()
    };
    if (extra) {
      for (var k in extra) payload[k] = extra[k];
    }
    send(payload);
  }

  function emitInit(label, ok, err) {
    send({
      layer: "scplugin",
      type: ok ? "__INIT_HOOK__" : "__INIT_HOOK_FAIL__",
      value: label,
      err: err ? String(err) : undefined,
      caller: "init",
      stack: [],
      ts: Date.now()
    });
  }

  // libc++ std::string layout (24 bytes, ARM64):
  //   byte0.bit0 = 0 → SHORT: byte0=(size<<1), bytes 1..22 = data
  //   byte0.bit0 = 1 → LONG:  bytes 0..7 = cap|tag, 8..15 = size, 16..23 = data ptr
  function readLibcxxString(p) {
    if (p.isNull()) return null;
    var b0 = p.readU8();
    if ((b0 & 1) === 0) {
      var size = b0 >>> 1;
      if (size === 0) return "";
      if (size > 22) return null;        // sanity
      return p.add(1).readUtf8String(size);
    }
    // LONG
    var size = p.add(0x8).readU64().toNumber();
    if (size === 0) return "";
    if (size > 64 * 1024) return null;   // sanity cap
    var dataPtr = p.add(0x10).readPointer();
    if (dataPtr.isNull()) return null;
    return dataPtr.readUtf8String(size);
  }

  function callerInLib(returnAddress) {
    if (!lib) return false;
    var ret = uint64(returnAddress.toString());
    var base = uint64(lib.base.toString());
    var end = base.add(lib.size);
    return ret.compare(base) >= 0 && ret.compare(end) < 0;
  }

  function callerOffset(returnAddress) {
    return returnAddress.sub(lib.base).toString();
  }

  // ─── Wait for libscplugin to load ───────────────────────────────────────
  // The .so is loaded LAZY by Snap (System.loadLibrary("scplugin") fires only
  // on first iew.mpi.* call, which happens during the Argos flow — usually
  // after the user starts signup or anything that triggers attestation).
  // We can attach long before that. Two-pronged wait:
  //   (a) periodic poll up to 5 min in case Process.findModuleByName misses
  //       a fast load between attach and our first poll
  //   (b) hook android_dlopen_ext to catch the load synchronously

  var hooksInstalled = false;
  function tryInstall() {
    if (hooksInstalled) return;
    if (findLib()) {
      hooksInstalled = true;
      installHooks();
    }
  }

  if (!findLib()) {
    emit("__INIT__", LIB_NAME + " not yet loaded — waiting (dlopen observer + 5min poll)");

    // (a) periodic poll
    var retryCount = 0;
    var retryHandle = setInterval(function () {
      retryCount++;
      if (hooksInstalled) { clearInterval(retryHandle); return; }
      tryInstall();
      if (retryCount > 600) {                  // 600 × 500ms = 5min
        clearInterval(retryHandle);
        if (!hooksInstalled) {
          emitInit(LIB_NAME + " not loaded after 5min — driver Snap to a flow that triggers Argos (signup/login)", false);
        }
      }
    }, 500);

    // (b) dlopen observer — fires the moment Snap loads the lib
    try {
      var dlopenExt = Module.findExportByName(null, "android_dlopen_ext");
      if (dlopenExt) {
        Interceptor.attach(dlopenExt, {
          onEnter: function (args) {
            try { this.path = args[0].readCString(); } catch (e) { this.path = null; }
          },
          onLeave: function () {
            if (!hooksInstalled && this.path && this.path.indexOf(LIB_NAME) !== -1) {
              tryInstall();
            }
          }
        });
        emitInit("android_dlopen_ext observer installed", true);
      }
    } catch (e) {
      emitInit("android_dlopen_ext observer", false, e);
    }
  } else {
    hooksInstalled = true;
    installHooks();
  }

  function installHooks() {
    emit("__INIT__", LIB_NAME + " base=" + lib.base + " size=" + lib.size);

    // ─── Hook 1: deobfuscator @ libscplugin+0x88ab4 ───────────────────────

    try {
      var deobfAddr = lib.base.add(DEOBF_OFFSET);
      Interceptor.attach(deobfAddr, {
        onEnter: function (args) {
          // x8 holds the std::string* destination (caller-allocated).
          // It's not part of the regular args[] mapping in Frida (which
          // covers x0..x7); read directly from context.
          this.dst = this.context.x8;
        },
        onLeave: function (retval) {
          if (deobfCount >= MAX_DEOBF_EMITS) return;
          if (!this.dst || this.dst.isNull()) return;
          var str = null;
          try { str = readLibcxxString(this.dst); } catch (e) { str = "<read err: " + e + ">"; }
          if (str === null) return;
          // Dedup: same string content emitted only N times per session
          var key = str;
          var n = (seenStrings[key] || 0) + 1;
          seenStrings[key] = n;
          if (n > 4) return;          // emit at most 4 occurrences per unique string
          deobfCount++;
          emit("SCPLUGIN_DEOBF_STR", str, {
            occurrence: n,
            length: str.length,
            caller_offset: callerOffset(this.returnAddress)
          });
        }
      });
      emitInit("scplugin.deobfuscator @ +0x" + DEOBF_OFFSET.toString(16), true);
    } catch (e) {
      emitInit("scplugin.deobfuscator", false, e);
    }

    // ─── Hook 2: __system_property_get filtered by caller in libscplugin ──
    // Args: const char* name (x0), char* value_buf (x1).

    try {
      var spgPtr = Module.findExportByName("libc.so", "__system_property_get");
      if (!spgPtr) throw new Error("__system_property_get not exported by libc.so");
      Interceptor.attach(spgPtr, {
        onEnter: function (args) {
          if (!callerInLib(this.returnAddress)) {
            this.skip = true;
            return;
          }
          this.key = args[0].readCString();
          this.valueBuf = args[1];
          this.callerOff = callerOffset(this.returnAddress);
        },
        onLeave: function (retval) {
          if (this.skip) return;
          var val = null;
          try { val = this.valueBuf.readCString(); } catch (e) { val = "<read err>"; }
          emit("SCPLUGIN_SYSPROP_GET", this.key, {
            sysprop_value: val,
            ret: retval.toInt32(),
            caller_offset: this.callerOff
          });
        }
      });
      emitInit("__system_property_get (filtered)", true);
    } catch (e) {
      emitInit("__system_property_get", false, e);
    }

    // ─── Hook 3: __system_property_find filtered by caller ────────────────
    // Args: const char* name (x0). Returns: const prop_info* (x0).
    // The actual value comes from a subsequent __system_property_read call,
    // which we don't try to correlate — but capturing the find tells us
    // *what key* was looked up.

    try {
      var spfPtr = Module.findExportByName("libc.so", "__system_property_find");
      if (!spfPtr) throw new Error("__system_property_find not exported by libc.so");
      Interceptor.attach(spfPtr, {
        onEnter: function (args) {
          if (!callerInLib(this.returnAddress)) {
            this.skip = true;
            return;
          }
          this.key = args[0].readCString();
          this.callerOff = callerOffset(this.returnAddress);
        },
        onLeave: function (retval) {
          if (this.skip) return;
          emit("SCPLUGIN_SYSPROP_FIND", this.key, {
            prop_info_ret: retval.toString(),
            caller_offset: this.callerOff
          });
        }
      });
      emitInit("__system_property_find (filtered)", true);
    } catch (e) {
      emitInit("__system_property_find", false, e);
    }

    send({
      layer: "scplugin",
      type: "__INIT__",
      value: "Layer 6 (libscplugin v13.89 deep capture) — deobfuscator @+0x88ab4, __system_property_get/find filtered to libscplugin caller. Cap=" + MAX_DEOBF_EMITS + " unique deobf strings per session (max 4 occurrences each); sysprop reads uncapped. Run during a signup to surface the 44 enumerated sysprop callsites.",
      caller: "",
      stack: [],
      ts: Date.now()
    });
  }
})();
