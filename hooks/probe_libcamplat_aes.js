/**
 * Probe: hook libcamplat+ AES core functions to confirm cipher source and
 * map the seal wrapper's call graph.
 *
 * Static recon (2026-04-29) located AES via ARM Crypto Extensions (Mike
 * Hamburg's implementation) in libcamplat+:
 *   +0x793820   AES key setup
 *   +0x793b80   AES decrypt block (1024B)
 *   +0x793f80   AES encrypt block (896B, 40 AESE + 35 AESMC)
 *   +0x3f2918+  PMULL cluster (GHASH for AES-GCM, 9 instructions 0x1e0 apart)
 *
 * Strategy:
 *   1. Hook +0x793f80 (AES encrypt) — fires per AES block during a seal.
 *      For a 2548B plaintext, expect ~159 AES block calls.
 *   2. On entry: read X0/X1/X2 (input/output/key-schedule pointers) +
 *      read LR (X30) = the immediate caller's PC.
 *   3. Aggregate calls by LR — the dominant LR is the seal wrapper's call site
 *      to AES_encrypt. From there we know the seal's location in libcamplat+.
 *   4. Bonus: read 16 bytes from X0 (input plaintext block) and X1 after the
 *      call (output ciphertext block) — gives us all keystream blocks. With
 *      enough of these and known plaintext we can reconstruct the AES-CTR key
 *      stream offline.
 *
 * Cap: 10 emit events — enough to identify caller LR + sample first few blocks.
 */
(function () {
  function emit(type, value, extra) {
    var p = {
      layer: "libcamplat",
      type: type,
      value: value === null || value === undefined ? null : String(value),
      caller: type, stack: [], ts: Date.now()
    };
    if (extra) for (var k in extra) p[k] = extra[k];
    send(p);
  }

  function emitInit(label, ok, err) {
    emit(ok ? "__INIT_HOOK__" : "__INIT_HOOK_FAIL__", label, err ? { err: String(err) } : undefined);
  }

  function bytesToHex(buf) {
    if (!buf) return null;
    var view = new Uint8Array(buf);
    var s = "";
    for (var i = 0; i < view.length; i++) {
      var v = view[i];
      s += (v < 16 ? "0" : "") + v.toString(16);
    }
    return s;
  }

  function tryReadBytes(p, len) {
    if (!p || p.isNull() || len <= 0) return null;
    try { return p.readByteArray(len); } catch (e) { return null; }
  }

  // libcamplat+ has variable filename suffix per build — match by prefix.
  // Loads lazily during Snap startup; if attach happens before that, wait.
  var camplatMod = null;

  function findCamplat() {
    var mods = Process.enumerateModules();
    for (var i = 0; i < mods.length; i++) {
      if (mods[i].name.indexOf("libcamplat+") === 0) {
        return mods[i];
      }
    }
    return null;
  }

  var hooksArmed = false;
  function tryArmHooks() {
    if (hooksArmed) return;
    var m = findCamplat();
    if (!m) return;
    camplatMod = m;
    hooksArmed = true;
    emit("__INIT__", "libcamplat+ at " + camplatMod.base + " size=" + camplatMod.size);
    attachAesEncrypt();
    attachAesKeySetup();
    attachSealHelper();
    armHistogramDump();
  }

  // Schedule histogram dump 30s after hooks are armed (not script load).
  function armHistogramDump() {
    setTimeout(function () {
      var entries = Object.keys(lrHistogram).map(function (k) {
        var p = ptr(k);
        var off = p.sub(camplatMod.base);
        return { lr: k, lrOffset: off.toString(), count: lrHistogram[k] };
      });
      entries.sort(function (a, b) { return b.count - a.count; });

      var keyEntries = Object.keys(keyScheduleHist).map(function (k) {
        return { key_sched: k, count: keyScheduleHist[k] };
      });
      keyEntries.sort(function (a, b) { return b.count - a.count; });

      emit("AES_ENC_LR_HISTOGRAM", "after " + aesEncCount + " block calls", {
        totalCalls: aesEncCount,
        distinctLRs: entries.length,
        top10LRs: entries.slice(0, 10),
        distinctKeySchedules: keyEntries.length,
        top5KeySchedules: keyEntries.slice(0, 5)
      });
    }, 30000);
  }

  // Offsets identified statically
  var AES_ENC_OFFSET    = 0x793f80;
  var AES_KEY_OFFSET    = 0x793820;
  var AES_DEC_OFFSET    = 0x793b80;
  var SEAL_HELPER_OFFSET = 0x8b1dd8;

  var aesEncCount = 0;
  var MAX_AES_ENC_EMIT = 10;
  var lrHistogram = {};   // LR -> count
  var keyScheduleHist = {}; // X2 (key schedule ptr) -> count

  function attachAesEncrypt() {
    try {
      var addr = camplatMod.base.add(AES_ENC_OFFSET);
      Interceptor.attach(addr, {
        onEnter: function (args) {
          aesEncCount++;
          // Track LR (caller's return address) to find the seal wrapper
          var lr = this.context.lr;
          var lrStr = lr.toString();
          lrHistogram[lrStr] = (lrHistogram[lrStr] || 0) + 1;

          // Track key schedule pointer (X2) to identify session keys
          var keySchedStr = args[2].toString();
          keyScheduleHist[keySchedStr] = (keyScheduleHist[keySchedStr] || 0) + 1;

          if (aesEncCount > MAX_AES_ENC_EMIT) return;

          // Capture first AES block: input (X0, 16B), key schedule (X2, 256B for AES-256)
          var inBlock = tryReadBytes(args[0], 16);
          var keySchedHead = tryReadBytes(args[2], 64);

          this.callIdx = aesEncCount;
          this.in16 = bytesToHex(inBlock);
          this.lrStr = lrStr;
          this.lrOff = lr.sub(camplatMod.base).toString();
          this.outPtr = args[1];
          this.keySchedHead64 = bytesToHex(keySchedHead);
        },
        onLeave: function (retval) {
          if (this.callIdx === undefined || this.callIdx > MAX_AES_ENC_EMIT) return;
          var outBlock = tryReadBytes(this.outPtr, 16);
          emit("AES_ENC_BLOCK", "+0x" + AES_ENC_OFFSET.toString(16), {
            callIdx: this.callIdx,
            lr: this.lrStr,
            lrOffsetInLib: this.lrOff,
            in16: this.in16,
            out16: bytesToHex(outBlock),
            keySchedHead64: this.keySchedHead64
          });
        }
      });
      emitInit("AES_encrypt @ libcamplat+0x" + AES_ENC_OFFSET.toString(16), true);
    } catch (e) {
      emitInit("AES_encrypt attach failed", false, e);
    }
  }

  function attachAesKeySetup() {
    try {
      var addr = camplatMod.base.add(AES_KEY_OFFSET);
      var count = 0;
      Interceptor.attach(addr, {
        onEnter: function (args) {
          count++;
          if (count > 4) return;
          // (key bits, key bytes ptr, key schedule out)
          // X0 = key, X1 = bits, X2 = key schedule out
          var bits = args[1].toInt32();
          var keyBytes = tryReadBytes(args[0], bits / 8);
          var lr = this.context.lr;
          emit("AES_KEY_SETUP", "+0x" + AES_KEY_OFFSET.toString(16), {
            callIdx: count,
            lr: lr.toString(),
            lrOffsetInLib: lr.sub(camplatMod.base).toString(),
            bits: bits,
            keyHex: bytesToHex(keyBytes),
            keySchedOutPtr: args[2].toString()
          });
        }
      });
      emitInit("AES_key_setup @ libcamplat+0x" + AES_KEY_OFFSET.toString(16), true);
    } catch (e) {
      emitInit("AES_key_setup attach failed", false, e);
    }
  }

  function attachSealHelper() {
    try {
      var addr = camplatMod.base.add(SEAL_HELPER_OFFSET);
      Interceptor.attach(addr, {
        onEnter: function (args) {
          var lr = this.context.lr;
          emit("SEAL_HELPER_ENTRY", "+0x" + SEAL_HELPER_OFFSET.toString(16), {
            x0: args[0].toString(),
            x1: args[1].toString(),
            x2: args[2].toString(),
            x3: args[3].toString(),
            lr: lr.toString(),
            lrOffsetInLib: lr.sub(camplatMod.base).toString()
          });
        }
      });
      emitInit("seal_helper @ libcamplat+0x" + SEAL_HELPER_OFFSET.toString(16), true);
    } catch (e) {
      emitInit("seal_helper attach failed", false, e);
    }
  }

  // Try arming immediately. If lib not loaded, set up dlopen observer + 2min poll.
  tryArmHooks();
  if (!hooksArmed) {
    emit("__INIT__", "libcamplat+ not loaded yet — waiting (dlopen observer + 4min poll)");
    var retryCount = 0;
    var retryHandle = setInterval(function () {
      retryCount++;
      if (hooksArmed) { clearInterval(retryHandle); return; }
      tryArmHooks();
      if (retryCount > 480) {
        clearInterval(retryHandle);
        if (!hooksArmed) {
          emit("__INIT__", "libcamplat+ still not loaded after 4min — Snap may not need it for this flow");
        }
      }
    }, 500);

    try {
      var dlopenExt = Module.findExportByName(null, "android_dlopen_ext");
      if (dlopenExt) {
        Interceptor.attach(dlopenExt, {
          onEnter: function (args) {
            try { this.path = args[0].readCString(); } catch (e) { this.path = null; }
          },
          onLeave: function () {
            if (!hooksArmed && this.path && this.path.indexOf("libcamplat+") !== -1) {
              tryArmHooks();
            }
          }
        });
      }
    } catch (e) {}
  } else {
    emit("__INIT__", "libcamplat+ AES probe armed (immediate): AES_enc + key_setup + seal_helper.");
  }
})();
