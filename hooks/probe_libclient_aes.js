/**
 * Probe: hook libclient.so internal AES + GHASH to capture the Argos cipher.
 *
 * Static recon (2026-04-29) located libclient.so internal BoringSSL:
 *   +0xb3c68c   AES encrypt cluster (108 AESE + 94 AESMC; Mike Hamburg impl)
 *   +0xc8f5e4   GHASH (58 PMULL + 29 PMULL2 = AES-GCM mac)
 *   +0x26231a   "ChaCha20-Poly1305" string (algo name in EVP table)
 *   +0x2aae12   "Mike Hamburg" attribution
 *
 * Why this should work where the libcrypto hook didn't:
 *   libclient.so has STATICALLY-LINKED BoringSSL with hidden symbols. The
 *   exported EVP_AEAD_CTX_seal in /system/lib64/libcrypto.so is a different
 *   instance — Snap never calls into it. The actual cipher runs inside
 *   libclient's private copy. By hooking the AES core directly via offset
 *   (no symbol resolution needed) we catch the cipher regardless of mangling.
 *
 * Strategy:
 *   1. Hook +0xb3c68c (AES encrypt). Should fire ~159× per signup seal
 *      (2548 byte plaintext / 16 byte block).
 *   2. Capture LR (X30) on each call -> the immediate caller's PC.
 *   3. Capture X0/X1/X2 (input block, output block, key schedule).
 *   4. After 30s, dump LR histogram. Top LR = the seal wrapper's call site
 *      to AES_encrypt inside libclient.so.
 *   5. Cap emit count at 10 to keep output manageable (LR/key tracking
 *      continues for all calls via histogram).
 *
 * Bonus: this probe also gives us the AES KEY (read from key schedule on
 * first AES call — first 16 or 32 bytes of the schedule = original key).
 */
(function () {
  function emit(type, value, extra) {
    var p = {
      layer: "libclient_aes",
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

  // Offsets identified statically in libclient.so 2026-04-29 (sha256:24acdfc...)
  // Function entries (NOT mid-function offsets) — verified via prologue scan.
  var AES_ENC_OFFSET   = 0xb3c620;  // AES_encrypt entry (size 544B, contains AESE@+0x6c)
  var GHASH_OFFSET     = 0xc8f590;  // GHASH entry (size 1676B, contains PMULL@+0x54)
  var SEAL_OFFSET      = 0xb3e4e4;  // Seal wrapper entry (size 912B, calls AES @ +0x1f8)

  var libclientMod = null;
  var hooksArmed = false;
  var aesEncCount = 0;
  var ghashCount = 0;
  var sealCount = 0;
  var MAX_EMIT = 30;
  var MAX_SEAL_EMIT = 10;
  var lrHistogram = {};
  var keyScheduleHist = {};

  function findLib() {
    try {
      libclientMod = Process.getModuleByName("libclient.so");
      return true;
    } catch (e) {
      return false;
    }
  }

  function attachHooks() {
    if (hooksArmed) return;
    if (!findLib()) return;
    hooksArmed = true;
    emit("__INIT__", "libclient.so at " + libclientMod.base + " size=" + libclientMod.size);

    // Hook AES encrypt block @ +0xb3c68c
    try {
      var aesAddr = libclientMod.base.add(AES_ENC_OFFSET);
      Interceptor.attach(aesAddr, {
        onEnter: function (args) {
          aesEncCount++;
          var lr = this.context.lr;
          var lrStr = lr.toString();
          lrHistogram[lrStr] = (lrHistogram[lrStr] || 0) + 1;

          var keySchedStr = args[2].toString();
          keyScheduleHist[keySchedStr] = (keyScheduleHist[keySchedStr] || 0) + 1;

          if (aesEncCount > MAX_EMIT) return;

          var inBlock = tryReadBytes(args[0], 16);
          var keySchedHead = tryReadBytes(args[2], 64);
          this.callIdx = aesEncCount;
          this.in16 = bytesToHex(inBlock);
          this.lrStr = lrStr;
          this.lrOff = lr.sub(libclientMod.base).toString();
          this.outPtr = args[1];
          this.keySchedHead64 = bytesToHex(keySchedHead);
        },
        onLeave: function (retval) {
          if (this.callIdx === undefined || this.callIdx > MAX_EMIT) return;
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
      emitInit("AES_encrypt @ libclient+0x" + AES_ENC_OFFSET.toString(16), true);
    } catch (e) {
      emitInit("AES_encrypt attach failed", false, e);
    }

    // Hook GHASH (PMULL cluster) @ +0xc8f5e4 — confirms AES-GCM if also fires
    try {
      var ghashAddr = libclientMod.base.add(GHASH_OFFSET);
      Interceptor.attach(ghashAddr, {
        onEnter: function (args) {
          ghashCount++;
          if (ghashCount > MAX_EMIT) return;
          var lr = this.context.lr;
          emit("GHASH_BLOCK", "+0x" + GHASH_OFFSET.toString(16), {
            callIdx: ghashCount,
            lr: lr.toString(),
            lrOffsetInLib: lr.sub(libclientMod.base).toString(),
            x0: args[0].toString(),
            x1: args[1].toString(),
            x2: args[2].toString()
          });
        }
      });
      emitInit("GHASH @ libclient+0x" + GHASH_OFFSET.toString(16), true);
    } catch (e) {
      emitInit("GHASH attach failed", false, e);
    }

    // Hook the SEAL wrapper at +0xb3e4e4 — captures full AEAD args (BoringSSL signature):
    //   X0 = EVP_AEAD_CTX*  (key inside)
    //   X1 = out, X2 = &out_len, X3 = max_out_len
    //   X4 = nonce, X5 = nonce_len
    //   X6 = in (plaintext), X7 = in_len
    //   [SP+0] = ad, [SP+8] = ad_len
    try {
      var sealAddr = libclientMod.base.add(SEAL_OFFSET);
      Interceptor.attach(sealAddr, {
        onEnter: function (args) {
          sealCount++;
          if (sealCount > MAX_SEAL_EMIT) return;
          this.callIdx = sealCount;
          this.t0 = Date.now();

          this.ctx = args[0];
          this.out = args[1];
          this.outLenPtr = args[2];
          this.maxOutLen = args[3].toInt32();
          this.nonce = args[4];
          this.nonceLen = args[5].toInt32();
          this.in = args[6];
          this.inLen = args[7].toInt32();

          // stack args
          try {
            this.ad = this.context.sp.add(0).readPointer();
            this.adLen = this.context.sp.add(8).readU64().toNumber();
          } catch (e) { this.ad = null; this.adLen = -1; }

          // Read crypto inputs BEFORE the seal modifies anything
          this.ctxFirst64Hex = bytesToHex(tryReadBytes(this.ctx, 64));
          this.nonceHex = bytesToHex(tryReadBytes(this.nonce, this.nonceLen > 0 && this.nonceLen < 64 ? this.nonceLen : 0));
          this.plaintextHead = bytesToHex(tryReadBytes(this.in, this.inLen > 0 && this.inLen < 256 ? this.inLen : 256));
          this.adHex = (this.ad && this.adLen > 0 && this.adLen < 64) ? bytesToHex(tryReadBytes(this.ad, this.adLen)) : null;
        },
        onLeave: function (retval) {
          if (this.callIdx === undefined || this.callIdx > MAX_SEAL_EMIT) return;

          var actualOutLen = -1;
          try { actualOutLen = this.outLenPtr.readU64().toNumber(); } catch (e) {}

          var ciphertextHeadHex = null;
          if (actualOutLen > 0 && actualOutLen < 65536) {
            ciphertextHeadHex = bytesToHex(tryReadBytes(this.out, Math.min(actualOutLen, 64)));
          }

          emit("LIBCLIENT_AEAD_SEAL", "+0x" + SEAL_OFFSET.toString(16), {
            callIdx: this.callIdx,
            ret: retval ? retval.toInt32() : 0,
            ctx: this.ctx.toString(),
            ctxFirst64Hex: this.ctxFirst64Hex,
            nonceLen: this.nonceLen,
            nonceHex: this.nonceHex,
            inLen: this.inLen,
            plaintextHead: this.plaintextHead,
            adLen: this.adLen,
            adHex: this.adHex,
            outLen: actualOutLen,
            maxOutLen: this.maxOutLen,
            ciphertextHead: ciphertextHeadHex,
            durationMs: Date.now() - this.t0
          });
        }
      });
      emitInit("LIBCLIENT_AEAD_SEAL @ libclient+0x" + SEAL_OFFSET.toString(16), true);
    } catch (e) {
      emitInit("LIBCLIENT_AEAD_SEAL attach failed", false, e);
    }

    // Histogram dump after 90s — must be AFTER iew.mpi.e seal completes.
    setTimeout(function () {
      var lrEntries = Object.keys(lrHistogram).map(function (k) {
        var p = ptr(k);
        var off = p.sub(libclientMod.base);
        return { lr: k, lrOffset: off.toString(), count: lrHistogram[k] };
      });
      lrEntries.sort(function (a, b) { return b.count - a.count; });

      var keyEntries = Object.keys(keyScheduleHist).map(function (k) {
        return { key_sched: k, count: keyScheduleHist[k] };
      });
      keyEntries.sort(function (a, b) { return b.count - a.count; });

      emit("AES_ENC_LR_HISTOGRAM", "after " + aesEncCount + " AES + " + ghashCount + " GHASH + " + sealCount + " SEAL calls", {
        totalAesCalls: aesEncCount,
        totalGhashCalls: ghashCount,
        totalSealCalls: sealCount,
        distinctLRs: lrEntries.length,
        top10LRs: lrEntries.slice(0, 10),
        distinctKeySchedules: keyEntries.length,
        top5KeySchedules: keyEntries.slice(0, 5)
      });
    }, 90000);
  }

  // Try arming immediately. libclient.so loads VERY early in Snap startup,
  // so this should succeed on attach.
  attachHooks();
  if (!hooksArmed) {
    emit("__INIT__", "libclient.so not yet loaded — waiting (poll 500ms / 4min)");
    var retryCount = 0;
    var retryHandle = setInterval(function () {
      retryCount++;
      if (hooksArmed) { clearInterval(retryHandle); return; }
      attachHooks();
      if (retryCount > 480) {
        clearInterval(retryHandle);
        if (!hooksArmed) emit("__INIT__", "libclient.so still not loaded after 4min");
      }
    }, 500);
  }
})();
