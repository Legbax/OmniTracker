/**
 * Probe: hook EVP_AEAD_CTX_seal in every loaded libcrypto.so.
 *
 * Hypothesis (2026-04-29): the Argos field 12 cipher runs in libcrypto.so
 * (BoringSSL), not libscplugin.so. f2 (316B) and f6 (2548B) of the bundle
 * are confirmed encrypted (entropy 7.27 / 7.93 bits/byte). libscplugin has
 * NO crypto primitives and NO libcrypto in its DT_NEEDED, so the call must
 * happen via dlopen() or via callback through Java conscrypt.
 *
 * EVP_AEAD_CTX_seal signature (BoringSSL):
 *   int EVP_AEAD_CTX_seal(
 *     const EVP_AEAD_CTX *ctx,    // X0  - holds key inside
 *     uint8_t *out,                // X1  - ciphertext output
 *     size_t  *out_len,            // X2  - written length
 *     size_t   max_out_len,        // X3
 *     const uint8_t *nonce,        // X4  - 12 bytes for ChaCha20-Poly1305
 *     size_t  nonce_len,           // X5
 *     const uint8_t *in,           // X6  - plaintext
 *     size_t  in_len,              // X7
 *     const uint8_t *ad,           // [SP, #0] - associated data
 *     size_t  ad_len               // [SP, #8]
 *   );
 *
 * What we capture: key (first 64B of ctx), nonce, plaintext head, lengths.
 * That's enough to decrypt the same ciphertext offline with any
 * ChaCha20-Poly1305 / AES-GCM library.
 */
(function () {
  function emit(type, value, extra) {
    var p = {
      layer: "evp_aead",
      type: type,
      value: value === null || value === undefined ? null : String(value),
      caller: type,
      stack: [],
      ts: Date.now()
    };
    if (extra) for (var k in extra) p[k] = extra[k];
    send(p);
  }

  function emitInit(label, ok, err) {
    emit(ok ? "__INIT_HOOK__" : "__INIT_HOOK_FAIL__", label,
         err ? { err: String(err) } : undefined);
  }

  function bytesToHex(buf, max) {
    if (!buf) return null;
    var view = new Uint8Array(buf);
    var n = max ? Math.min(max, view.length) : view.length;
    var s = "";
    for (var i = 0; i < n; i++) {
      var v = view[i];
      s += (v < 16 ? "0" : "") + v.toString(16);
    }
    if (max && view.length > max) s += "...";
    return s;
  }

  function tryReadBytes(ptrAddr, len, cap) {
    if (!ptrAddr || ptrAddr.isNull() || len <= 0) return null;
    var n = cap ? Math.min(len, cap) : len;
    try { return ptrAddr.readByteArray(n); } catch (e) { return null; }
  }

  function tryReadSize(ptrAddr) {
    if (!ptrAddr || ptrAddr.isNull()) return -1;
    try { return ptrAddr.readU64().toNumber(); } catch (e) { return -2; }
  }

  // Cap emissions to avoid flooding
  var sealCount = 0;
  var MAX_SEALS = 32;

  function attachToLibcrypto(mod) {
    var addr = null;
    try { addr = Module.findExportByName(mod.name, "EVP_AEAD_CTX_seal"); }
    catch (e) {}
    if (!addr || addr.isNull()) {
      emitInit("EVP_AEAD_CTX_seal NOT exported in " + mod.path, false);
      return false;
    }

    try {
      Interceptor.attach(addr, {
        onEnter: function (args) {
          if (sealCount >= MAX_SEALS) return;
          this.skip = false;
          this.ctx       = args[0];
          this.out       = args[1];
          this.outLenPtr = args[2];
          this.maxOutLen = args[3].toInt32();
          this.nonce     = args[4];
          this.nonceLen  = args[5].toInt32();
          this.in        = args[6];
          this.inLen     = args[7].toInt32();

          // Stack args: ad, ad_len  (off SP)
          this.ad     = this.context.sp.add(0).readPointer();
          this.adLen  = this.context.sp.add(8).readU64().toNumber();

          this.ctxFirst64    = tryReadBytes(this.ctx, 64);
          this.nonceBytes    = tryReadBytes(this.nonce, this.nonceLen, 64);
          this.plaintextHead = tryReadBytes(this.in, this.inLen, 256);
          this.adHead        = tryReadBytes(this.ad, this.adLen, 64);
        },
        onLeave: function (retval) {
          if (sealCount >= MAX_SEALS) return;
          if (this.skip) return;
          sealCount++;

          var actualOutLen = tryReadSize(this.outLenPtr);
          var ctxFirst64Hex    = bytesToHex(this.ctxFirst64);
          var nonceHex         = bytesToHex(this.nonceBytes);
          var plaintextHeadHex = bytesToHex(this.plaintextHead, 64);
          var adHex            = bytesToHex(this.adHead, 32);

          // Read first 64 bytes of ciphertext output for verification
          var ctHead = tryReadBytes(this.out, Math.min(actualOutLen, 64));
          var ctHeadHex = bytesToHex(ctHead);

          emit("EVP_AEAD_SEAL", "0x" + addr.toString(16), {
            sealIdx:        sealCount,
            libcryptoPath:  mod.path,
            ret:            retval ? retval.toInt32() : 0,
            ctx:            this.ctx.toString(),
            ctxFirst64Hex:  ctxFirst64Hex,   // first 32B is the chacha key (BoringSSL layout)
            nonceLen:       this.nonceLen,
            nonceHex:       nonceHex,
            inLen:          this.inLen,
            plaintextHead:  plaintextHeadHex,
            adLen:          this.adLen,
            adHex:          adHex,
            outLen:         actualOutLen,
            maxOutLen:      this.maxOutLen,
            ciphertextHead: ctHeadHex
          });
        }
      });
      emitInit("EVP_AEAD_CTX_seal hooked in " + mod.path +
               " @ " + addr.toString() +
               " (offset 0x" + addr.sub(mod.base).toString(16) + ")", true);
      return true;
    } catch (e) {
      emitInit("Interceptor.attach EVP_AEAD_CTX_seal in " + mod.path, false, e);
      return false;
    }
  }

  // Find every loaded libcrypto.so. Hook each one.
  var mods = Process.enumerateModules();
  var libcryptos = mods.filter(function (m) { return m.name === "libcrypto.so"; });
  emit("__INIT__", "Found " + libcryptos.length + " libcrypto.so instances loaded");
  var hooked = 0;
  for (var i = 0; i < libcryptos.length; i++) {
    if (attachToLibcrypto(libcryptos[i])) hooked++;
  }
  emit("__INIT__", "Hooked EVP_AEAD_CTX_seal in " + hooked + "/" + libcryptos.length +
                   " libcrypto.so instances. Cap=" + MAX_SEALS + " seals/session.");
})();
