/**
 * Wide BoringSSL hook — covers low-level crypto APIs that bypass EVP_AEAD.
 *
 * After EVP_AEAD_CTX_seal returned 0 hits during a confirmed signup seal,
 * the candidate APIs are:
 *
 *   - EVP_EncryptInit_ex / EVP_EncryptUpdate / EVP_EncryptFinal_ex (OpenSSL legacy)
 *   - EVP_CipherInit_ex / EVP_CipherUpdate / EVP_CipherFinal_ex
 *   - AES_encrypt / AES_set_encrypt_key (low-level AES)
 *   - AES_cbc_encrypt / AES_ctr128_encrypt
 *   - CRYPTO_chacha_20 (raw ChaCha20)
 *   - chacha20_poly1305_seal / *_open (BoringSSL internal)
 *   - HMAC_Init_ex / HMAC_Update / HMAC_Final (signature-side)
 *   - ECDSA_do_sign / ECDSA_sign (Argos signature path)
 *   - CRYPTO_gcm128_encrypt (AES-GCM low-level)
 *
 * Plus libsigx.so candidates — libsigx is ~395KB and Snap-shipped, so it may
 * hold custom crypto that doesn't link libcrypto symbolically.
 */
(function () {
  function emit(type, value, extra) {
    var p = {
      layer: "crypto_wide",
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

  function tryReadBytes(p, len, cap) {
    if (!p || p.isNull() || len <= 0) return null;
    var n = cap ? Math.min(len, cap) : len;
    try { return p.readByteArray(n); } catch (e) { return null; }
  }

  // Cap aggregate emissions — many of these hooks fire frequently.
  var counts = {};
  var MAX_PER_FN = 4;

  // List of (name, onEnter handler) pairs.
  // Each handler returns the extra metadata to emit. Returning null skips emit.
  var FUNCTIONS = [
    {
      name: "EVP_EncryptInit_ex",
      // (ctx, type, impl, key, iv) — key is X3, iv is X4
      handler: function (args) {
        var keyB = tryReadBytes(args[3], 32);
        var ivB  = tryReadBytes(args[4], 16);
        return {
          ctx: args[0].toString(),
          typePtr: args[1].toString(),
          keyHead32: bytesToHex(keyB),
          ivHead16: bytesToHex(ivB)
        };
      }
    },
    {
      name: "EVP_EncryptUpdate",
      // (ctx, out, &out_len, in, in_len)
      handler: function (args) {
        var inLen = args[4].toInt32();
        var inB = tryReadBytes(args[3], inLen, 64);
        return {
          ctx: args[0].toString(),
          inLen: inLen,
          inHead: bytesToHex(inB, 32)
        };
      }
    },
    {
      name: "EVP_EncryptFinal_ex",
      // (ctx, out, &out_len)
      handler: function (args) {
        return { ctx: args[0].toString() };
      }
    },
    {
      name: "EVP_CipherInit_ex",
      handler: function (args) {
        var keyB = tryReadBytes(args[3], 32);
        return { keyHead32: bytesToHex(keyB) };
      }
    },
    {
      name: "EVP_CipherUpdate",
      handler: function (args) {
        return { inLen: args[4].toInt32() };
      }
    },
    {
      name: "AES_encrypt",
      // (in, out, key) — single block 16B
      handler: function (args) {
        var inB = tryReadBytes(args[0], 16);
        return { in16: bytesToHex(inB), keyPtr: args[2].toString() };
      }
    },
    {
      name: "AES_set_encrypt_key",
      // (userKey, bits, AES_KEY*) — userKey at X0, bit-size at X1
      handler: function (args) {
        var bits = args[1].toInt32();
        var keyB = tryReadBytes(args[0], bits / 8);
        return { bits: bits, key: bytesToHex(keyB) };
      }
    },
    {
      name: "AES_ctr128_encrypt",
      handler: function (args) {
        return { len: args[2].toInt32() };
      }
    },
    {
      name: "AES_cbc_encrypt",
      handler: function (args) {
        return { len: args[2].toInt32() };
      }
    },
    {
      name: "CRYPTO_chacha_20",
      // (out, in, in_len, key[32], nonce[12], counter)
      handler: function (args) {
        var keyB = tryReadBytes(args[3], 32);
        var nonceB = tryReadBytes(args[4], 12);
        return {
          inLen: args[2].toInt32(),
          key32: bytesToHex(keyB),
          nonce12: bytesToHex(nonceB),
          counter: args[5].toInt32()
        };
      }
    },
    {
      name: "chacha20_poly1305_seal_scatter",
      handler: function (args) {
        return { sealScatter: true };
      }
    },
    {
      name: "chacha20_poly1305_seal",
      handler: function (args) { return { sealPath: true }; }
    },
    {
      name: "HMAC_Init_ex",
      // (ctx, key, key_len, md, impl)
      handler: function (args) {
        var keyLen = args[2].toInt32();
        var keyB = tryReadBytes(args[1], keyLen, 32);
        return { keyLen: keyLen, keyHead: bytesToHex(keyB) };
      }
    },
    {
      name: "HMAC_Update",
      handler: function (args) { return { len: args[2].toInt32() }; }
    },
    {
      name: "HMAC_Final",
      handler: function (args) { return { ctx: args[0].toString() }; }
    },
    {
      name: "ECDSA_do_sign",
      // (digest, digest_len, EC_KEY*)
      handler: function (args) {
        var digB = tryReadBytes(args[0], args[1].toInt32(), 32);
        return { digestHash: bytesToHex(digB) };
      }
    },
    {
      name: "ECDSA_sign",
      handler: function (args) { return { type: args[0].toInt32() }; }
    },
    {
      name: "EVP_DigestSign",
      handler: function (args) { return { ctx: args[0].toString() }; }
    },
    {
      name: "EVP_PKEY_sign",
      handler: function (args) { return { ctx: args[0].toString() }; }
    },
    {
      name: "CRYPTO_gcm128_encrypt",
      handler: function (args) { return { len: args[3].toInt32() }; }
    },
    {
      name: "RAND_bytes",
      // (buf, num) — captures requested random byte count
      handler: function (args) { return { len: args[1].toInt32() }; }
    }
  ];

  // Find libcrypto.so (any of the 3 paths — they share the symbol so one is fine).
  var allMods = Process.enumerateModules();
  var libcryptos = allMods.filter(function (m) { return m.name === "libcrypto.so"; });
  if (libcryptos.length === 0) {
    emit("__INIT__", "no libcrypto.so loaded — wide hook not installed");
    return;
  }
  // System libcrypto (lowest virt addr typically) — but they all resolve to same fn anyway
  var lc = libcryptos[0];
  emit("__INIT__", "Wide hook target: " + lc.path + " base=" + lc.base);

  var hookedCount = 0;
  for (var i = 0; i < FUNCTIONS.length; i++) {
    var spec = FUNCTIONS[i];
    var addr = null;
    try { addr = Module.findExportByName(lc.name, spec.name); } catch (e) {}
    if (!addr || addr.isNull()) {
      emitInit(spec.name + " not exported in libcrypto.so", false);
      continue;
    }

    (function (fnName, hndlr, fnAddr) {
      try {
        Interceptor.attach(fnAddr, {
          onEnter: function (args) {
            if (counts[fnName] === undefined) counts[fnName] = 0;
            if (counts[fnName] >= MAX_PER_FN) return;
            counts[fnName]++;
            try {
              var meta = hndlr(args);
              if (meta) {
                meta.fn = fnName;
                meta.callIdx = counts[fnName];
                emit("CRYPTO_CALL", fnName, meta);
              }
            } catch (e) {
              emit("CRYPTO_CALL_ERR", fnName, { err: String(e) });
            }
          }
        });
        hookedCount++;
      } catch (e) {
        emitInit("attach " + fnName, false, e);
      }
    })(spec.name, spec.handler, addr);
  }
  emit("__INIT__", "Wide BoringSSL hook attached: " + hookedCount + "/" + FUNCTIONS.length +
                   " functions. Cap=" + MAX_PER_FN + " per function.");

  // Also probe libsigx.so for any exported function calls (just attach hooks to ALL
  // exports — anything that fires during seal is a candidate cipher path).
  var sigx = allMods.find(function (m) { return m.name === "libsigx.so"; });
  if (sigx) {
    var sigxExports = [];
    try { sigxExports = Module.enumerateExports(sigx.name); } catch (e) {}
    var sigxHooked = 0;
    var SIGX_HOOK_LIMIT = 50;  // hard cap
    for (var j = 0; j < sigxExports.length && sigxHooked < SIGX_HOOK_LIMIT; j++) {
      var ex = sigxExports[j];
      if (ex.type !== "function") continue;
      // Skip C++ name-mangled junk and obvious-non-crypto exports
      if (/^_Z/.test(ex.name)) continue;  // C++ mangled
      (function (exName, exAddr) {
        try {
          Interceptor.attach(exAddr, {
            onEnter: function () {
              var k = "sigx:" + exName;
              if (counts[k] === undefined) counts[k] = 0;
              if (counts[k] >= 2) return;
              counts[k]++;
              emit("SIGX_CALL", exName, { callIdx: counts[k] });
            }
          });
          sigxHooked++;
        } catch (e) {}
      })(ex.name, ex.address);
    }
    emit("__INIT__", "libsigx.so exports hooked: " + sigxHooked + "/" + sigxExports.length);
  } else {
    emit("__INIT__", "libsigx.so not loaded");
  }
})();
