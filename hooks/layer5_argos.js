/**
 * Layer 5 — Argos Plaintext Capture (Snapchat-specific)
 *
 * Hookea las dos rutas Java que materializan el plaintext del payload Argos
 * antes de que la cifra estática ChaCha20-Poly1305 lo envuelva en field 12
 * del wire de RegisterWithUsernamePassword:
 *
 *   Lfd0;->getAttestationPayloadProto(Ljava/lang/String;Ljava/lang/String;I)[B
 *     ─ args estructurados (endpoint URL, userId, requestType). Construye
 *       el proto LKQ8, lo serializa con MessageNano.toByteArray y lo pasa
 *       a Liew.mpi.e. Su return ya es ciphertext.
 *
 *   Liew/mpi;->e([B)[B   (JNI native estática, impl en libscplugin.so)
 *     ─ recibe los BYTES PLAINTEXT del proto KQ8. Su return es el ciphertext
 *       que termina envuelto en field 12. Este es el hook que cierra la
 *       duda IMSI/ICCID/phone-en-cifrado.
 *
 *   Liew/mpi;->f([B Ljava/lang/String;)[B  (JNI native estática)
 *     ─ ruta hermana de firma (input plaintext, return signature).
 *
 * Nombres ofuscados verificados contra:
 *   D:/Claude Projects/OmniShield Dumps-Tests/2026-04-27/argos_decompile_20260427/
 *     bytecode_dumps.txt (lineas 1-71 para fd0, 822-865 para iew.mpi)
 * Snap APK 2026-04-27 — confirmado por el usuario que no se ha actualizado.
 *
 * Eventos emitidos (binarios adjuntos via send-with-data):
 *   ARGOS_PAYLOAD_PROTO       ciphertext que retorna fd0.getAttestationPayloadProto
 *   ARGOS_PLAINTEXT           bytes que entran a iew.mpi.e (el oro)
 *   ARGOS_CIPHERTEXT          bytes que retorna iew.mpi.e
 *   ARGOS_SIGN_INPUT          bytes que entran a iew.mpi.f
 *   ARGOS_SIGNATURE           bytes que retorna iew.mpi.f
 *
 * Cap de 64 emisiones por sesión para acotar I/O y disco.
 */

Java.perform(function () {

  var emittedCount = 0;
  var MAX_EMITS = 64;

  // ─── Stalker scoping for cipher-path discovery (2026-04-29) ─────────────────
  // libclient.so+0xbb6220 was falsified as the AEAD seal function (see
  // layer7_libclient.js for the rationale). The seal must run inside the JNI
  // native impl of iew.mpi.e, which is bound to libscplugin.so. We use
  // Stalker.follow() scoped to the iew.mpi.e thread + filtered to libscplugin.so
  // call destinations to enumerate WHICH function inside that library implements
  // the cipher.
  //
  // Strategy: one-shot — only Stalker the FIRST iew.mpi.e call of the session
  // (avoids per-call slowdown that anti-tamper timing checks could flag, and
  // one summary is enough to identify candidate functions).
  //
  // Output: ARGOS_STALKER_SUMMARY event with histogram of call destinations
  // inside libscplugin.so (offsets relative to base) + total calls outside.
  // Top-N functions by call count are the cipher candidates.
  var stalkerEArmed = true;   // single-shot for iew.mpi.e
  var stalkerScpluginRange = null;
  function getScpluginRange() {
    // Only cache SUCCESS — if libscplugin.so isn't loaded yet at first call,
    // a later call (e.g. when iew.mpi.e fires after JNI binding via
    // RegisterNatives) will retry. Caching error states broke this flow on
    // 2026-04-29 when attach happened before scplugin's dlopen.
    if (stalkerScpluginRange && stalkerScpluginRange.base) return stalkerScpluginRange;
    try {
      var sc = Process.getModuleByName("libscplugin.so");
      stalkerScpluginRange = {
        base: sc.base,
        end: sc.base.add(sc.size),
        baseStr: sc.base.toString(),
        size: sc.size
      };
    } catch (e) {
      stalkerScpluginRange = { error: String(e) };
    }
    return stalkerScpluginRange;
  }

  function bytesToArrayBuffer(jbytes) {
    if (!jbytes) return null;
    var len = jbytes.length;
    var buf = new ArrayBuffer(len);
    var view = new Uint8Array(buf);
    for (var i = 0; i < len; i++) view[i] = jbytes[i] & 0xff;
    return buf;
  }

  function head8Hex(jbytes) {
    if (!jbytes || jbytes.length === 0) return "";
    var n = Math.min(8, jbytes.length);
    var s = "";
    for (var i = 0; i < n; i++) {
      var v = jbytes[i] & 0xff;
      s += (v < 16 ? "0" : "") + v.toString(16);
    }
    return s;
  }

  function emitBinary(type, len, head, extra, byteBuffer) {
    if (emittedCount >= MAX_EMITS) return;
    emittedCount++;
    var payload = {
      layer: "argos",
      type: type,
      value: head,
      caller: type,
      stack: [],
      ts: Date.now(),
      length: len,
      head8: head
    };
    if (extra) {
      for (var k in extra) payload[k] = extra[k];
    }
    if (byteBuffer) {
      send(payload, byteBuffer);
    } else {
      send(payload);
    }
  }

  function emitInit(label, ok, err) {
    send({
      layer: "argos",
      type: ok ? "__INIT_HOOK__" : "__INIT_HOOK_FAIL__",
      value: label,
      err: err ? String(err) : undefined,
      caller: "init",
      stack: [],
      ts: Date.now()
    });
  }

  // ─── Hook 1: Lfd0;->getAttestationPayloadProto ──────────────────────────────
  // Args estructurados nos dicen QUÉ endpoint pidió attestation. El return es
  // el ciphertext (post-cifra interna) — sirve para correlación con field 12
  // del wire payload. El plaintext propiamente dicho lo capturamos en hook 2.

  try {
    var fd0 = Java.use("fd0");
    fd0.getAttestationPayloadProto.implementation = function (endpoint, userId, reqType) {
      var meta = {
        endpoint: endpoint == null ? null : String(endpoint),
        userId:   userId   == null ? null : String(userId),
        requestType: reqType
      };
      var ret = this.getAttestationPayloadProto(endpoint, userId, reqType);
      try {
        var len = ret ? ret.length : 0;
        emitBinary("ARGOS_PAYLOAD_PROTO", len, head8Hex(ret), meta,
                   bytesToArrayBuffer(ret));
      } catch (e) {
        emitBinary("ARGOS_PAYLOAD_PROTO_ERR", 0, "", { err: String(e) }, null);
      }
      return ret;
    };
    emitInit("fd0.getAttestationPayloadProto", true);
  } catch (e) {
    emitInit("fd0.getAttestationPayloadProto", false, e);
  }

  // ─── Hook 2: Liew/mpi;->e([B)[B  ←  THE plaintext input ─────────────────────
  // arg[0] son los bytes PLAINTEXT del proto KQ8 antes de cifrar. Hookeamos
  // ambos lados (input + return) para validar el delta de tamaños y poder
  // correlacionar con el ciphertext del hook 1.

  try {
    var mpi = Java.use("iew.mpi");
    mpi.e.implementation = function (plaintext) {
      try {
        emitBinary("ARGOS_PLAINTEXT",
                   plaintext ? plaintext.length : 0,
                   head8Hex(plaintext),
                   { source: "iew.mpi.e" },
                   bytesToArrayBuffer(plaintext));
      } catch (e) {
        emitBinary("ARGOS_PLAINTEXT_ERR", 0, "", { err: String(e) }, null);
      }

      // ─── Stalker in-Java with invalidate + block events (v3) ────────────────
      // v1 (call events only) captured 0 — Stalker followed but call event
      // generation didn't fire on pre-compiled native code reached through the
      // JS-to-native bridge.
      // v2 (native Interceptor on Java_iew_mpi_e) failed: scplugin uses
      // RegisterNatives (zero exported JNI symbols).
      // v3: stay in Java context but FORCE recompilation of libscplugin via
      // Stalker.invalidate() + use block events (lower-level, more reliable
      // than call events). Block events fire on every basic-block boundary,
      // so even short windows produce signal. Filter to libscplugin range
      // and aggregate by basic-block start address; the cipher's basic blocks
      // are the ones with the highest hit count (tight loops).
      var stalkerOn = false;
      var stalkerThreadId = null;
      var stalkerStart = 0;
      var stalkerAgg = null;
      if (stalkerEArmed) {
        var sc = getScpluginRange();
        if (sc && sc.base) {
          stalkerEArmed = false;
          stalkerThreadId = Process.getCurrentThreadId();
          stalkerStart = Date.now();
          stalkerAgg = {
            insideHist: {},        // off (block start) -> count
            insideTotal: 0,
            outsideTotal: 0,
            parseErrors: 0,
            callsInside: 0,
            blocksInside: 0
          };
          try {
            // Force recompile of libscplugin code so Stalker takes effect.
            // Without this, the thread executes already-compiled libscplugin
            // basic blocks that bypass Stalker's instrumentation.
            try { Stalker.invalidate({ base: sc.base, size: sc.size }); }
            catch (eI) { stalkerAgg.invalidateErr = String(eI); }

            Stalker.follow(stalkerThreadId, {
              events: { call: true, block: true },
              onReceive: function (eventsBuf) {
                try {
                  var parsed = Stalker.parse(eventsBuf, { annotate: false });
                  for (var i = 0; i < parsed.length; i++) {
                    var ev = parsed[i];
                    var kind = ev[0];
                    if (kind !== "call" && kind !== "block") continue;
                    // For 'call', target is ev[2]; for 'block', start is ev[1] (begin) and end ev[2].
                    var addr = (kind === "call") ? ev[2] : ev[1];
                    if (!addr) continue;
                    if (addr.compare(sc.base) >= 0 && addr.compare(sc.end) < 0) {
                      var off = addr.sub(sc.base).toString();
                      stalkerAgg.insideHist[off] =
                        (stalkerAgg.insideHist[off] || 0) + 1;
                      stalkerAgg.insideTotal++;
                      if (kind === "call") stalkerAgg.callsInside++;
                      else stalkerAgg.blocksInside++;
                    } else {
                      stalkerAgg.outsideTotal++;
                    }
                  }
                } catch (eR) {
                  stalkerAgg.parseErrors++;
                }
              }
            });
            stalkerOn = true;
          } catch (eF) {
            emitBinary("ARGOS_STALKER_ERR", 0, "",
                       { stage: "follow_v3", err: String(eF) }, null);
          }
        } else {
          emitBinary("ARGOS_STALKER_ERR", 0, "",
                     { stage: "getScpluginRange",
                       err: sc && sc.error ? sc.error : "libscplugin.so not loaded" },
                     null);
        }
      }

      var ct = this.e(plaintext);

      if (stalkerOn) {
        try {
          Stalker.unfollow(stalkerThreadId);
          Stalker.flush();
          var distinctInside = Object.keys(stalkerAgg.insideHist).length;
          var topEntries = Object.keys(stalkerAgg.insideHist)
            .map(function (off) { return [off, stalkerAgg.insideHist[off]]; })
            .sort(function (a, b) { return b[1] - a[1]; })
            .slice(0, 30);
          var topHist = {};
          topEntries.forEach(function (e) { topHist[e[0]] = e[1]; });
          emitBinary("ARGOS_STALKER_SUMMARY", 0, "", {
            source: "iew.mpi.e (Java + invalidate + block)",
            threadId: stalkerThreadId,
            libscpluginBase: sc.baseStr,
            libscpluginSize: sc.size,
            durationMs: Date.now() - stalkerStart,
            callsInsideScplugin: stalkerAgg.callsInside,
            blocksInsideScplugin: stalkerAgg.blocksInside,
            totalInside: stalkerAgg.insideTotal,
            outsideTotal: stalkerAgg.outsideTotal,
            distinctInsideTargets: distinctInside,
            parseErrors: stalkerAgg.parseErrors,
            invalidateErr: stalkerAgg.invalidateErr || null,
            top30: topHist
          }, null);
        } catch (eU) {
          emitBinary("ARGOS_STALKER_ERR", 0, "",
                     { stage: "unfollow_v3/flush", err: String(eU),
                       partial: stalkerAgg ? {
                         totalInside: stalkerAgg.insideTotal,
                         distinctInside: Object.keys(stalkerAgg.insideHist).length
                       } : null },
                     null);
        }
      }

      try {
        emitBinary("ARGOS_CIPHERTEXT",
                   ct ? ct.length : 0,
                   head8Hex(ct),
                   { source: "iew.mpi.e" },
                   bytesToArrayBuffer(ct));
      } catch (e) {
        emitBinary("ARGOS_CIPHERTEXT_ERR", 0, "", { err: String(e) }, null);
      }
      return ct;
    };
    emitInit("iew.mpi.e (with Stalker one-shot for libscplugin.so cipher discovery)", true);
  } catch (e) {
    emitInit("iew.mpi.e", false, e);
  }

  // ─── Hook 3: Liew/mpi;->f([B,String)[B  ←  signature path ───────────────────

  try {
    var mpiF = Java.use("iew.mpi");
    mpiF.f.implementation = function (plaintext, label) {
      try {
        emitBinary("ARGOS_SIGN_INPUT",
                   plaintext ? plaintext.length : 0,
                   head8Hex(plaintext),
                   { source: "iew.mpi.f", label: label == null ? null : String(label) },
                   bytesToArrayBuffer(plaintext));
      } catch (e) {
        emitBinary("ARGOS_SIGN_INPUT_ERR", 0, "", { err: String(e) }, null);
      }
      var sig = this.f(plaintext, label);
      try {
        emitBinary("ARGOS_SIGNATURE",
                   sig ? sig.length : 0,
                   head8Hex(sig),
                   { source: "iew.mpi.f" },
                   bytesToArrayBuffer(sig));
      } catch (e) {
        emitBinary("ARGOS_SIGNATURE_ERR", 0, "", { err: String(e) }, null);
      }
      return sig;
    };
    emitInit("iew.mpi.f", true);
  } catch (e) {
    emitInit("iew.mpi.f", false, e);
  }

  // ─── Native Stalker hook on JNI(iew.mpi.e) impl in libscplugin.so ───────────
  // STATUS 2026-04-29: confirmed scplugin uses RegisterNatives (zero
  // Java_iew_mpi_* exports in libscplugin.so). To use this path we'd need
  // to spawn Snap cold with a JNI_OnLoad RegisterNatives hook. Since v3
  // of the in-Java Stalker (with invalidate + block events) is preferred,
  // this function is kept as documentation but called only for diagnostic
  // logging — does NOT install any Interceptor on --attach sessions.

  function installNativeStalkerHook() {
    var sc = getScpluginRange();
    if (!sc || !sc.base) {
      emitInit("Native Stalker hook (libscplugin.so not loaded yet — skipping)", false,
               sc && sc.error ? sc.error : "module not found");
      return;
    }

    // Try common JNI mangling variants for iew.mpi.e([B)[B
    var candidates = [
      "Java_iew_mpi_e",
      "Java_iew_mpi_e___3B"
    ];
    var nativeAddr = null;
    var matchedName = null;
    for (var i = 0; i < candidates.length; i++) {
      try {
        var a = Module.findExportByName("libscplugin.so", candidates[i]);
        if (a && !a.isNull()) { nativeAddr = a; matchedName = candidates[i]; break; }
      } catch (e) {}
    }

    // Fallback: enumerate + prefix scan
    if (!nativeAddr) {
      try {
        var allExports = Module.enumerateExports("libscplugin.so");
        var matches = [];
        for (var j = 0; j < allExports.length; j++) {
          if (allExports[j].name.indexOf("Java_iew_mpi") === 0) {
            matches.push({ name: allExports[j].name,
                           addr: allExports[j].address.toString() });
            // Take the first 'e' match
            if (!nativeAddr && allExports[j].name.indexOf("Java_iew_mpi_e") === 0) {
              nativeAddr = allExports[j].address;
              matchedName = allExports[j].name;
            }
          }
        }
        emitInit("Native Stalker hook export scan: " + matches.length +
                 " Java_iew_mpi* exports found" +
                 (matches.length > 0 ? " (first=" + matches[0].name + ")" : ""), true);
      } catch (e2) {
        emitInit("Native Stalker hook enumerateExports", false, e2);
      }
    }

    if (!nativeAddr) {
      emitInit("Native Stalker hook FAILED: no Java_iew_mpi_e symbol in " +
               "libscplugin.so. JNI binding likely uses RegisterNatives — " +
               "needs JNI_OnLoad hook (cold-spawn flow, not --attach).", false);
      return;
    }

    var stalkerArmed = true;  // one-shot

    try {
      Interceptor.attach(nativeAddr, {
        onEnter: function (args) {
          if (!stalkerArmed) return;
          stalkerArmed = false;  // consume one-shot
          this.tid = Process.getCurrentThreadId();
          this.t0 = Date.now();
          this.agg = {
            insideHist: {},
            insideTotal: 0,
            outsideTotal: 0,
            parseErrors: 0
          };
          this.followed = false;
          try {
            var aggLocal = this.agg;
            Stalker.follow(this.tid, {
              events: { call: true },
              onReceive: function (eventsBuf) {
                try {
                  var parsed = Stalker.parse(eventsBuf, { annotate: false });
                  for (var k = 0; k < parsed.length; k++) {
                    var ev = parsed[k];
                    if (ev[0] !== "call") continue;
                    var tgt = ev[2];
                    if (!tgt) continue;
                    if (tgt.compare(sc.base) >= 0 && tgt.compare(sc.end) < 0) {
                      var off = tgt.sub(sc.base).toString();
                      aggLocal.insideHist[off] =
                        (aggLocal.insideHist[off] || 0) + 1;
                      aggLocal.insideTotal++;
                    } else {
                      aggLocal.outsideTotal++;
                    }
                  }
                } catch (eR) {
                  aggLocal.parseErrors++;
                }
              }
            });
            this.followed = true;
          } catch (eF) {
            emitBinary("ARGOS_STALKER_ERR", 0, "",
                       { stage: "follow_native", err: String(eF) }, null);
          }
        },
        onLeave: function (retval) {
          if (!this.followed) return;
          try {
            Stalker.unfollow(this.tid);
            Stalker.flush();
            var distinct = Object.keys(this.agg.insideHist).length;
            var topEntries = Object.keys(this.agg.insideHist)
              .map(function (o) { return [o, this.agg.insideHist[o]]; }.bind(this))
              .sort(function (a, b) { return b[1] - a[1]; })
              .slice(0, 30);
            var topHist = {};
            topEntries.forEach(function (e) { topHist[e[0]] = e[1]; });
            emitBinary("ARGOS_STALKER_SUMMARY", 0, "", {
              source: "Java_iew_mpi_e (native)",
              symbol: matchedName,
              threadId: this.tid,
              libscpluginBase: sc.baseStr,
              libscpluginSize: sc.size,
              durationMs: Date.now() - this.t0,
              callsInsideScplugin: this.agg.insideTotal,
              callsOutsideScplugin: this.agg.outsideTotal,
              distinctInsideTargets: distinct,
              parseErrors: this.agg.parseErrors,
              top30: topHist
            }, null);
          } catch (eU) {
            emitBinary("ARGOS_STALKER_ERR", 0, "",
                       { stage: "unfollow_native/flush", err: String(eU),
                         partial: { insideTotal: this.agg.insideTotal,
                                    distinct: Object.keys(this.agg.insideHist).length }
                       }, null);
          }
        }
      });
      emitInit("Native Stalker hook attached on " + matchedName +
               " @ " + nativeAddr.toString() +
               " (libscplugin+0x" + nativeAddr.sub(sc.base).toString(16) + ")",
               true);
    } catch (eA) {
      emitInit("Native Stalker hook Interceptor.attach", false, eA);
    }
  }

  try { installNativeStalkerHook(); }
  catch (e) { emitInit("installNativeStalkerHook", false, e); }

  send({
    layer: "argos",
    type: "__INIT__",
    value: "Layer 5 (Argos plaintext capture v2 + native Stalker) hooks loaded — fd0.getAttestationPayloadProto, iew.mpi.e (Java + native Stalker), iew.mpi.f. Cap=" + MAX_EMITS + " events/session. Binary blobs emitted via send-with-data; launcher persists them under <output_dir>/argos_blobs/.",
    caller: "",
    stack: [],
    ts: Date.now()
  });
});
