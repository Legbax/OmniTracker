/**
 * probe_iew_cipher.js — comprehensive cipher pinpoint probe for iew.mpi.e
 *
 * Pre-requisites:
 *   - OmniShield v2.4.0+ with `ferrite_neutralize=true` in .identity.cfg
 *     (so Stalker.follow on Snap threads doesn't trigger SIGTRAP-mediated kill)
 *
 * Strategy:
 *   1. Hook iew.mpi.e (the JNI native that produces field 12 ciphertext)
 *   2. Capture plaintext input bytes (43B KQ8 proto: endpoint + userId + reqType)
 *   3. Stalker.follow current thread, scoped to libclient.so + libscplugin.so
 *      ranges, both call AND block events
 *   4. Stalker.invalidate both ranges to force recompile
 *   5. Call original e() — the seal runs entirely inside this call
 *   6. Stalker.unfollow + flush, aggregate hit counts per target/block
 *   7. Capture ciphertext output (the 2887B Argos bundle = wire field 12)
 *   8. Emit top-30 call targets + top-30 block starts in EACH module
 *
 * Output events (binary attachments via send-with-data):
 *   IEW_CIPHER_PLAINTEXT      — ARGOS_PLAINTEXT (43B input to seal)
 *   IEW_CIPHER_CIPHERTEXT     — ARGOS_CIPHERTEXT (2887B sealed output, field 12)
 *   IEW_CIPHER_STALKER        — Stalker hit-count summary (top-30 per module)
 *
 * The cipher offset will be the libclient.so target with the highest call count
 * AND a tight block hit pattern (cipher-like inner loop).
 */
Java.perform(function () {
  function emit(type, value, extra, byteBuffer) {
    var p = { layer: "iew_cipher", type: type, value: value === null ? null : String(value),
              ts: Date.now() };
    if (extra) for (var k in extra) p[k] = extra[k];
    try {
      if (byteBuffer) send(p, byteBuffer); else send(p);
    } catch (e) {}
  }

  function emitInit(label, ok, err) {
    emit(ok ? "__INIT_HOOK__" : "__INIT_HOOK_FAIL__", label, err ? { err: String(err) } : undefined);
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

  function bytesToArrayBuffer(jbytes) {
    if (!jbytes) return null;
    var len = jbytes.length;
    var buf = new ArrayBuffer(len);
    var view = new Uint8Array(buf);
    for (var i = 0; i < len; i++) view[i] = jbytes[i] & 0xff;
    return buf;
  }

  // Resolve module ranges lazily — libclient/libscplugin may load AFTER attach.
  var ranges = { libclient: null, libscplugin: null };
  function resolveRange(modName) {
    if (ranges[modName]) return ranges[modName];
    try {
      var m = Process.getModuleByName(modName + ".so");
      ranges[modName] = {
        base: m.base,
        end: m.base.add(m.size),
        baseStr: m.base.toString(),
        size: m.size,
        name: modName
      };
      return ranges[modName];
    } catch (e) {
      return null;
    }
  }

  // Multi-shot: Stalker EVERY iew.mpi.e so we get accumulated stats across
  // multiple calls (cipher path varies slightly per request type, but the
  // hot inner loop should rank highest after several iterations).
  // Cap at 8 Stalker iterations to bound the cost; plaintext/ciphertext
  // capture is also CAPPED to prevent IPC saturation when Snap fires 30+
  // iew.mpi.e calls in rapid succession (login attestation pattern).
  var STALKER_MAX_ITERS = 8;
  var PLAINTEXT_MAX_EMITS = 5;        // first N unique plaintexts only
  var CIPHERTEXT_MAX_EMITS = 5;       // first N ciphertexts only
  var stalkerIter = 0;
  var iterCount = 0;
  var plaintextEmits = 0;
  var ciphertextEmits = 0;
  var seenPlaintextHeads = new Set();
  // Aggregated histograms across all Stalker iterations
  var aggHist = {
    libclient:   { calls: {}, blocks: {}, callsTotal: 0, blocksTotal: 0 },
    libscplugin: { calls: {}, blocks: {}, callsTotal: 0, blocksTotal: 0 },
    outsideTotal: 0,
    parseErrors: 0
  };

  try {
    var mpi = Java.use("iew.mpi");
    mpi.e.implementation = function (plaintext) {
      iterCount++;

      // --- Capture plaintext (capped + dedup'd by head8) ---
      try {
        var head = head8Hex(plaintext);
        var len = plaintext ? plaintext.length : 0;
        var shouldEmitBlob = false;
        if (plaintextEmits < PLAINTEXT_MAX_EMITS && !seenPlaintextHeads.has(head + ":" + len)) {
          seenPlaintextHeads.add(head + ":" + len);
          plaintextEmits++;
          shouldEmitBlob = true;
        }
        emit("IEW_CIPHER_PLAINTEXT",
             "iter#" + iterCount + " " + len + "B head=" + head + (shouldEmitBlob ? "" : " (dedup)"),
             { iter: iterCount, length: len, head8: head, dedup: !shouldEmitBlob },
             shouldEmitBlob ? bytesToArrayBuffer(plaintext) : null);
      } catch (e) {
        emit("IEW_CIPHER_PLAINTEXT_ERR", String(e));
      }

      // --- Stalker setup (multi-shot, accumulated) ---
      var stalkerOn = false;
      var stalkerThreadId = null;
      var stalkerStart = 0;
      var thisIterEvents = 0;

      if (stalkerIter < STALKER_MAX_ITERS) {
        var libclientRange = resolveRange("libclient");
        var libscpluginRange = resolveRange("libscplugin");
        if (libclientRange || libscpluginRange) {
          stalkerIter++;
          stalkerThreadId = Process.getCurrentThreadId();
          stalkerStart = Date.now();

          try {
            // Drain interval = 1ms — the seal is ~50ms, we want events to arrive
            // before we read the histogram (in onReceive).
            Stalker.queueDrainInterval = 1;
            Stalker.queueCapacity = 16 * 1024 * 1024;
            Stalker.follow(stalkerThreadId, {
              events: { call: true, block: true },
              onReceive: function (eventsBuf) {
                try {
                  var parsed = Stalker.parse(eventsBuf, { annotate: false });
                  thisIterEvents += parsed.length;
                  for (var i = 0; i < parsed.length; i++) {
                    var ev = parsed[i];
                    var kind = ev[0];
                    if (kind !== "call" && kind !== "block") continue;
                    var addr = (kind === "call") ? ev[2] : ev[1];
                    if (!addr) continue;

                    if (libclientRange &&
                        addr.compare(libclientRange.base) >= 0 &&
                        addr.compare(libclientRange.end) < 0) {
                      var off = addr.sub(libclientRange.base).toString();
                      var b = aggHist.libclient;
                      if (kind === "call") {
                        b.calls[off] = (b.calls[off] || 0) + 1;
                        b.callsTotal++;
                      } else {
                        b.blocks[off] = (b.blocks[off] || 0) + 1;
                        b.blocksTotal++;
                      }
                    } else if (libscpluginRange &&
                               addr.compare(libscpluginRange.base) >= 0 &&
                               addr.compare(libscpluginRange.end) < 0) {
                      var off2 = addr.sub(libscpluginRange.base).toString();
                      var b2 = aggHist.libscplugin;
                      if (kind === "call") {
                        b2.calls[off2] = (b2.calls[off2] || 0) + 1;
                        b2.callsTotal++;
                      } else {
                        b2.blocks[off2] = (b2.blocks[off2] || 0) + 1;
                        b2.blocksTotal++;
                      }
                    } else {
                      aggHist.outsideTotal++;
                    }
                  }
                } catch (eR) {
                  aggHist.parseErrors++;
                }
              }
            });
            stalkerOn = true;
            if (stalkerIter === 1) {
              emit("IEW_CIPHER_STALKER_ARMED",
                   "tid=" + stalkerThreadId +
                   " libclient=" + (libclientRange ? libclientRange.baseStr : "?") +
                   " libscplugin=" + (libscpluginRange ? libscpluginRange.baseStr : "?") +
                   " maxIters=" + STALKER_MAX_ITERS);
            }
          } catch (eF) {
            emit("IEW_CIPHER_STALKER_ERR", "follow iter=" + stalkerIter + ": " + String(eF));
          }
        }
      }

      // --- Run original seal ---
      var ct = this.e(plaintext);

      // --- Unfollow + emit summary ---
      if (stalkerOn) {
        try {
          Stalker.unfollow(stalkerThreadId);
          Stalker.flush();
        } catch (eU) {}

        // Per-iter mini-summary (so we can see if events accumulate)
        emit("IEW_CIPHER_STALKER_ITER",
             "iter=" + stalkerIter + " durationMs=" + (Date.now() - stalkerStart) +
             " thisIterEventsParsed=" + thisIterEvents,
             {
               iter: stalkerIter,
               durationMs: Date.now() - stalkerStart,
               thisIterEventsParsed: thisIterEvents,
               aggCallsLibclient: aggHist.libclient.callsTotal,
               aggBlocksLibclient: aggHist.libclient.blocksTotal,
               aggCallsLibscplugin: aggHist.libscplugin.callsTotal,
               aggBlocksLibscplugin: aggHist.libscplugin.blocksTotal,
               aggOutside: aggHist.outsideTotal,
               aggParseErrors: aggHist.parseErrors
             });

        // Final aggregated summary on the LAST iteration
        if (stalkerIter >= STALKER_MAX_ITERS) {
          function topN(obj, n) {
            return Object.keys(obj)
              .map(function (k) { return [k, obj[k]]; })
              .sort(function (a, b) { return b[1] - a[1]; })
              .slice(0, n);
          }
          function asObject(pairs) {
            var o = {};
            pairs.forEach(function (p) { o[p[0]] = p[1]; });
            return o;
          }

          var summary = {
            iters: stalkerIter,
            parseErrors: aggHist.parseErrors,
            outsideTotal: aggHist.outsideTotal,
            libclient: {
              base: ranges.libclient ? ranges.libclient.baseStr : null,
              size: ranges.libclient ? ranges.libclient.size : null,
              callsTotal: aggHist.libclient.callsTotal,
              blocksTotal: aggHist.libclient.blocksTotal,
              distinctCallTargets: Object.keys(aggHist.libclient.calls).length,
              distinctBlockStarts: Object.keys(aggHist.libclient.blocks).length,
              top30Calls: asObject(topN(aggHist.libclient.calls, 30)),
              top30Blocks: asObject(topN(aggHist.libclient.blocks, 30))
            },
            libscplugin: {
              base: ranges.libscplugin ? ranges.libscplugin.baseStr : null,
              size: ranges.libscplugin ? ranges.libscplugin.size : null,
              callsTotal: aggHist.libscplugin.callsTotal,
              blocksTotal: aggHist.libscplugin.blocksTotal,
              distinctCallTargets: Object.keys(aggHist.libscplugin.calls).length,
              distinctBlockStarts: Object.keys(aggHist.libscplugin.blocks).length,
              top30Calls: asObject(topN(aggHist.libscplugin.calls, 30)),
              top30Blocks: asObject(topN(aggHist.libscplugin.blocks, 30))
            }
          };
          emit("IEW_CIPHER_STALKER", "FINAL after " + stalkerIter + " iters", summary);
        }
      }

      // --- Capture ciphertext (capped) ---
      try {
        var ctLen = ct ? ct.length : 0;
        var shouldEmitCt = ciphertextEmits < CIPHERTEXT_MAX_EMITS;
        if (shouldEmitCt) ciphertextEmits++;
        emit("IEW_CIPHER_CIPHERTEXT",
             "iter#" + iterCount + " " + ctLen + "B head=" + head8Hex(ct) + (shouldEmitCt ? "" : " (capped)"),
             { iter: iterCount, length: ctLen, head8: head8Hex(ct) },
             shouldEmitCt ? bytesToArrayBuffer(ct) : null);
      } catch (e) {
        emit("IEW_CIPHER_CIPHERTEXT_ERR", String(e));
      }

      return ct;
    };
    emitInit("iew.mpi.e (cipher pinpoint via Stalker on libclient + libscplugin)", true);
  } catch (e) {
    emitInit("iew.mpi.e cipher hook", false, e);
  }
});
