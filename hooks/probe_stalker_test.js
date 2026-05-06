/**
 * Phase 2A.5 — Stalker isolation test (non-Snap target).
 *
 * Goal: validate whether Frida Stalker.follow() emits events on a target that
 * has NO ferrite installed. If Stalker fires events here → ferrite IS likely
 * the inv #49 blocker on Snap. If Stalker fires zero events here too → the
 * stealth-frida-server build itself has broken Stalker emission, and ferrite
 * is innocent.
 *
 * What we measure:
 *   1. Stalker.follow() with onReceive callback — counts raw event blocks
 *      received within a 5s window
 *   2. Stalker.queueDrainInterval / queueCapacity — set explicitly to flush
 *      events promptly
 *   3. Compute call event count, block event count, exec event count
 *   4. Sample a few event records to confirm format
 *
 * Methodology: hook a frequently-called Java method (System.currentTimeMillis)
 * to provide a known stalker-active call path. Inside the hook, call
 * Stalker.follow with events.call=true and events.block=true. Then call the
 * original Java method (re-entrant — fine for currentTimeMillis).
 *
 * If currentThread isn't a Frida-tracked thread, Stalker.follow on it can fail
 * silently. To avoid that, we follow the JS thread itself by calling
 * Stalker.follow(Process.getCurrentThreadId()) from the agent's main thread,
 * NOT from a Java hook (Java thread context = ART, not Frida-spawned).
 *
 * Output: STALKER_TEST_RESULT event with eventCount, callCount, blockCount,
 * fullSampleHex of first 64 bytes.
 */
(function () {
  function emit(type, value, extra) {
    var p = { layer: "stalker_test", type: type, value: String(value), ts: Date.now() };
    if (extra) for (var k in extra) p[k] = extra[k];
    try { send(p); } catch (e) {}
  }

  emit("__INIT__", "Stalker isolation test armed (non-Snap target)");

  var totalEventBlocks = 0;
  var totalCallEvents = 0;
  var totalBlockEvents = 0;
  var sampleBytes = null;
  var emittedSamples = 0;

  // Decode Stalker GumEvent stream format.
  // From frida-gum/stalker.h: GumEvent is a tagged union, type at offset 0:
  //   GUM_CALL = 1, GUM_RET = 2, GUM_EXEC = 4, GUM_BLOCK = 8, GUM_COMPILE = 16
  // Each event is 32 bytes (GumCallEvent largest). Iterate through the buffer.
  function processEventBuffer(buf) {
    if (!buf) return;
    totalEventBlocks++;
    var u8 = new Uint8Array(buf);
    if (sampleBytes === null && u8.length > 0) {
      var hex = "";
      for (var k = 0; k < Math.min(64, u8.length); k++) {
        hex += (u8[k] < 16 ? "0" : "") + u8[k].toString(16);
      }
      sampleBytes = hex;
    }
    // Approx: count events by stride. Stalker emits 32-byte aligned records.
    var EVENT_SIZE = 32;
    var nEvents = Math.floor(u8.length / EVENT_SIZE);
    for (var i = 0; i < nEvents; i++) {
      var off = i * EVENT_SIZE;
      // type at offset 0 is a u32 LE
      var t = u8[off] | (u8[off+1] << 8) | (u8[off+2] << 16) | (u8[off+3] << 24);
      if (t === 1) totalCallEvents++;
      else if (t === 8) totalBlockEvents++;
    }
  }

  function runStalkerTest() {
    emit("STALKER_TEST_STARTING", "follow currentThreadId for 5s");
    var tid = Process.getCurrentThreadId();
    var followed = false;
    try {
      Stalker.queueDrainInterval = 100;   // flush every 100ms
      Stalker.queueCapacity = 2 * 1024 * 1024; // 2MB queue
      Stalker.follow(tid, {
        events: { call: true, block: true, ret: false, exec: false, compile: false },
        onReceive: function (events) {
          processEventBuffer(events);
        }
      });
      followed = true;
      emit("STALKER_FOLLOW_OK", "tid=" + tid);
    } catch (e) {
      emit("STALKER_FOLLOW_FAIL", e.message);
    }

    if (!followed) {
      emit("STALKER_TEST_RESULT", "follow failed", { eventBlocks: 0, callEvents: 0, blockEvents: 0 });
      return;
    }

    // Generate some call/block activity by doing a busy-loop with method calls
    // The follow runs on the agent thread which is the same thread executing
    // this JS, so calls below should produce Stalker events.
    var loopWork = function () {
      var s = "";
      for (var i = 0; i < 100; i++) {
        s += Math.sin(i).toFixed(3) + "_" + Math.cos(i).toFixed(3);
      }
      return s.length;
    };

    // Run loop for 4 seconds
    setTimeout(function () {
      try {
        var hits = 0;
        var deadline = Date.now() + 4000;
        while (Date.now() < deadline) {
          hits += loopWork();
        }
        emit("STALKER_LOOP_DONE", "hits=" + hits);
      } catch (e) {
        emit("STALKER_LOOP_FAIL", e.message);
      }

      // unfollow + drain
      setTimeout(function () {
        try {
          Stalker.unfollow(tid);
          emit("STALKER_UNFOLLOW_OK", "tid=" + tid);
        } catch (e) {
          emit("STALKER_UNFOLLOW_FAIL", e.message);
        }
        try { Stalker.flush(); } catch (e) {}
        // Final drain pause
        setTimeout(function () {
          emit("STALKER_TEST_RESULT", "done", {
            eventBlocks: totalEventBlocks,
            callEvents: totalCallEvents,
            blockEvents: totalBlockEvents,
            sampleHex: sampleBytes,
            verdict: (totalEventBlocks > 0 ? "STALKER_WORKS" : "STALKER_DEAD")
          });
        }, 500);
      }, 200);
    }, 100);
  }

  // Start after small delay so init message flushes first
  setTimeout(runStalkerTest, 200);
})();
