/**
 * Phase 2A.5b — Stalker on a SNAP thread (not the agent thread).
 *
 * The previous probe_stalker_test.js confirmed Stalker.follow on the agent's
 * own JS thread emits events. The real inv #49 failure was Stalker.follow on
 * a SNAP-spawned thread (e.g., the Java thread executing iew.mpi.e). Test
 * that here.
 *
 * Method:
 *   1. Enumerate Process.enumerateThreads() — pick a Snap thread.
 *   2. Stalker.follow(snap_tid) with onReceive callback.
 *   3. Wait 5 seconds (Snap is doing whatever it's doing — UI, networking).
 *   4. Stalker.unfollow + flush.
 *   5. Report event counts.
 *
 * If event count > 0 → Stalker on Snap threads works → inv #49 has yet another
 * cause (possibly the prior implementations had bugs in HOW they targeted the
 * thread).
 * If event count == 0 → Stalker on Snap threads is somehow blocked → ferrite
 * (or libsigchain or libsigx) IS interfering with non-Frida threads.
 */
(function () {
  function emit(type, value, extra) {
    var p = { layer: "stalker_snap_thread", type: type, value: String(value), ts: Date.now() };
    if (extra) for (var k in extra) p[k] = extra[k];
    try { send(p); } catch (e) {}
  }

  emit("__INIT__", "Stalker on Snap thread test armed");

  var totalEventBlocks = 0;
  var totalCallEvents = 0;
  var totalBlockEvents = 0;
  var sampleBytes = null;

  function processEventBuffer(buf) {
    if (!buf) return;
    totalEventBlocks++;
    var u8 = new Uint8Array(buf);
    if (sampleBytes === null && u8.length > 0) {
      var hex = "";
      for (var k = 0; k < Math.min(64, u8.length); k++) hex += (u8[k] < 16 ? "0" : "") + u8[k].toString(16);
      sampleBytes = hex;
    }
    var EVENT_SIZE = 32;
    var n = Math.floor(u8.length / EVENT_SIZE);
    for (var i = 0; i < n; i++) {
      var off = i * EVENT_SIZE;
      var t = u8[off] | (u8[off+1] << 8) | (u8[off+2] << 16) | (u8[off+3] << 24);
      if (t === 1) totalCallEvents++;
      else if (t === 8) totalBlockEvents++;
    }
  }

  setTimeout(function () {
    var threads = Process.enumerateThreads();
    var agentTid = Process.getCurrentThreadId();
    emit("THREADS_FOUND", threads.length + " threads, agent=" + agentTid);

    // Filter to NON-agent threads. Pick the first one that's "running"
    // (state R). Bias towards threads with low ids (Snap's main thread is
    // typically the lowest tid of the process).
    var candidates = [];
    for (var i = 0; i < threads.length; i++) {
      var t = threads[i];
      if (t.id === agentTid) continue;
      candidates.push({ id: t.id, state: t.state, name: t.name || "?" });
    }
    candidates.sort(function (a, b) { return a.id - b.id; });
    emit("CANDIDATES", candidates.length + " non-agent threads", { sample: candidates.slice(0, 10) });

    if (candidates.length === 0) {
      emit("STALKER_TEST_RESULT", "no candidate threads", { eventBlocks: 0, verdict: "NO_THREADS" });
      return;
    }

    // Try to follow the first 3 non-agent threads (multiplex)
    var followedTids = [];
    var maxFollow = Math.min(3, candidates.length);
    try {
      Stalker.queueDrainInterval = 100;
      Stalker.queueCapacity = 4 * 1024 * 1024;
    } catch (e) {}

    for (var f = 0; f < maxFollow; f++) {
      var snapTid = candidates[f].id;
      try {
        Stalker.follow(snapTid, {
          events: { call: true, block: true, ret: false, exec: false, compile: false },
          onReceive: function (events) { processEventBuffer(events); }
        });
        followedTids.push(snapTid);
        emit("STALKER_FOLLOW_OK", "tid=" + snapTid + " name=" + candidates[f].name + " state=" + candidates[f].state);
      } catch (e) {
        emit("STALKER_FOLLOW_FAIL", "tid=" + snapTid + " err=" + e.message);
      }
    }

    if (followedTids.length === 0) {
      emit("STALKER_TEST_RESULT", "all follows failed", { eventBlocks: 0, verdict: "FOLLOW_FAILED" });
      return;
    }

    // Wait 5s for the Snap threads to do work (UI events, networking, etc.)
    setTimeout(function () {
      // unfollow all
      for (var u = 0; u < followedTids.length; u++) {
        try { Stalker.unfollow(followedTids[u]); } catch (e) {}
      }
      try { Stalker.flush(); } catch (e) {}
      setTimeout(function () {
        emit("STALKER_TEST_RESULT", "done", {
          followedTids: followedTids,
          eventBlocks: totalEventBlocks,
          callEvents: totalCallEvents,
          blockEvents: totalBlockEvents,
          sampleHex: sampleBytes,
          verdict: (totalEventBlocks > 0 ? "STALKER_WORKS_ON_SNAP_THREADS" : "STALKER_DEAD_ON_SNAP_THREADS")
        });
      }, 500);
    }, 5000);
  }, 200);
})();
