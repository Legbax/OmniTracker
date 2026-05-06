/**
 * Phase 2B — ferrite bypass POC.
 *
 * Two modes (set globalThis.OT_FERRITE_MODE before this script loads):
 *   "observe" — Interceptor.attach on +0x4fe4 + +0x50d8 (log only); no replacement.
 *   "bypass"  — Same observation hooks PLUS Interceptor.replace +0x4fe4 with a
 *               stub. See below for stub strategy.
 *
 * Static facts (from tools/ferrite_re/02_static_analysis.md + 04_death_certificate.md):
 *   libferrite-launcher.so base+0x4fe4  → SIGILL/TRAP/ABRT/BUS/FPE handler (sa_sigaction)
 *   libferrite-launcher.so base+0x50d8  → bl syscall@plt for tgkill re-raise
 *
 * Bypass strategy options (we'll iterate based on observation data):
 *   A. Interceptor.attach +0x4fe4 with onEnter that sets retval and returns
 *      → ferrite's body never runs → no fork+execve, no tgkill. Risk: if SIGTRAP
 *      came from BRK instruction (Stalker insertion), kernel resumes at BRK →
 *      infinite loop. Need to verify experimentally.
 *   B. NOP at +0x50d8 (kill the tgkill re-raise). ferrite still does dump but
 *      never kills. Same risk as A for BRK-induced traps.
 *   C. Replace +0x4fe4 with a NativeCallback that calls sigaction(signum, NULL,
 *      &out) to restore default disposition, then returns. Kernel re-delivers
 *      with default → process dies cleanly (still better than ferrite's tgkill,
 *      since now it's catchable by Frida's chain).
 *   D. Use sigaction() at probe-init to OVERWRITE the SIGTRAP handler with
 *      a Frida-friendly handler that advances PC and returns. This requires
 *      knowing the trap context (siginfo_t->si_code, ucontext->pc adjustment).
 *
 * For Phase 2B step 1 we ONLY observe. Step 2 will pick the bypass strategy
 * based on what we learn here.
 */
(function () {
  function emit(type, value, extra) {
    var p = { layer: "ferrite_bypass", type: type, value: String(value), ts: Date.now() };
    if (extra) for (var k in extra) p[k] = extra[k];
    try { send(p); } catch (e) {}
  }

  var SIG_NAMES = {
    1: "SIGHUP", 4: "SIGILL", 5: "SIGTRAP", 6: "SIGABRT", 7: "SIGBUS",
    8: "SIGFPE", 9: "SIGKILL", 11: "SIGSEGV", 14: "SIGALRM", 15: "SIGTERM"
  };
  var SYS_TGKILL = 131;

  // Find ferrite-launcher
  var ferriteLauncher = null;
  var mods = Process.enumerateModules();
  for (var i = 0; i < mods.length; i++) {
    if (/libferrite-launcher/i.test(mods[i].name)) { ferriteLauncher = mods[i]; break; }
  }
  if (!ferriteLauncher) {
    emit("__INIT_HOOK_FAIL__", "libferrite-launcher.so not loaded");
    return;
  }
  emit("__INIT__", "libferrite-launcher base=" + ferriteLauncher.base + " size=" + ferriteLauncher.size);

  var addr_4fe4 = ferriteLauncher.base.add(0x4fe4);
  var addr_50d8 = ferriteLauncher.base.add(0x50d8);
  emit("__INIT__", "+0x4fe4 = " + addr_4fe4 + "  +0x50d8 = " + addr_50d8);

  var mode = (typeof OT_FERRITE_MODE === "string") ? OT_FERRITE_MODE : "observe";
  emit("__INIT__", "mode=" + mode);

  // ─── Hook +0x4fe4 (signal handler entry) ──────────────────────────────
  // Signature when called by kernel via SA_SIGINFO: void(int sig, siginfo_t* si, void* uctx)
  // args[0] = signum
  // args[1] = siginfo_t* (offsets: si_signo@0, si_errno@4, si_code@8, si_addr@16 on AArch64)
  // args[2] = ucontext_t* (PC at offset depending on layout — gregs in mc_context)
  var fired_4fe4_count = 0;
  try {
    Interceptor.attach(addr_4fe4, {
      onEnter: function (args) {
        fired_4fe4_count++;
        var signum = args[0].toInt32();
        var siPtr = args[1];
        var ucPtr = args[2];
        var siCode = -1, siAddr = "?";
        try {
          if (siPtr && !siPtr.isNull()) {
            siCode = siPtr.add(8).readS32();
            siAddr = siPtr.add(16).readPointer().toString();
          }
        } catch (e) {}
        emit("FERRITE_HANDLER_ENTRY", "sig=" + (SIG_NAMES[signum] || signum) + " siCode=" + siCode + " siAddr=" + siAddr + " call#" + fired_4fe4_count, {
          signum: signum, siCode: siCode, siAddr: siAddr,
          lr: this.context.lr.toString(),
          sp: this.context.sp.toString(),
          siPtr: siPtr.toString(),
          ucPtr: ucPtr.toString(),
          force: true
        });
        if (mode === "bypass") {
          emit("FERRITE_HANDLER_BYPASS_RETURN", "intercepted — returning early without ferrite body", { force: true });
          // Set return value to skip the rest of the function. For sa_sigaction
          // (returns void), retval = anything is fine. We just need to NOT execute
          // the body. Use Interceptor's onEnter then returning from it lets the
          // function continue. To skip the body, we'd need Interceptor.replace.
          // Done in attachReplaceMode() below — observation only here.
        }
      },
      onLeave: function (retval) {
        emit("FERRITE_HANDLER_LEAVE", "call#" + fired_4fe4_count + " retval=" + retval, { force: true });
      }
    });
    emit("__INIT_HOOK__", "+0x4fe4 attached");
  } catch (e) {
    emit("__INIT_HOOK_FAIL__", "+0x4fe4: " + e.message);
  }

  // ─── Hook +0x50d8 (tgkill re-raise) ─────────────────────────────────────
  var fired_50d8_count = 0;
  try {
    Interceptor.attach(addr_50d8, {
      onEnter: function (args) {
        fired_50d8_count++;
        // At this point we're at the call instruction TO syscall@plt. The args
        // to syscall(SYS_tgkill, tgid, tid, sig) are in x0-x3 (set up by the
        // preceding instructions). Frida's args[N] reflects current x0..xN.
        var sysno = args[0].toInt32();
        var tgid = args[1].toInt32();
        var tid = args[2].toInt32();
        var sig = args[3].toInt32();
        emit("FERRITE_TGKILL", "sysno=" + sysno + " tgid=" + tgid + " tid=" + tid + " sig=" + (SIG_NAMES[sig] || sig) + " call#" + fired_50d8_count, {
          sysno: sysno, tgid: tgid, tid: tid, sig: sig,
          lr: this.context.lr.toString(),
          force: true
        });
      }
    });
    emit("__INIT_HOOK__", "+0x50d8 attached");
  } catch (e) {
    emit("__INIT_HOOK_FAIL__", "+0x50d8: " + e.message);
  }

  // ─── Bypass mode: Interceptor.replace +0x4fe4 with a PC-advancing stub ─
  // Critical: the BRK at siaddr will retrap if we just return. We MUST
  // advance the trap PC by 4 in the ucontext so the kernel resumes at BRK+4.
  //
  // bionic AArch64 ucontext_t layout (verified against bionic/libc/include/sys/ucontext.h):
  //   offset    field                   size
  //   0         uc_flags                8
  //   8         uc_link                 8
  //   16        uc_stack (ss_sp,...)    24
  //   40        uc_sigmask              8 (bionic) — but kernel writes 128B starting here
  //   48        __padding               120 (alignment to mc)
  //   168       uc_mcontext begin       (=0xa8)
  //     +0      fault_address          8
  //     +8      regs[0..30]            248  (31 * 8)
  //     +256    sp                     8
  //     +264    pc                     8    ← PC offset in mcontext
  //     +272    pstate                 8
  //   PC offset in ucontext = 168 + 264 = 432 = 0x1b0
  //
  // For SIGTRAP from Stalker BRK we want pc += 4 (4-byte instructions).
  if (mode === "bypass") {
    var UC_PC_OFFSET = 0x1b0;
    var bypassFiredCount = 0;
    try {
      var bypassStub = new NativeCallback(function (signum, siPtr, ucPtr) {
        bypassFiredCount++;
        var oldPc = "?", newPc = "?";
        try {
          oldPc = ucPtr.add(UC_PC_OFFSET).readU64().toString();
          var pcU64 = ucPtr.add(UC_PC_OFFSET).readU64();
          // pcU64 is a UInt64 in Frida — add 4
          var advanced = pcU64.add(4);
          ucPtr.add(UC_PC_OFFSET).writeU64(advanced);
          newPc = advanced.toString();
        } catch (e) {
          newPc = "WRITE_FAIL: " + e.message;
        }
        try { send({ layer: "ferrite_bypass", type: "BYPASS_STUB_FIRED",
                     value: "sig=" + signum + " pc=" + oldPc + " -> " + newPc + " call#" + bypassFiredCount,
                     ts: Date.now(), force: true }); } catch (e) {}
        return;
      }, 'void', ['int', 'pointer', 'pointer']);
      Interceptor.replace(addr_4fe4, bypassStub);
      emit("__INIT__", "BYPASS active — +0x4fe4 replaced with PC-advancing stub (PC offset 0x" + UC_PC_OFFSET.toString(16) + ")");
    } catch (e) {
      emit("__INIT_HOOK_FAIL__", "bypass stub: " + e.message);
    }
  }

  // ─── Trigger Stalker on Snap thread (3 sec post-init) ──────────────────
  var STALKER_FOLLOW_DELAY_MS = 3000;
  var STALKER_RUN_MS = 5000;
  var totalEventBlocks = 0;
  var totalCallEvents = 0;
  var totalBlockEvents = 0;

  function processEventBuffer(buf) {
    if (!buf) return;
    totalEventBlocks++;
    var u8 = new Uint8Array(buf);
    var EVENT_SIZE = 32;
    var n = Math.floor(u8.length / EVENT_SIZE);
    for (var i = 0; i < n; i++) {
      var off = i * EVENT_SIZE;
      var t = u8[off] | (u8[off+1] << 8) | (u8[off+2] << 16) | (u8[off+3] << 24);
      if (t === 1) totalCallEvents++;
      else if (t === 8) totalBlockEvents++;
    }
  }

  if (typeof OT_RUN_STALKER !== "undefined" && OT_RUN_STALKER) {
    setTimeout(function () {
      var threads = Process.enumerateThreads();
      var agentTid = Process.getCurrentThreadId();
      var snapThreads = threads.filter(function (t) { return t.id !== agentTid; })
        .sort(function (a, b) { return a.id - b.id; })
        .slice(0, 3);
      emit("STALKER_TRIGGER", "agent=" + agentTid + " following " + snapThreads.length + " Snap threads");
      try { Stalker.queueDrainInterval = 100; Stalker.queueCapacity = 4 * 1024 * 1024; } catch (e) {}
      var followed = [];
      for (var i = 0; i < snapThreads.length; i++) {
        try {
          Stalker.follow(snapThreads[i].id, {
            events: { call: true, block: true },
            onReceive: function (events) { processEventBuffer(events); }
          });
          followed.push(snapThreads[i].id);
          emit("STALKER_FOLLOW_OK", "tid=" + snapThreads[i].id + " name=" + snapThreads[i].name);
        } catch (e) {
          emit("STALKER_FOLLOW_FAIL", "tid=" + snapThreads[i].id + " err=" + e.message);
        }
      }
      setTimeout(function () {
        for (var i = 0; i < followed.length; i++) {
          try { Stalker.unfollow(followed[i]); } catch (e) {}
        }
        try { Stalker.flush(); } catch (e) {}
        setTimeout(function () {
          emit("STALKER_TEST_RESULT", "done", {
            mode: mode,
            ferrite_4fe4_fires: fired_4fe4_count,
            ferrite_tgkill_fires: fired_50d8_count,
            stalker_eventBlocks: totalEventBlocks,
            stalker_callEvents: totalCallEvents,
            stalker_blockEvents: totalBlockEvents,
            verdict: (totalEventBlocks > 0 ? "STALKER_WORKS" : "STALKER_DEAD"),
            kill_signal_traced: (fired_4fe4_count > 0 ? "ferrite_caught_signal" : "no_signal_caught")
          });
        }, 500);
      }, STALKER_RUN_MS);
    }, STALKER_FOLLOW_DELAY_MS);
  } else {
    emit("__INIT__", "OT_RUN_STALKER not set — observation only, no Stalker trigger");
  }
})();
