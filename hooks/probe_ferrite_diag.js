/**
 * Probe: ferrite diagnostic harness (Strategy B Phase 2A).
 *
 * Goal: capture a "death certificate" baseline of how libferrite-launcher.so
 * + libferrite-tracer.so behave at startup and during the inevitable
 * kill-event triggered by foreign instrumentation.
 *
 * Working model (from tools/ferrite_re/01_recon.md + 02_static_analysis.md):
 *   - libferrite-launcher.so (33KB) is in-process. It registers signal
 *     handlers on dlopen via __attribute__((constructor)) → init_array.
 *   - When a signal fires (SIGSEGV/SIGBUS/SIGILL/SIGABRT/SIGTRAP), the handler
 *     captures siginfo+ucontext on a sigaltstack, fork()s a child, execve()s
 *     libferrite-tracer.so as a separate process to dump state, then re-raises
 *     the original signal via tgkill at launcher+0x50d8.
 *
 * What we want to measure (NO Stalker, observation only):
 *   1. Every sigaction()/sigaltstack() call from libferrite-launcher range —
 *      tells us which signals it owns + handler addresses.
 *   2. Every pthread_create() — thread inventory + start_routine offsets.
 *   3. dl_iterate_phdr / dlopen — exact moment libferrite libs map.
 *   4. ptrace / __system_property_get — what ferrite reads at init.
 *   5. fork / vfork / clone / execve — the tracer launch moment when a kill
 *      happens.
 *   6. abort / android_set_abort_message — last-line death.
 *   7. syscall (selectively: tgkill, kill) — confirm the launcher+0x50d8
 *      tgkill re-raise mechanism statically derived from disassembly.
 *
 * Why this won't trigger ferrite itself:
 *   - We hook libc, not libclient/libsigx. ferrite hashes libclient pages, not
 *     libc's PLT.
 *   - The hooked functions (sigaction, pthread_create, dlopen) are called rarely
 *     — once or twice at process init, then never. Frida trampoline overhead
 *     doesn't accumulate the way it does on getpid/syscall (which Snap calls
 *     thousands of times/sec).
 *   - We do NOT install Stalker (Stalker IS what ferrite blocks per inv #49).
 *
 * Caller-origin filtering:
 *   Every hook captures LR (X30) on entry. If LR ∈ libferrite-launcher range
 *   OR libferrite-tracer range → tag event with `fromFerrite: true`. Otherwise
 *   `fromFerrite: false` and emit only if the event type itself is interesting
 *   (e.g. sigaction always emit — we want to see Snap's own sigaction too).
 *
 * Phase A (baseline): load this probe alone. Observe ferrite's init + normal
 *   operation for 30-60s. Establish "what ferrite does when nothing
 *   provokes it".
 * Phase B (kill scenario): load this probe + enable ONE known-fatal hook
 *   (e.g. _OT_PRCTL_HOOK = true via a small config script before
 *   layer2_native.js). Watch ferrite react: sigaction handler firing,
 *   fork+execve("libferrite-tracer.so"), tgkill re-raise.
 */
(function () {
  // ─── Config ───────────────────────────────────────────────────────────
  var MAX_EMIT_PER_TYPE = 60;        // cap per event type to avoid log flood
  var MAX_PROP_NAMES = 200;          // cap unique property names captured
  var MAX_PTRACE_REQ = 100;          // cap per ptrace request type
  var FERRITE_LAUNCHER_RE = /libferrite-launcher/i;
  var FERRITE_TRACER_RE = /libferrite-tracer/i;
  var SIG_NAMES = {
    1: "SIGHUP", 2: "SIGINT", 3: "SIGQUIT", 4: "SIGILL", 5: "SIGTRAP",
    6: "SIGABRT", 7: "SIGBUS", 8: "SIGFPE", 9: "SIGKILL", 10: "SIGUSR1",
    11: "SIGSEGV", 12: "SIGUSR2", 13: "SIGPIPE", 14: "SIGALRM", 15: "SIGTERM",
    17: "SIGCHLD", 19: "SIGSTOP", 20: "SIGTSTP"
  };
  var PTRACE_NAMES = {
    0: "PTRACE_TRACEME", 1: "PTRACE_PEEKTEXT", 2: "PTRACE_PEEKDATA",
    3: "PTRACE_PEEKUSER", 4: "PTRACE_POKETEXT", 5: "PTRACE_POKEDATA",
    7: "PTRACE_CONT", 8: "PTRACE_KILL", 9: "PTRACE_SINGLESTEP",
    16: "PTRACE_ATTACH", 17: "PTRACE_DETACH", 24: "PTRACE_SYSCALL",
    16902: "PTRACE_SEIZE", 16903: "PTRACE_INTERRUPT"
  };
  // tgkill = 131 on AArch64
  var SYS_TGKILL = 131;
  var SYS_KILL = 129;
  var SYS_RT_SIGACTION = 134;
  var SYS_GETTID = 178;

  // ─── Module state ─────────────────────────────────────────────────────
  var ferriteLauncherMod = null;
  var ferriteTracerMod = null;
  var emitCounts = {};
  var seenPropNames = {};
  var seenPtraceReq = {};

  function emit(type, value, extra) {
    var n = (emitCounts[type] || 0) + 1;
    emitCounts[type] = n;
    if (n > MAX_EMIT_PER_TYPE && !(extra && extra.force)) return;
    var p = {
      layer: "ferrite_diag",
      type: type,
      value: value === null || value === undefined ? null : String(value),
      ts: Date.now()
    };
    if (extra) for (var k in extra) p[k] = extra[k];
    try { send(p); } catch (e) {}
  }

  function emitInit(label, ok, err) {
    var p = {
      layer: "ferrite_diag",
      type: ok ? "__INIT_HOOK__" : "__INIT_HOOK_FAIL__",
      value: label, ts: Date.now()
    };
    if (err) p.err = String(err);
    try { send(p); } catch (e) {}
  }

  // Compute ferrite range membership for a given absolute address.
  // Returns null if neither, "launcher" or "tracer" if inside.
  function ferriteOriginOf(addr) {
    if (!addr) return null;
    var n = NULL;
    try { n = ptr(addr.toString()); } catch (e) { return null; }
    if (ferriteLauncherMod) {
      var b = ferriteLauncherMod.base;
      var e = b.add(ferriteLauncherMod.size);
      if (n.compare(b) >= 0 && n.compare(e) < 0) return "launcher";
    }
    if (ferriteTracerMod) {
      var b2 = ferriteTracerMod.base;
      var e2 = b2.add(ferriteTracerMod.size);
      if (n.compare(b2) >= 0 && n.compare(e2) < 0) return "tracer";
    }
    return null;
  }

  function ferriteOffsetOf(addr) {
    var origin = ferriteOriginOf(addr);
    if (!origin) return null;
    var mod = origin === "launcher" ? ferriteLauncherMod : ferriteTracerMod;
    return { origin: origin, off: addr.sub(mod.base).toString() };
  }

  function detectFerriteModules() {
    try {
      var mods = Process.enumerateModules();
      for (var i = 0; i < mods.length; i++) {
        var m = mods[i];
        if (!ferriteLauncherMod && FERRITE_LAUNCHER_RE.test(m.name)) {
          ferriteLauncherMod = m;
          emit("FERRITE_MODULE_FOUND", "launcher", {
            base: m.base.toString(), size: m.size, path: m.path, force: true
          });
        }
        if (!ferriteTracerMod && FERRITE_TRACER_RE.test(m.name)) {
          ferriteTracerMod = m;
          emit("FERRITE_MODULE_FOUND", "tracer", {
            base: m.base.toString(), size: m.size, path: m.path, force: true
          });
        }
      }
    } catch (e) {}
  }

  // ─── Hooks ────────────────────────────────────────────────────────────

  function hookSigaction() {
    // sigaction is the libc wrapper; some libs call __sigaction directly
    // and some go via syscall(rt_sigaction). Cover the wrapper here; the
    // raw syscall is covered by hookSyscall().
    var names = ["sigaction", "__sigaction", "bsd_signal", "signal"];
    for (var i = 0; i < names.length; i++) {
      var name = names[i];
      var p = Module.findExportByName("libc.so", name);
      if (!p) { emitInit(name, false, "not exported"); continue; }
      try {
        Interceptor.attach(p, (function (sym) { return {
          onEnter: function (args) {
            this.signum = args[0].toInt32();
            this.actPtr = args[1];
            this.lr = this.context.lr;
            var origin = ferriteOriginOf(this.lr);
            this.fromFerrite = !!origin;
            this.origin = origin;
          },
          onLeave: function (retval) {
            var sigName = SIG_NAMES[this.signum] || ("SIG_" + this.signum);
            var handlerAddr = "(none)";
            var flags = "(none)";
            if (this.actPtr && !this.actPtr.isNull()) {
              try {
                // struct sigaction on AArch64 Bionic:
                //   void (*sa_handler)(int);  (offset 0, 8B)
                //   ulong sa_flags;           (offset 8, 8B) — yes, 8B on bionic
                //   void (*sa_restorer)(void);(offset 16, 8B)
                //   sigset_t sa_mask;         (offset 24)
                // sa_sigaction is union with sa_handler.
                var h = this.actPtr.readPointer();
                handlerAddr = h.toString();
                flags = this.actPtr.add(8).readU64().toString();
              } catch (e) {}
            }
            var lrInfo = ferriteOffsetOf(this.lr);
            emit("SIGACTION_CALL", sym + "(" + sigName + ")", {
              signum: this.signum,
              handler: handlerAddr,
              flags: flags,
              fromFerrite: this.fromFerrite,
              origin: this.origin || "other",
              lrAbs: this.lr.toString(),
              lrOff: lrInfo ? (lrInfo.origin + "+" + lrInfo.off) : null,
              ret: retval.toInt32(),
              force: true   // never throttle sigaction events — these are gold
            });
          }
        }; })(name));
        emitInit(name, true);
      } catch (e) { emitInit(name, false, e.message); }
    }
  }

  function hookSigaltstack() {
    var p = Module.findExportByName("libc.so", "sigaltstack");
    if (!p) { emitInit("sigaltstack", false, "not exported"); return; }
    try {
      Interceptor.attach(p, {
        onEnter: function (args) {
          this.ssPtr = args[0];
          this.lr = this.context.lr;
        },
        onLeave: function (retval) {
          var ssBase = "(none)", ssSize = 0;
          if (this.ssPtr && !this.ssPtr.isNull()) {
            try {
              ssBase = this.ssPtr.readPointer().toString();
              ssSize = this.ssPtr.add(8).readU64().toNumber();
            } catch (e) {}
          }
          var lrInfo = ferriteOffsetOf(this.lr);
          emit("SIGALTSTACK", ssBase + " size=" + ssSize, {
            ssBase: ssBase, ssSize: ssSize,
            origin: lrInfo ? lrInfo.origin : "other",
            lrOff: lrInfo ? (lrInfo.origin + "+" + lrInfo.off) : null,
            force: true
          });
        }
      });
      emitInit("sigaltstack", true);
    } catch (e) { emitInit("sigaltstack", false, e.message); }
  }

  function hookPthreadCreate() {
    var p = Module.findExportByName("libc.so", "pthread_create");
    if (!p) { emitInit("pthread_create", false, "not exported"); return; }
    try {
      Interceptor.attach(p, {
        onEnter: function (args) {
          this.threadIdPtr = args[0];
          this.startRoutine = args[2];
          this.lr = this.context.lr;
        },
        onLeave: function (retval) {
          var startInfo = ferriteOffsetOf(this.startRoutine);
          var lrInfo = ferriteOffsetOf(this.lr);
          var origin = startInfo ? startInfo.origin : (lrInfo ? lrInfo.origin : "other");
          // Symbolize start_routine if possible
          var sym = "?";
          try {
            var s = DebugSymbol.fromAddress(this.startRoutine);
            if (s && s.name) sym = s.name + (s.moduleName ? ("@" + s.moduleName) : "");
          } catch (e) {}
          emit("PTHREAD_CREATE", "start=" + this.startRoutine + " " + sym, {
            startRoutine: this.startRoutine.toString(),
            startOff: startInfo ? (startInfo.origin + "+" + startInfo.off) : null,
            startSym: sym,
            origin: origin,
            lrOff: lrInfo ? (lrInfo.origin + "+" + lrInfo.off) : null,
            force: (origin === "launcher" || origin === "tracer")
          });
        }
      });
      emitInit("pthread_create", true);
    } catch (e) { emitInit("pthread_create", false, e.message); }
  }

  function hookDlIteratePhdr() {
    var p = Module.findExportByName("libc.so", "dl_iterate_phdr");
    if (!p) {
      p = Module.findExportByName("libdl.so", "dl_iterate_phdr");
    }
    if (!p) { emitInit("dl_iterate_phdr", false, "not exported"); return; }
    try {
      Interceptor.attach(p, {
        onEnter: function (args) {
          this.lr = this.context.lr;
        },
        onLeave: function (retval) {
          var lrInfo = ferriteOffsetOf(this.lr);
          emit("DL_ITERATE_PHDR", lrInfo ? (lrInfo.origin + "+" + lrInfo.off) : "other", {
            origin: lrInfo ? lrInfo.origin : "other",
            lrAbs: this.lr.toString(),
            ret: retval.toInt32()
          });
        }
      });
      emitInit("dl_iterate_phdr", true);
    } catch (e) { emitInit("dl_iterate_phdr", false, e.message); }
  }

  function hookDlopen() {
    var names = ["dlopen", "android_dlopen_ext"];
    for (var i = 0; i < names.length; i++) {
      var name = names[i];
      var p = Module.findExportByName("libdl.so", name);
      if (!p) p = Module.findExportByName("libc.so", name);
      if (!p) { emitInit(name, false, "not exported"); continue; }
      try {
        Interceptor.attach(p, (function (sym) { return {
          onEnter: function (args) {
            this.pathPtr = args[0];
            this.lr = this.context.lr;
            try {
              this.pathStr = this.pathPtr && !this.pathPtr.isNull() ? this.pathPtr.readUtf8String() : null;
            } catch (e) { this.pathStr = "(unreadable)"; }
          },
          onLeave: function (retval) {
            // Re-detect modules every time something is loaded
            if (!ferriteLauncherMod || !ferriteTracerMod) detectFerriteModules();
            var lrInfo = ferriteOffsetOf(this.lr);
            var isFerrite = this.pathStr && /libferrite/i.test(this.pathStr);
            emit("DLOPEN", sym + "(" + (this.pathStr || "?") + ")", {
              path: this.pathStr,
              isFerriteLib: isFerrite,
              ret: retval.toString(),
              lrOff: lrInfo ? (lrInfo.origin + "+" + lrInfo.off) : null,
              force: isFerrite || true   // force-emit dlopens — relatively rare
            });
          }
        }; })(name));
        emitInit(name, true);
      } catch (e) { emitInit(name, false, e.message); }
    }
  }

  function hookPtrace() {
    var p = Module.findExportByName("libc.so", "ptrace");
    if (!p) { emitInit("ptrace", false, "not exported"); return; }
    try {
      Interceptor.attach(p, {
        onEnter: function (args) {
          this.req = args[0].toInt32();
          this.targetPid = args[1].toInt32();
          this.addr = args[2];
          this.data = args[3];
          this.lr = this.context.lr;
        },
        onLeave: function (retval) {
          var nKey = "PTRACE_" + this.req;
          var nForReq = (seenPtraceReq[nKey] || 0) + 1;
          seenPtraceReq[nKey] = nForReq;
          if (nForReq > MAX_PTRACE_REQ) return;
          var name = PTRACE_NAMES[this.req] || ("REQ_" + this.req);
          var lrInfo = ferriteOffsetOf(this.lr);
          emit("PTRACE", name + " pid=" + this.targetPid, {
            request: this.req, requestName: name,
            targetPid: this.targetPid,
            addr: this.addr.toString(), data: this.data.toString(),
            ret: retval.toInt32(),
            origin: lrInfo ? lrInfo.origin : "other",
            lrOff: lrInfo ? (lrInfo.origin + "+" + lrInfo.off) : null,
            force: true
          });
        }
      });
      emitInit("ptrace", true);
    } catch (e) { emitInit("ptrace", false, e.message); }
  }

  function hookSyspropGet() {
    // Only emit when caller is libferrite. Non-ferrite calls would flood
    // (Snap does thousands per second).
    var p = Module.findExportByName("libc.so", "__system_property_get");
    if (!p) { emitInit("__system_property_get", false, "not exported"); return; }
    try {
      Interceptor.attach(p, {
        onEnter: function (args) {
          this.namePtr = args[0];
          this.lr = this.context.lr;
          this.fromFerrite = !!ferriteOriginOf(this.lr);
          if (this.fromFerrite) {
            try { this.nameStr = this.namePtr.readUtf8String(); } catch (e) { this.nameStr = "?"; }
          }
        },
        onLeave: function (retval) {
          if (!this.fromFerrite) return;
          if (Object.keys(seenPropNames).length > MAX_PROP_NAMES) return;
          var key = this.nameStr || "?";
          if (seenPropNames[key]) {
            seenPropNames[key]++;
            return;     // already emitted at least once; just count
          }
          seenPropNames[key] = 1;
          var lrInfo = ferriteOffsetOf(this.lr);
          emit("FERRITE_SYSPROP_GET", key, {
            name: key,
            origin: lrInfo ? lrInfo.origin : "other",
            lrOff: lrInfo ? (lrInfo.origin + "+" + lrInfo.off) : null,
            force: true
          });
        }
      });
      emitInit("__system_property_get", true);
    } catch (e) { emitInit("__system_property_get", false, e.message); }
  }

  function hookForkFamily() {
    var names = ["fork", "vfork"];
    for (var i = 0; i < names.length; i++) {
      var name = names[i];
      var p = Module.findExportByName("libc.so", name);
      if (!p) { emitInit(name, false, "not exported"); continue; }
      try {
        Interceptor.attach(p, (function (sym) { return {
          onEnter: function (args) { this.lr = this.context.lr; },
          onLeave: function (retval) {
            var lrInfo = ferriteOffsetOf(this.lr);
            emit("FORK", sym, {
              ret: retval.toInt32(),
              origin: lrInfo ? lrInfo.origin : "other",
              lrOff: lrInfo ? (lrInfo.origin + "+" + lrInfo.off) : null,
              force: true
            });
          }
        }; })(name));
        emitInit(name, true);
      } catch (e) { emitInit(name, false, e.message); }
    }
  }

  function hookExecve() {
    var names = ["execve", "execv", "execvp", "execvpe", "posix_spawn", "posix_spawnp"];
    for (var i = 0; i < names.length; i++) {
      var name = names[i];
      var p = Module.findExportByName("libc.so", name);
      if (!p) { emitInit(name, false, "not exported"); continue; }
      try {
        Interceptor.attach(p, (function (sym) { return {
          onEnter: function (args) {
            this.lr = this.context.lr;
            // For execve(path, argv, envp): args[0] is path
            // For posix_spawn(pid, path, ...): args[1] is path
            var pathPtr = (sym.indexOf("posix_spawn") === 0) ? args[1] : args[0];
            try {
              this.path = pathPtr && !pathPtr.isNull() ? pathPtr.readUtf8String() : "?";
            } catch (e) { this.path = "(unreadable)"; }
            // Try to read first 4 argv entries
            var argvPtr = (sym.indexOf("posix_spawn") === 0) ? args[3] : args[1];
            this.argv = [];
            try {
              if (argvPtr && !argvPtr.isNull()) {
                for (var i = 0; i < 6; i++) {
                  var a = argvPtr.add(i * Process.pointerSize).readPointer();
                  if (a.isNull()) break;
                  this.argv.push(a.readUtf8String());
                }
              }
            } catch (e) {}
          },
          onLeave: function (retval) {
            var lrInfo = ferriteOffsetOf(this.lr);
            var isFerriteExec = this.path && /ferrite|tracer/i.test(this.path);
            emit("EXECVE", sym + "(" + (this.path || "?") + ")", {
              path: this.path,
              argv: this.argv,
              isFerriteExec: !!isFerriteExec,
              ret: retval.toInt32(),
              origin: lrInfo ? lrInfo.origin : "other",
              lrOff: lrInfo ? (lrInfo.origin + "+" + lrInfo.off) : null,
              force: true
            });
          }
        }; })(name));
        emitInit(name, true);
      } catch (e) { emitInit(name, false, e.message); }
    }
  }

  function hookAbort() {
    var names = ["abort", "android_set_abort_message", "__libc_fatal", "__assert", "__assert2"];
    for (var i = 0; i < names.length; i++) {
      var name = names[i];
      var p = Module.findExportByName("libc.so", name);
      if (!p) { emitInit(name, false, "not exported"); continue; }
      try {
        Interceptor.attach(p, (function (sym) { return {
          onEnter: function (args) {
            this.lr = this.context.lr;
            var msg = "(none)";
            if (sym === "android_set_abort_message" && args[0] && !args[0].isNull()) {
              try { msg = args[0].readUtf8String(); } catch (e) {}
            }
            this.msg = msg;
          },
          onLeave: function (retval) {
            var lrInfo = ferriteOffsetOf(this.lr);
            emit("ABORT", sym + ": " + this.msg, {
              fn: sym, msg: this.msg,
              origin: lrInfo ? lrInfo.origin : "other",
              lrOff: lrInfo ? (lrInfo.origin + "+" + lrInfo.off) : null,
              force: true
            });
          }
        }; })(name));
        emitInit(name, true);
      } catch (e) { emitInit(name, false, e.message); }
    }
  }

  function hookSyscall() {
    // Selective: only tgkill, kill, rt_sigaction, gettid. We do NOT hook
    // syscall(2) globally — that's the path that crashes Snap on getpid
    // burst per layer2_native.js comments. Instead we filter inside onEnter
    // and bail fast for uninteresting syscalls.
    var p = Module.findExportByName("libc.so", "syscall");
    if (!p) { emitInit("syscall", false, "not exported"); return; }
    try {
      Interceptor.attach(p, {
        onEnter: function (args) {
          this.sysno = args[0].toInt32();
          // Fast-path bail for syscalls we don't care about
          if (this.sysno !== SYS_TGKILL && this.sysno !== SYS_KILL &&
              this.sysno !== SYS_RT_SIGACTION) {
            this.skip = true;
            return;
          }
          this.skip = false;
          this.arg0 = args[1].toInt32();
          this.arg1 = args[2].toInt32();
          this.arg2 = args[3].toInt32();
          this.lr = this.context.lr;
        },
        onLeave: function (retval) {
          if (this.skip) return;
          var name = "?";
          if (this.sysno === SYS_TGKILL) name = "tgkill";
          else if (this.sysno === SYS_KILL) name = "kill";
          else if (this.sysno === SYS_RT_SIGACTION) name = "rt_sigaction";
          else if (this.sysno === SYS_GETTID) name = "gettid";
          var lrInfo = ferriteOffsetOf(this.lr);
          var sigName = SIG_NAMES[this.arg2] || ("sig=" + this.arg2);
          emit("SYSCALL_FERRITE_OP", name + "(" + this.arg0 + ", " + this.arg1 + ", " + sigName + ")", {
            sysno: this.sysno, name: name,
            arg0: this.arg0, arg1: this.arg1, arg2: this.arg2,
            ret: retval.toInt32(),
            origin: lrInfo ? lrInfo.origin : "other",
            lrOff: lrInfo ? (lrInfo.origin + "+" + lrInfo.off) : null,
            force: true
          });
        }
      });
      emitInit("syscall(selective)", true);
    } catch (e) { emitInit("syscall(selective)", false, e.message); }
  }

  // ─── Sigaction handler query ──────────────────────────────────────────
  // Read CURRENT sigaction handler for each catchable signal. Tells us who
  // owns SIGSEGV/SIGBUS/SIGILL/SIGABRT/SIGTRAP/SIGFPE.
  //
  // bionic AArch64 struct sigaction layout (verified against
  // /bionic/libc/include/bits/signal_types.h):
  //   union { sa_handler; sa_sigaction; }   offset 0   8B (pointer)
  //   sigset_t sa_mask                      offset 8   8B (unsigned long)
  //   int sa_flags                          offset 16  4B
  //   (4B padding)                          offset 20
  //   void (*sa_restorer)(void)             offset 24  8B
  //   total: 32B (we alloc 256B for safety)
  // Earlier probe revision read the wrong offset → captured flag bytes
  // (0x8000004 = SA_ONSTACK|SA_SIGINFO) instead of handler. Fixed via the
  // explicit 0/16/24 layout below + dump first 32B of buffer for sanity check.
  function querySigactionHandlers() {
    var sigactionPtr = Module.findExportByName("libc.so", "sigaction");
    if (!sigactionPtr) {
      emit("__INIT__", "sigaction not exported — cannot query handlers", { force: true });
      return;
    }
    var sigactionFn = new NativeFunction(sigactionPtr, "int", ["int", "pointer", "pointer"]);
    var oldactBuf = Memory.alloc(256);
    var probeSigs = [4, 5, 6, 7, 8, 11];
    for (var i = 0; i < probeSigs.length; i++) {
      var sig = probeSigs[i];
      // Zero buffer
      try { Memory.writeByteArray(oldactBuf, new Array(64).fill(0)); } catch (e) {}
      var rv = -1;
      try { rv = sigactionFn(sig, NULL, oldactBuf); } catch (e) {}
      // Dump first 32 bytes as hex for offset disambiguation
      var raw = "";
      try {
        var u8 = new Uint8Array(oldactBuf.readByteArray(32));
        for (var k = 0; k < u8.length; k++) raw += (u8[k] < 16 ? "0" : "") + u8[k].toString(16);
      } catch (e) {}
      var handler = NULL, flags = 0;
      try { handler = oldactBuf.readPointer(); } catch (e) {}
      try { flags = oldactBuf.add(16).readU32(); } catch (e) {}
      var origin = ferriteOriginOf(handler);
      var info = ferriteOffsetOf(handler);
      var sym = "?";
      if (handler && !handler.isNull()) {
        try {
          var s = DebugSymbol.fromAddress(handler);
          if (s && s.name) sym = s.name + (s.moduleName ? ("@" + s.moduleName) : "");
        } catch (e) {}
        var hs = handler.toString();
        if (hs === "0x0") sym = "SIG_DFL";
        else if (hs === "0x1") sym = "SIG_IGN";
      }
      emit("HANDLER_QUERY", "sig=" + (SIG_NAMES[sig] || sig) + " handler=" + handler + " sym=" + sym, {
        signum: sig,
        signame: SIG_NAMES[sig] || ("SIG_" + sig),
        handler: handler.toString(),
        handlerSym: sym,
        flags: "0x" + flags.toString(16),
        origin: origin || "other",
        ownerOff: info ? (info.origin + "+" + info.off) : null,
        rv: rv,
        raw32: raw,
        force: true
      });
    }
  }

  // ─── Self-crash provocation ───────────────────────────────────────────
  // Send a real signal to the Snap process via libc raise(). ferrite's
  // sigaction handler MUST catch it (we proved SIGILL handler lives at
  // libferrite-launcher+0x4fe4). Our hooks then capture the chain:
  // sigaltstack registration / pthread_create / fork / execve / tgkill.
  //
  // Frida's Memory.writeU32(NULL) gets caught at JS layer by Frida's own
  // SIGSEGV trampoline → never reaches Snap process. raise() goes through
  // libc which delivers a real signal to the calling thread.
  //
  // Set globalThis.OT_SELF_CRASH = "<seconds>:<signum>" before this script
  // loads. Examples:
  //   "8:11"   = raise SIGSEGV  in 8s
  //   "8:6"    = raise SIGABRT  in 8s
  //   "8:5"    = raise SIGTRAP  in 8s (Stalker-equivalent)
  function maybeScheduleSelfCrash() {
    if (typeof OT_SELF_CRASH === "undefined") return;
    var parts = String(OT_SELF_CRASH).split(":");
    var delay = parseInt(parts[0], 10);
    var sig = parseInt(parts[1] || "11", 10);
    if (isNaN(delay) || delay < 1) delay = 5;
    if (isNaN(sig) || sig < 1) sig = 11;
    var raisePtr = Module.findExportByName("libc.so", "raise");
    if (!raisePtr) {
      emit("__INIT__", "SELF_CRASH: raise not exported — abort fallback", { force: true });
      return;
    }
    var raiseFn = new NativeFunction(raisePtr, "int", ["int"]);
    var sigName = SIG_NAMES[sig] || ("SIG_" + sig);
    emit("__INIT__", "SELF_CRASH armed: will raise(" + sigName + ") in " + delay + "s", { force: true });
    setTimeout(function () {
      emit("SELF_CRASH_TRIGGERING", "raise(" + sigName + ") via libc NOW", { force: true });
      var rv = -1;
      try {
        rv = raiseFn(sig);
      } catch (e) {
        emit("SELF_CRASH_JS_CAUGHT", e.message, { force: true });
        return;
      }
      // If we got here, either signal was ignored OR ferrite handler returned cleanly
      emit("SELF_CRASH_RETURNED", "raise() returned " + rv + " (signal not fatal — ferrite handler swallowed?)", { force: true });
    }, delay * 1000);
  }

  // ─── Init sequence ────────────────────────────────────────────────────
  function init() {
    // Detect ferrite if it's already loaded (likely yes when --attach)
    detectFerriteModules();
    if (ferriteLauncherMod) {
      emit("__INIT__", "libferrite-launcher.so already mapped at " + ferriteLauncherMod.base + " size=" + ferriteLauncherMod.size, { force: true });
    } else {
      emit("__INIT__", "libferrite-launcher.so NOT yet mapped — will detect on dlopen", { force: true });
    }
    if (ferriteTracerMod) {
      emit("__INIT__", "libferrite-tracer.so already mapped at " + ferriteTracerMod.base + " size=" + ferriteTracerMod.size, { force: true });
    }
    hookSigaction();
    hookSigaltstack();
    hookPthreadCreate();
    hookDlIteratePhdr();
    hookDlopen();
    hookPtrace();
    hookSyspropGet();
    hookForkFamily();
    hookExecve();
    hookAbort();
    hookSyscall();
    // Query sigaction handlers AFTER ferrite mod is detected and hooks are armed
    querySigactionHandlers();
    // Optionally arm self-crash
    maybeScheduleSelfCrash();
    emit("__INIT__", "ferrite_diag probe armed", { force: true });
  }

  init();

  // Periodic re-detection in case ferrite loads later
  setInterval(function () {
    if (!ferriteLauncherMod || !ferriteTracerMod) detectFerriteModules();
  }, 2000);

  // ─── Optional: enable ONE known-fatal hook to provoke ferrite ─────────
  // Set OT_FERRITE_PROVOKE = "prctl" | "getpid" | "ptrace" | "syscall"
  // BEFORE this script loads (via injected config) to also enable the
  // matching layer2_native flag. layer2_native.js must be loaded AFTER
  // this probe for the flag to apply — load order in android_monitor.py
  // staggered loader processes alphabetically so this works automatically
  // (probe_ferrite_diag < layer2_native by default; if not, change order).
  if (typeof OT_FERRITE_PROVOKE === "string") {
    var pmap = {
      prctl:   "_OT_PRCTL_HOOK",
      getpid:  "_OT_PID_HOOKS",
      ptrace:  "_OT_PTRACE_HOOK",
      syscall: "_OT_SYSCALL_HOOK"
    };
    var flag = pmap[OT_FERRITE_PROVOKE];
    if (flag) {
      globalThis[flag] = true;
      emit("__INIT__", "PROVOKE mode armed: " + OT_FERRITE_PROVOKE + " (set globalThis." + flag + " = true)", { force: true });
    } else {
      emit("__INIT__", "PROVOKE: unknown mode '" + OT_FERRITE_PROVOKE + "', expected prctl|getpid|ptrace|syscall", { force: true });
    }
  }
})();
