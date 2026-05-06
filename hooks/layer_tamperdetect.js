/**
 * Layer: tamperdetect
 *
 * Diagnostic Frida layer to identify the path Snap uses to detect OmniShield's
 * Binder hook (root cause of SS03 with the PR-KSChain fix). Hooks high-value
 * Java APIs Snap might use to fingerprint the hook environment. NO behavior
 * change — log only.
 *
 * Vectors covered:
 *   H1  timing            — System.nanoTime, SystemClock.elapsedRealtimeNanos
 *   H2  stack-trace       — Thread.getStackTrace, VMStack.getThreadStackTrace,
 *                            Throwable.fillInStackTrace (sampled)
 *   H3  procfs / sysfs    — FileInputStream(/proc|/sys|*maps*), RandomAccessFile
 *   H4  subprocess        — Runtime.exec, ProcessBuilder.start
 *   H5  SS03 trigger      — Activity.startActivity / startActivityForResult
 *                            (catches the moment Snap launches the error screen)
 *   H6  attestation flow  — fd0.getAttestationPayloadProto return value
 *                            (already covered by argos layer; kept here to
 *                            correlate timestamps with detection events)
 *
 * Filter: only emit if the call stack contains "snap" or "snapchat" — drops
 * thousands of framework-internal nanoTime/getStackTrace calls.
 *
 * Cap: each event type capped at the listed max to keep output bounded.
 */
(function () {
    function emit(type, value, extra) {
        var p = {
            layer: "tamperdetect",
            type: type,
            value: value === null || value === undefined ? null : String(value),
            ts: Date.now()
        };
        if (extra) for (var k in extra) p[k] = extra[k];
        send(p);
    }

    function emitInit(label, ok, err) {
        emit(ok ? "__INIT_HOOK__" : "__INIT_HOOK_FAIL__", label,
             err ? { err: String(err) } : undefined);
    }

    function shortStack(limit) {
        try {
            var Throwable_ = Java.use("java.lang.Throwable");
            var t = Throwable_.$new();
            var st = t.getStackTrace();
            var n = Math.min(st.length, limit || 8);
            var out = [];
            for (var i = 0; i < n; i++) {
                var fr = st[i];
                out.push(fr.getClassName() + "." + fr.getMethodName() +
                         ":" + fr.getLineNumber());
            }
            return out;
        } catch (e) { return ["<stack-err:" + e + ">"]; }
    }

    function stackHasSnap(stack) {
        for (var i = 0; i < stack.length; i++) {
            var s = stack[i];
            if (s.indexOf("snap") >= 0 || s.indexOf("Snap") >= 0) return true;
        }
        return false;
    }

    function stackTraceFromArray(stArr, limit) {
        var n = Math.min(stArr.length, limit || 8);
        var out = [];
        for (var i = 0; i < n; i++) {
            var fr = stArr[i];
            out.push(fr.getClassName() + "." + fr.getMethodName() +
                     ":" + fr.getLineNumber());
        }
        return out;
    }

    Java.perform(function () {

        // ── H1a: System.nanoTime ──────────────────────────────────────────
        try {
            var System_ = Java.use("java.lang.System");
            var nanoTotal = 0, nanoEmit = 0;
            var nanoMax = 100;
            System_.nanoTime.implementation = function () {
                nanoTotal++;
                var ret = this.nanoTime();
                if (nanoEmit < nanoMax) {
                    var stack = shortStack(5);
                    if (stackHasSnap(stack)) {
                        nanoEmit++;
                        emit("NANOTIME", ret.toString(), {
                            stack: stack, totalCalls: nanoTotal
                        });
                    }
                }
                return ret;
            };
            emitInit("System.nanoTime", true);
        } catch (e) { emitInit("System.nanoTime", false, e); }

        // ── H1b: SystemClock.elapsedRealtimeNanos ─────────────────────────
        try {
            var SystemClock_ = Java.use("android.os.SystemClock");
            var ertTotal = 0, ertEmit = 0;
            var ertMax = 100;
            SystemClock_.elapsedRealtimeNanos.implementation = function () {
                ertTotal++;
                var ret = this.elapsedRealtimeNanos();
                if (ertEmit < ertMax) {
                    var stack = shortStack(5);
                    if (stackHasSnap(stack)) {
                        ertEmit++;
                        emit("ELAPSED_RT_NANOS", ret.toString(), {
                            stack: stack, totalCalls: ertTotal
                        });
                    }
                }
                return ret;
            };
            emitInit("SystemClock.elapsedRealtimeNanos", true);
        } catch (e) { emitInit("SystemClock.elapsedRealtimeNanos", false, e); }

        // ── H2a: Thread.getStackTrace (Snap-side stack inspection) ────────
        try {
            var Thread_ = Java.use("java.lang.Thread");
            var stTotal = 0, stEmit = 0;
            var stMax = 50;
            Thread_.getStackTrace.implementation = function () {
                stTotal++;
                var ret = this.getStackTrace();
                if (stEmit < stMax) {
                    var caller = shortStack(6);
                    if (stackHasSnap(caller)) {
                        stEmit++;
                        emit("THREAD_GET_STACKTRACE",
                             "frames=" + ret.length, {
                            callerStack: caller,
                            inspectedStack: stackTraceFromArray(ret, 8),
                            totalCalls: stTotal
                        });
                    }
                }
                return ret;
            };
            emitInit("Thread.getStackTrace", true);
        } catch (e) { emitInit("Thread.getStackTrace", false, e); }

        // ── H2b: VMStack.getThreadStackTrace ──────────────────────────────
        try {
            var VMStack_ = Java.use("dalvik.system.VMStack");
            var vmsTotal = 0, vmsEmit = 0;
            var vmsMax = 50;
            VMStack_.getThreadStackTrace.implementation = function (thread) {
                vmsTotal++;
                var ret = this.getThreadStackTrace(thread);
                if (vmsEmit < vmsMax) {
                    var caller = shortStack(6);
                    if (stackHasSnap(caller)) {
                        vmsEmit++;
                        var tname = "?";
                        try { tname = thread ? thread.getName() : "?"; }
                        catch (e) { tname = "<err>"; }
                        emit("VMSTACK_GET_THREAD_STACKTRACE",
                             "frames=" + ret.length, {
                            callerStack: caller,
                            targetThread: tname,
                            totalCalls: vmsTotal
                        });
                    }
                }
                return ret;
            };
            emitInit("VMStack.getThreadStackTrace", true);
        } catch (e) { emitInit("VMStack.getThreadStackTrace", false, e); }

        // ── H3a: FileInputStream(File) ─ procfs/sysfs introspection ───────
        try {
            var FIS_ = Java.use("java.io.FileInputStream");
            var sensitivePath = function (p) {
                if (!p) return false;
                if (p.indexOf("/proc/") === 0) return true;
                if (p.indexOf("/sys/") === 0) return true;
                if (p.indexOf("maps") >= 0) return true;
                if (p.indexOf("/data/adb") >= 0) return true;
                if (p.indexOf("omnishield") >= 0) return true;
                return false;
            };
            FIS_.$init.overload("java.io.File").implementation = function (file) {
                var path = "?";
                try { path = file ? file.getPath() : "?"; } catch (e) {}
                if (sensitivePath(path)) {
                    var stack = shortStack(7);
                    if (stackHasSnap(stack)) {
                        emit("FILE_OPEN_FILE", path, { stack: stack });
                    }
                }
                return this.$init(file);
            };
            FIS_.$init.overload("java.lang.String").implementation = function (path) {
                if (sensitivePath(path)) {
                    var stack = shortStack(7);
                    if (stackHasSnap(stack)) {
                        emit("FILE_OPEN_STR", path, { stack: stack });
                    }
                }
                return this.$init(path);
            };
            emitInit("FileInputStream(File|String) /proc /sys /data/adb", true);
        } catch (e) { emitInit("FileInputStream", false, e); }

        // ── H3b: RandomAccessFile ─────────────────────────────────────────
        try {
            var RAF_ = Java.use("java.io.RandomAccessFile");
            RAF_.$init.overload("java.io.File", "java.lang.String").implementation = function (file, mode) {
                try {
                    var path = file ? file.getPath() : "?";
                    if (path.indexOf("/proc") === 0 || path.indexOf("/sys/") === 0 ||
                        path.indexOf("maps") >= 0) {
                        var stack = shortStack(7);
                        if (stackHasSnap(stack)) {
                            emit("RANDOM_ACCESS_FILE", path,
                                 { stack: stack, mode: mode });
                        }
                    }
                } catch (e) {}
                return this.$init(file, mode);
            };
            emitInit("RandomAccessFile", true);
        } catch (e) { emitInit("RandomAccessFile", false, e); }

        // ── H4a: Runtime.exec(String) ─────────────────────────────────────
        try {
            var Runtime_ = Java.use("java.lang.Runtime");
            Runtime_.exec.overload("java.lang.String").implementation = function (cmd) {
                var stack = shortStack(7);
                if (stackHasSnap(stack)) {
                    emit("RUNTIME_EXEC_STR", cmd, { stack: stack });
                }
                return this.exec(cmd);
            };
            Runtime_.exec.overload("[Ljava.lang.String;").implementation = function (argv) {
                var stack = shortStack(7);
                if (stackHasSnap(stack)) {
                    var argvStr = "?";
                    try {
                        var parts = [];
                        for (var i = 0; i < argv.length; i++) parts.push(String(argv[i]));
                        argvStr = parts.join(" ");
                    } catch (e) {}
                    emit("RUNTIME_EXEC_ARGV", argvStr, { stack: stack });
                }
                return this.exec(argv);
            };
            emitInit("Runtime.exec", true);
        } catch (e) { emitInit("Runtime.exec", false, e); }

        // ── H4b: ProcessBuilder.start ─────────────────────────────────────
        try {
            var PB_ = Java.use("java.lang.ProcessBuilder");
            PB_.start.implementation = function () {
                var stack = shortStack(7);
                if (stackHasSnap(stack)) {
                    var cmd = "?";
                    try {
                        var list = this.command();
                        var parts = [];
                        for (var i = 0; i < list.size(); i++)
                            parts.push(String(list.get(i)));
                        cmd = parts.join(" ");
                    } catch (e) {}
                    emit("PROCESS_BUILDER_START", cmd, { stack: stack });
                }
                return this.start();
            };
            emitInit("ProcessBuilder.start", true);
        } catch (e) { emitInit("ProcessBuilder.start", false, e); }

        // ── H5: Activity.startActivity (catches SS03 launcher) ────────────
        try {
            var Activity_ = Java.use("android.app.Activity");
            Activity_.startActivity.overload("android.content.Intent").implementation = function (intent) {
                try {
                    var c = intent ? intent.getComponent() : null;
                    var name = c ? c.getClassName() : "?";
                    if (name.indexOf("snap") >= 0 || name.indexOf("Snap") >= 0 ||
                        name.indexOf("Error") >= 0 || name.indexOf("SS03") >= 0 ||
                        name.indexOf("Bounce") >= 0) {
                        emit("ACTIVITY_START", name, {
                            action: intent ? String(intent.getAction()) : "?",
                            stack: shortStack(7)
                        });
                    }
                } catch (e) {}
                return this.startActivity(intent);
            };
            emitInit("Activity.startActivity", true);
        } catch (e) { emitInit("Activity.startActivity", false, e); }

        // ── H6: Toast / Dialog markers (SS03 may show as a Dialog) ────────
        try {
            var Toast_ = Java.use("android.widget.Toast");
            Toast_.show.implementation = function () {
                try {
                    var t = this.getView();
                    var stack = shortStack(7);
                    if (stackHasSnap(stack))
                        emit("TOAST_SHOW", "(toast)", { stack: stack });
                } catch (e) {}
                return this.show();
            };
            emitInit("Toast.show", true);
        } catch (e) { emitInit("Toast.show", false, e); }

        // ── H7: Process.killProcess + System.exit (Snap may self-kill) ────
        try {
            var Process_ = Java.use("android.os.Process");
            Process_.killProcess.implementation = function (pid) {
                emit("PROCESS_KILL", "pid=" + pid, { stack: shortStack(8) });
                return this.killProcess(pid);
            };
            emitInit("Process.killProcess", true);
        } catch (e) { emitInit("Process.killProcess", false, e); }

        try {
            var SystemExit_ = Java.use("java.lang.System");
            SystemExit_.exit.implementation = function (code) {
                emit("SYSTEM_EXIT", "code=" + code, { stack: shortStack(8) });
                return this.exit(code);
            };
            emitInit("System.exit", true);
        } catch (e) { emitInit("System.exit", false, e); }

        // ── H8: KeyStore.getCertificateChain ─ direct cert chain capture ─
        // While we're hooking Java for diagnostics, also grab the cert chain
        // from the public KeyStore API. Snap *will* iterate getCertificateChain
        // after generateKey returns, and that's our cleanest visibility.
        try {
            var KeyStore_ = Java.use("java.security.KeyStore");
            var Base64_ = Java.use("android.util.Base64");
            KeyStore_.getCertificateChain.implementation = function (alias) {
                var ret = this.getCertificateChain(alias);
                try {
                    if (ret) {
                        for (var i = 0; i < ret.length; i++) {
                            var der = ret[i].getEncoded();
                            var b64 = Base64_.encodeToString(der, 0);
                            emit("KEYSTORE_CERT", "alias=" + alias +
                                 " idx=" + i + " len=" + der.length, {
                                idx: i,
                                total: ret.length,
                                lenBytes: der.length,
                                b64: String(b64)
                            });
                        }
                    } else {
                        emit("KEYSTORE_CERT_NULL", "alias=" + alias);
                    }
                } catch (e) {
                    emit("KEYSTORE_CERT_ERR", "alias=" + alias + " err=" + e);
                }
                return ret;
            };
            emitInit("KeyStore.getCertificateChain", true);
        } catch (e) { emitInit("KeyStore.getCertificateChain", false, e); }

        // ── H9: AndroidKeyStoreSpi.engineGetCertificateChain ─ lower-level ─
        try {
            var ASpi_ = Java.use("android.security.keystore.AndroidKeyStoreSpi");
            var Base64_2 = Java.use("android.util.Base64");
            ASpi_.engineGetCertificateChain.implementation = function (alias) {
                var ret = this.engineGetCertificateChain(alias);
                try {
                    if (ret) {
                        for (var i = 0; i < ret.length; i++) {
                            var der = ret[i].getEncoded();
                            var b64 = Base64_2.encodeToString(der, 0);
                            emit("ASPI_CERT", "alias=" + alias +
                                 " idx=" + i + " len=" + der.length, {
                                idx: i,
                                total: ret.length,
                                lenBytes: der.length,
                                b64: String(b64)
                            });
                        }
                    }
                } catch (e) {
                    emit("ASPI_CERT_ERR", "alias=" + alias + " err=" + e);
                }
                return ret;
            };
            emitInit("AndroidKeyStoreSpi.engineGetCertificateChain", true);
        } catch (e) {
            emitInit("AndroidKeyStoreSpi.engineGetCertificateChain", false, e);
        }

        emit("__INIT__", "tamperdetect layer ready — hooking nanoTime/stack/proc/exec/cert");
    });
})();
