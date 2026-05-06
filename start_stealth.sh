#!/usr/bin/env bash
# start_stealth.sh — Launch the patched frida-server in stealth mode.
#
# What this does:
#   1. Patches bin/frida-server (string-replaces every runtime-visible
#      "frida"/"gum-" identifier) into bin/frida-stealth — see patch_frida.py.
#   2. Pushes bin/frida-stealth to the device under an innocuous path
#      (/data/local/tmp/.android-helper).
#   3. Kills any previous instance.
#   4. Launches it as root, listening only on 127.0.0.1:<PORT> (no abstract
#      socket reachable from other apps; the reverse-host bridge is
#      `adb forward`).
#   5. Sets up `adb forward tcp:<PORT> tcp:<PORT>` so the host frida client
#      reaches it via 127.0.0.1:<PORT>.
#
# Why this evades Snapchat-style detection:
#   - Process name is ".android-helper", not "frida-server".
#   - TCP listen on 127.0.0.1 (not 0.0.0.0:27042 default).
#   - Memfd / agent .so / thread names that get injected into the target are
#     renamed from "frida-*" / "gum-js-loop" -> "linux-*" / "lib-js-loop".
#   - Abstract socket prefix "@/frida-<uuid>" -> "@/linux-<uuid>" in
#     /proc/net/unix.
#
# Usage:
#   ./start_stealth.sh              # patch + push + launch + forward
#   ./start_stealth.sh restart      # kill + relaunch (skip patch/push)
#   ./start_stealth.sh stop         # kill only
#   ./start_stealth.sh status       # show running PIDs and open port

set -euo pipefail

PORT="${OMNI_FRIDA_PORT:-8443}"
DEVICE_PATH="${OMNI_FRIDA_DEVICE_PATH:-/data/local/tmp/.android-helper}"
DEVICE_LOG="/data/local/tmp/.helper.log"
SRC_BINARY="bin/frida-server"
PATCHED_BINARY="bin/frida-stealth"
# SusFS hiding: 1=apply ksu_susfs rules to make the helper invisible to
# umounted (zygote-spawned) app processes. Set to 0 to skip if the device
# does not have KernelSU+susfs.
USE_SUSFS="${OMNI_USE_SUSFS:-1}"

# Required for adb on Git Bash (Windows) so /data paths aren't rewritten.
export MSYS2_ARG_CONV_EXCL='*'
export MSYS_NO_PATHCONV=1

cd "$(dirname "$0")"

log() { printf '[stealth] %s\n' "$*"; }

ensure_patched() {
    if [ ! -f "$SRC_BINARY" ]; then
        log "ERROR: $SRC_BINARY not found"; exit 1
    fi
    if [ "$PATCHED_BINARY" -ot "$SRC_BINARY" ] || [ ! -f "$PATCHED_BINARY" ] \
        || [ patch_frida.py -nt "$PATCHED_BINARY" ]; then
        log "patching $SRC_BINARY -> $PATCHED_BINARY"
        python patch_frida.py "$SRC_BINARY" "$PATCHED_BINARY"
    else
        log "patched binary up to date"
    fi
}

push_to_device() {
    log "pushing to $DEVICE_PATH"
    adb push "$PATCHED_BINARY" "$DEVICE_PATH" >/dev/null
    adb shell "su -c 'chmod 755 $DEVICE_PATH'"
}

cmd_stop() {
    log "killing any running stealth helper"
    # pkill -9 -f exits non-zero if no match — that's fine.
    adb shell "su -c 'pkill -9 -f android-helper'" 2>/dev/null || true
    adb forward --remove "tcp:$PORT" 2>/dev/null || true
}

# Apply susfs hiding rules so app processes (uid >= 10000, umounted) cannot
# stat / readdir / open the helper binary or its log. Idempotent — repeated
# calls are no-ops on most ksu_susfs versions, errors are non-fatal.
#
# Why each rule:
#   add_sus_path        — hide from stat/open/access/readdir lookups now
#   add_sus_path_loop   — re-apply on every zygote spawn (Snap is spawned
#                         AFTER our setup; without the loop variant the
#                         child process inherits a non-flagged path)
#   add_sus_kstat       — return ENOENT-equivalent stat (so File.exists()
#                         in Java returns false)
#   hide_sus_mnts_for_non_su_procs 1
#                       — stop /proc/self/[mounts|mountinfo] from leaking
#                         KSU/susfs/zygisk mount points to apps
cmd_susfs() {
    if [ "$USE_SUSFS" != "1" ]; then
        log "susfs disabled (OMNI_USE_SUSFS=0) — skipping kernel-level hiding"
        return 0
    fi
    # Detect ksu_susfs presence; bail gracefully if missing.
    if ! adb shell "su -c 'command -v ksu_susfs >/dev/null 2>&1 && echo OK'" 2>/dev/null \
            | grep -q "OK"; then
        log "ksu_susfs not found on device — skipping susfs hiding"
        log "  (install KernelSU + susfs kernel patch to enable, or set OMNI_USE_SUSFS=0 to silence)"
        return 0
    fi
    # CRITICAL: ksu_susfs add_sus_path_loop is NOT idempotent — its own help
    # says "does not check if the path is existed or not". Calling it on every
    # `start_stealth.sh restart` enqueues another rule for the same path, and
    # on every zygote spawn susfs replays ALL of them. After N restarts the
    # per-syscall overhead grows linearly until ferrite-launcher's anti-tamper
    # timing check fires SIGSEGV in Snap's Thread-4. We use a marker file in
    # /data/local/tmp (wiped on reboot, kernel state also reset on reboot, so
    # this stays in sync with what the kernel has).
    local marker="/data/local/tmp/.susfs_omni_applied"
    if adb shell "su -c '[ -f $marker ] && echo YES'" 2>/dev/null | grep -q YES; then
        log "susfs rules already applied this boot (marker $marker present) — skipping"
        return 0
    fi
    log "applying susfs hiding rules to $DEVICE_PATH (one-shot per boot)"
    for cmd in \
        "add_sus_path $DEVICE_PATH" \
        "add_sus_path_loop $DEVICE_PATH" \
        "add_sus_kstat $DEVICE_PATH" \
        "add_sus_path $DEVICE_LOG" \
        "add_sus_kstat $DEVICE_LOG" \
        "hide_sus_mnts_for_non_su_procs 1" ; do
        out=$(adb shell "su -c 'ksu_susfs $cmd 2>&1'" 2>&1 | tr -d '\r')
        if [ -n "$out" ] && ! echo "$out" | grep -qiE "already|success|enabled|^\s*$"; then
            log "  ksu_susfs $cmd -> $out"
        else
            log "  ksu_susfs $cmd -> ok"
        fi
    done
    adb shell "su -c 'touch $marker'" 2>/dev/null
    log "susfs rules applied (marker $marker created — won't re-apply until reboot)"
}

cmd_susfs_status() {
    if [ "$USE_SUSFS" != "1" ]; then
        log "susfs disabled (OMNI_USE_SUSFS=0)"
        return 0
    fi
    if ! adb shell "su -c 'command -v ksu_susfs >/dev/null 2>&1 && echo OK'" 2>/dev/null \
            | grep -q "OK"; then
        log "ksu_susfs not present"
        return 0
    fi
    log "susfs version / features:"
    adb shell "su -c 'ksu_susfs show version 2>&1; ksu_susfs show enabled_features 2>&1'" 2>&1 \
        | sed 's/^/  /'
}

cmd_launch() {
    log "launching $DEVICE_PATH (TCP 127.0.0.1:$PORT)"
    adb shell "su -c 'nohup $DEVICE_PATH -l 127.0.0.1:$PORT -D >$DEVICE_LOG 2>&1 &'"
    sleep 2
    local pids
    pids=$(adb shell "su -c 'pgrep -f android-helper'" | tr -d '\r' || true)
    if [ -z "$pids" ]; then
        log "ERROR: helper failed to start. Last log:"
        adb shell "cat $DEVICE_LOG" || true
        exit 1
    fi
    log "running PIDs: $(echo "$pids" | tr '\n' ' ')"
    adb forward "tcp:$PORT" "tcp:$PORT" >/dev/null
    log "adb forward tcp:$PORT -> tcp:$PORT (host -> device)"
    # Apply susfs rules AFTER the helper is up but BEFORE the operator launches
    # the target app. Snap (or any uid>=10000 umounted process) spawned after
    # this point will see the helper as if it doesn't exist.
    cmd_susfs
    log "client: frida -H 127.0.0.1:$PORT  /  python: add_remote_device('127.0.0.1:$PORT')"
}

cmd_status() {
    log "device PIDs:"
    adb shell "su -c 'pgrep -af android-helper'" 2>/dev/null || log "  (none)"
    log "host adb forward:"
    adb forward --list | grep ":$PORT" || log "  (no forward for $PORT)"
    log "abstract sockets ('frida' should NOT appear):"
    adb shell "su -c 'cat /proc/net/unix | grep frida'" 2>/dev/null \
        || log "  none -> stealth OK"
    cmd_susfs_status
}

case "${1:-start}" in
    start)
        ensure_patched
        cmd_stop
        push_to_device
        cmd_launch
        cmd_status
        ;;
    restart)
        cmd_stop
        cmd_launch
        cmd_status
        ;;
    stop)    cmd_stop ;;
    status)  cmd_status ;;
    susfs)   cmd_susfs ;;            # apply susfs rules ad-hoc (no helper restart)
    *)       echo "usage: $0 [start|restart|stop|status|susfs]"; exit 2 ;;
esac
