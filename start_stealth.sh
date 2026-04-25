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
SRC_BINARY="bin/frida-server"
PATCHED_BINARY="bin/frida-stealth"

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

cmd_launch() {
    log "launching $DEVICE_PATH (TCP 127.0.0.1:$PORT)"
    adb shell "su -c 'nohup $DEVICE_PATH -l 127.0.0.1:$PORT -D >/data/local/tmp/.helper.log 2>&1 &'"
    sleep 2
    local pids
    pids=$(adb shell "su -c 'pgrep -f android-helper'" | tr -d '\r' || true)
    if [ -z "$pids" ]; then
        log "ERROR: helper failed to start. Last log:"
        adb shell "cat /data/local/tmp/.helper.log" || true
        exit 1
    fi
    log "running PIDs: $(echo "$pids" | tr '\n' ' ')"
    adb forward "tcp:$PORT" "tcp:$PORT" >/dev/null
    log "adb forward tcp:$PORT -> tcp:$PORT (host -> device)"
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
    *)       echo "usage: $0 [start|restart|stop|status]"; exit 2 ;;
esac
