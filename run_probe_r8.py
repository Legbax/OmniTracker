#!/usr/bin/env python3
"""One-shot runner for hooks/probe_r8_enum.js against Snap.

Connects to the stealth frida-server (TCP 127.0.0.1:8443), attaches to
Snap by name, loads the probe, waits for the R8_ENUM_REPORT message,
prints it, and exits. No reset / signup needed — Snap can be at any
screen.
"""

import json
import subprocess
import sys
import time
from pathlib import Path

import frida


def get_snap_pid() -> int:
    out = subprocess.run(
        ["adb", "shell", "pidof", "com.snapchat.android"],
        capture_output=True, text=True, timeout=5,
    )
    pid_str = out.stdout.strip().split("\n")[0].strip() if out.stdout else ""
    return int(pid_str) if pid_str else 0


def main():
    probe_path = Path(__file__).parent / "hooks" / "probe_r8_enum.js"
    if not probe_path.exists():
        print(f"[!] probe not found: {probe_path}")
        return 1

    pid = get_snap_pid()
    if pid <= 0:
        print("[!] Snap not running — `adb shell pidof com.snapchat.android` returned nothing")
        return 1

    print(f"[*] Connecting to 127.0.0.1:8443")
    device = frida.get_device_manager().add_remote_device("127.0.0.1:8443")
    print(f"[*] Attaching to com.snapchat.android (PID {pid})")
    session = device.attach(pid)

    output_holder = {"data": None, "partial": None, "errors": []}

    def on_message(msg, data):
        if msg.get("type") == "send":
            payload = msg.get("payload") or {}
            ptype = payload.get("type")
            if ptype == "R8_ENUM_REPORT":
                output_holder["data"] = payload.get("data")
                print(f"    [final] R8_ENUM_REPORT ({payload.get('value')})", flush=True)
            elif ptype == "R8_ENUM_PARTIAL":
                output_holder["partial"] = payload.get("data")
                print(f"    [partial] {payload.get('value')}", flush=True)
            elif ptype == "R8_ENUM_PROGRESS":
                pdata = payload.get("data") or {}
                stage = pdata.get("stage", "?")
                extra = {k: v for k, v in pdata.items() if k != "stage"}
                extra_str = " " + str(extra) if extra else ""
                print(f"    [progress] {stage}{extra_str}", flush=True)
            elif ptype == "error":
                output_holder["errors"].append(payload)
        elif msg.get("type") == "error":
            output_holder["errors"].append(msg)

    src = probe_path.read_text(encoding="utf-8")
    script = session.create_script(src)
    script.on("message", on_message)
    print(f"[*] Loading probe ({len(src)} bytes)")
    script.load()

    # Wait up to 180s for the report. Snap's classpath is large; the
    # read-method scan (step 3) iterates thousands of classes reflecting
    # methods, can easily run a minute on first invocation.
    deadline = time.time() + 180
    while time.time() < deadline and output_holder["data"] is None:
        time.sleep(0.5)

    if output_holder["errors"]:
        print("[!] Errors during probe:")
        for e in output_holder["errors"]:
            print(f"    {e}")

    if output_holder["data"] is None:
        if output_holder["partial"]:
            print("[!] Timed out before final report — saving last PARTIAL")
            data = output_holder["partial"]
        else:
            print("[!] Timed out waiting for R8_ENUM_REPORT and no PARTIAL captured")
            try:
                script.unload()
                session.detach()
            except Exception:
                pass
            return 2
    else:
        data = output_holder["data"]

    out_dir = Path(__file__).parent / "captures"
    out_dir.mkdir(exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")
    out_path = out_dir / f"r8_enum_{ts}.json"
    out_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    print(f"[+] Report written: {out_path}")
    print(f"    intercept_owners:           {len(data.get('intercept_owners', []))}")
    print(f"    proceed_owners:             {len(data.get('proceed_owners', []))}")
    print(f"    uploadprovider_candidates:  {len(data.get('uploadprovider_candidates', []))}")
    print(f"    keyword_classes:            {len(data.get('keyword_classes', []))}")
    print(f"    enum_class_count:           {data.get('enum_class_count', 0)}")
    if data.get("errors"):
        print(f"    probe-side errors:          {len(data['errors'])}")
        for e in data["errors"]:
            print(f"      - {e}")

    try:
        script.unload()
        session.detach()
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
