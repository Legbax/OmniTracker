#!/usr/bin/env python3
"""
patch_frida.py — Minimal stealth patch for frida-server.

Replaces ONLY the runtime-visible strings that leak into a target process
when the agent is injected. Internal names (frida-buffer, frida-core, error
quark prefixes, JS module require() paths, the re.frida.* D-Bus interface
namespace) are left untouched so the wire protocol keeps working.

What we patch (every replacement is byte-for-byte the same length so all
ELF offsets and relocations stay valid):

    Memfd / .so file names visible in target's /proc/self/maps after
    injection:
        "frida-helper-32"   -> "linux-helper-32"
        "frida-helper-64"   -> "linux-helper-64"
        "frida-agent-32"    -> "linux-agent-32"
        "frida-agent-64"    -> "linux-agent-64"
        "frida-agent-arm"   -> "linux-agent-arm"
        "frida-agent-arm64" -> "linux-agent-arm64"

    Thread names visible in /proc/PID/task/*/comm after injection:
        "gum-js-loop"       -> "lib-js-loop"
        "frida-main-loop"   -> "linux-main-loop"
        "frida-helper-loop" -> "linux-helper-loop"

What we deliberately keep:
    re.frida.*              — D-Bus interface IDs (HostSession16, etc.)
    frida-java-bridge etc.  — JS modules loaded via require()
    frida-buffer / -core    — internal symbol names, never exposed
    Frida / FRIDA literals  — version banners, env-var names, error text

Usage:
    python patch_frida.py bin/frida-server bin/frida-stealth
"""
import os
import sys
from pathlib import Path

# Each tuple is (needle, replacement). Both must have the same byte length.
# Order matters: longest / most specific needles come first so a later, shorter
# needle does not see a substring that has already been replaced.
TARGETED_REPLACEMENTS: list[tuple[bytes, bytes]] = [
    # Agent / helper .so names with the .so suffix. These ARE visible to the
    # target process via /proc/self/maps after injection (e.g.
    # /memfd:frida-agent-64.so). They have to be replaced too — keeping them
    # was the difference that made Snapchat keep detecting frida.
    # IMPORTANT: order matters — the .so variants come first so the bare
    # 'frida-agent-64' substring inside 'frida-agent-64.so' is consumed by
    # this rule, not by the bare rule below.
    (b"frida-agent-arm64.so", b"linux-agent-arm64.so"),
    (b"frida-agent-arm.so",   b"linux-agent-arm.so"),
    (b"frida-agent-32.so",    b"linux-agent-32.so"),
    (b"frida-agent-64.so",    b"linux-agent-64.so"),
    # Bare memfd / agent .so names exposed in target's /proc/self/maps.
    (b"frida-agent-arm64",    b"linux-agent-arm64"),
    (b"frida-agent-arm",      b"linux-agent-arm"),
    (b"frida-agent-32",       b"linux-agent-32"),
    (b"frida-agent-64",       b"linux-agent-64"),
    (b"frida-helper-32",      b"linux-helper-32"),
    (b"frida-helper-64",      b"linux-helper-64"),
    # JS literal "frida" used by frida-java-bridge as the prefix of the
    # File.createTempFile call that materialises the bridge .dex inside the
    # target's cache dir. Without this, Snapchat sees
    #   /data/data/com.snapchat.android/cache/frida<random>.dex
    # which is a guaranteed detection. The same literal also appears as a
    # cosmetic "cause" string in art::ThreadList::SuspendAll calls — those
    # don't care about the value, so blanket replacement is safe.
    (b'"frida"',              b'"linux"'),
    # Thread names exposed via /proc/PID/task/*/comm.
    (b"frida-helper-loop",    b"linux-helper-loop"),
    (b"frida-main-loop",      b"linux-main-loop"),
    (b"gum-js-loop",          b"lib-js-loop"),
    # Abstract Unix socket prefix exposed in /proc/net/unix as @/frida-<uuid>.
    # The standalone null-terminated literal is concatenated with a UUID at
    # runtime to build the socket name (still created even in TCP listen mode).
    (b"frida-\x00",           b"linux-\x00"),
]


def patch_binary(src: Path, dst: Path) -> None:
    if not src.exists():
        print(f"[!] Source not found: {src}", file=sys.stderr)
        sys.exit(1)

    data = bytearray(src.read_bytes())
    original_size = len(data)
    print(f"[+] Loaded {src} ({original_size:,} bytes)")

    total = 0
    for needle, repl in TARGETED_REPLACEMENTS:
        if len(needle) != len(repl):
            print(f"[!] length mismatch: {needle!r} ({len(needle)}) "
                  f"vs {repl!r} ({len(repl)})", file=sys.stderr)
            sys.exit(1)
        n = len(needle)
        i = 0
        replaced = 0
        while True:
            i = data.find(needle, i)
            if i < 0:
                break
            data[i : i + n] = repl
            replaced += 1
            i += n
        if replaced:
            total += replaced
            print(f"    {needle.decode():>20} -> {repl.decode():<20} "
                  f"({replaced})")

    if len(data) != original_size:
        print(f"[!] Size changed unexpectedly: {original_size} -> {len(data)}",
              file=sys.stderr)
        sys.exit(1)

    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(bytes(data))
    try:
        os.chmod(dst, 0o755)
    except OSError:
        pass
    print(f"[+] Wrote {dst} ({len(data):,} bytes, {total} replacements)")

    # Sanity: confirm the targeted strings are gone.
    raw = bytes(data)
    leaks = [n.decode() for n, _ in TARGETED_REPLACEMENTS if n in raw]
    if leaks:
        print(f"[!] WARNING: residual {leaks!r} in patched binary",
              file=sys.stderr)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(2)
    patch_binary(Path(sys.argv[1]), Path(sys.argv[2]))
