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
    # Runtime template that builds the memfd name. Frida composes the visible
    # /memfd:frida-agent-64.so by substituting <arch> in this literal at run
    # time, so the *expanded* form ("frida-agent-64.so") never appears in the
    # binary as such — patching only the expanded form is a no-op for the leak
    # that Snapchat actually reads from /proc/self/maps. This template MUST be
    # patched too. Same applies to "libfrida-agent-raw.so" and the agent-
    # container env-var prefix.
    (b"frida-agent-<arch>.so", b"linux-agent-<arch>.so"),
    (b"libfrida-agent-raw.so", b"liblinux-agent-raw.so"),
    # NOTE: do NOT patch "frida-agent-container" — appears to be the prefix of
    # an internal env-var or config key consumed by the helper-spawn path. When
    # patched, the binder layer fails with "timeout was reached" during
    # script.load(), suggesting the agent's own RPC/helper coordination breaks.
    # The string is internal (not visible in /proc/self/maps) so leaving it is
    # not a detection vector.
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
    # ──────────────────────────────────────────────────────────────────────
    # DISABLED: QuickJS atom patch (b'\x0afrida' -> b'\x0alinux')
    # ──────────────────────────────────────────────────────────────────────
    # The atom `frida` in frida-java-bridge's QuickJS bytecode is the dex
    # file prefix (creating /data/data/<target>/cache/frida<rand>.dex which
    # Snap can detect). Patching the atom DOES rename the dex to linux*.dex
    # but it ALSO breaks something internal in frida-java-bridge that causes
    # ART to crash with SIGSEGV in art::FindOatMethodFor when Snap forks
    # Thread-4 for ferrite anti-tamper checks. Hypothesis: the atom is
    # interned and referenced from compiled JS bytecode for an internal
    # method/property name; renaming corrupts the lookup.
    #
    # Trade-off accepted: Snap will see frida<rand>.dex and may detect us
    # via the cache directory listing — but the process won't crash.
    # Mitigation path: have susfs hide /data/data/com.snapchat.android/cache
    # entries that match frida*.dex, OR find a non-atom way to override the
    # dex prefix from inside frida-java-bridge config.
    # (b'\x0afrida',            b'\x0alinux'),
    # Thread names exposed via /proc/PID/task/*/comm.
    (b"frida-helper-loop",    b"linux-helper-loop"),
    (b"frida-main-loop",      b"linux-main-loop"),
    (b"gum-js-loop",          b"lib-js-loop"),
    # NOTE: do NOT patch the bare "frida-agent" literal. It appears once in the
    # loader's error message but is also used internally as a lookup key inside
    # the agent runtime — replacing it breaks Frida's own JS host-session code
    # (queryIntentActivities returns null on enumerate_processes/applications).
    # The error-message leak is acceptable; it only fires on failed injection.
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
