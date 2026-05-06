#!/usr/bin/env python3
"""
body_diff.py — compare protobuf signup bodies across 19 captures, look for
banned-vs-alive discriminators.

Usage:
    python tools/body_diff.py
"""

import os
import json
import hashlib
from pathlib import Path
from collections import defaultdict

CAPTURES_ROOT = Path("D:/Claude Projects/OmniTracker/captures")

# (capture_dir, account_num, status)
CAPTURES = [
    ("capybara_20260503_154339", 1,  "ALIVE"),
    ("capybara_20260503_200651", 2,  "BANNED"),
    ("capybara_20260503_201512", 3,  "BANNED"),
    ("capybara_20260503_202348", 4,  "BANNED"),
    ("capybara_20260503_203455", 5,  "BANNED"),
    ("capybara_20260503_204541", 6,  "BANNED"),
    ("capybara_20260503_205803", 7,  "BANNED"),
    ("capybara_20260503_210745", 8,  "BANNED"),
    ("capybara_20260503_211859", 9,  "ALIVE"),
    ("capybara_20260503_222300", 10, "ALIVE"),
    ("capybara_20260503_223206", 11, "ALIVE"),
    ("capybara_20260503_224204", 12, "ALIVE"),
    ("capybara_20260503_225051", 13, "ALIVE"),
    ("capybara_20260503_225912", 14, "ALIVE"),
    ("capybara_20260503_233008", 15, "ALIVE"),
    ("capybara_20260503_233732", 16, "ALIVE"),
    ("capybara_20260503_234837", 17, "ALIVE"),
    ("capybara_20260504_000034", 18, "ALIVE"),
    ("capybara_20260504_000928", 19, "ALIVE"),
]

# ---------------------------------------------------------------------------
# protobuf wire decoder (no .proto file)
# ---------------------------------------------------------------------------

WT_VARINT = 0
WT_FIXED64 = 1
WT_LEN = 2
WT_FIXED32 = 5

def read_varint(buf, pos):
    n = 0
    shift = 0
    while True:
        if pos >= len(buf):
            raise ValueError("truncated varint")
        b = buf[pos]
        pos += 1
        n |= (b & 0x7f) << shift
        if not (b & 0x80):
            break
        shift += 7
        if shift > 63:
            raise ValueError("varint too long")
    return n, pos

def parse_message(buf, start, end):
    """Return list of (field_num, wire_type, value, raw_bytes_or_None)."""
    out = []
    pos = start
    while pos < end:
        try:
            tag, pos = read_varint(buf, pos)
        except Exception:
            break
        fn = tag >> 3
        wt = tag & 7
        if wt == WT_VARINT:
            v, pos = read_varint(buf, pos)
            out.append((fn, wt, v, None))
        elif wt == WT_FIXED64:
            v = int.from_bytes(buf[pos:pos+8], 'little')
            pos += 8
            out.append((fn, wt, v, None))
        elif wt == WT_LEN:
            ln, pos = read_varint(buf, pos)
            raw = bytes(buf[pos:pos+ln])
            pos += ln
            out.append((fn, wt, raw, raw))
        elif wt == WT_FIXED32:
            v = int.from_bytes(buf[pos:pos+4], 'little')
            pos += 4
            out.append((fn, wt, v, None))
        else:
            raise ValueError(f"bad wire type {wt}")
    return out

def looks_like_message(raw):
    """heuristic: try to parse, if it consumes whole buffer with sensible field nums, ok."""
    if len(raw) == 0:
        return False
    try:
        items = parse_message(raw, 0, len(raw))
    except Exception:
        return False
    if not items:
        return False
    for (fn, wt, v, _) in items:
        if fn < 1 or fn > 1000000:
            return False
    return True

def descend(raw, depth=0, max_depth=5):
    """Return parsed tree."""
    items = parse_message(raw, 0, len(raw))
    out = []
    for (fn, wt, v, rawbytes) in items:
        node = {'fn': fn, 'wt': wt}
        if wt == WT_LEN:
            node['len'] = len(rawbytes)
            node['raw'] = rawbytes
            if depth < max_depth and looks_like_message(rawbytes):
                node['sub'] = descend(rawbytes, depth + 1, max_depth)
        else:
            node['val'] = v
        out.append(node)
    return out

# ---------------------------------------------------------------------------
# Locate signup blob
# ---------------------------------------------------------------------------

def find_signup_blob(capdir):
    blobs_dir = CAPTURES_ROOT / capdir / "argos_blobs"
    candidates = list(blobs_dir.glob("*_signup_grpc_unary_10*B.bin"))
    if not candidates:
        # fallback: largest blob
        candidates = sorted(blobs_dir.glob("*.bin"), key=lambda p: p.stat().st_size, reverse=True)
        if not candidates:
            return None
        return candidates[0]
    return max(candidates, key=lambda p: p.stat().st_size)

# ---------------------------------------------------------------------------
# Extract f15 sub-tree
# ---------------------------------------------------------------------------

def get_f15_subtree(blob_bytes):
    items = parse_message(blob_bytes, 0, len(blob_bytes))
    for (fn, wt, v, rawbytes) in items:
        if fn == 15 and wt == WT_LEN:
            return rawbytes, descend(rawbytes, 0, max_depth=5)
    return None, None

# ---------------------------------------------------------------------------
# Walk and tabulate
# ---------------------------------------------------------------------------

def walk_paths(tree, prefix=""):
    """Yield (path, node) for every node in tree."""
    # Group by field number to handle repeated fields (e.g., f16 has multiple)
    by_fn = defaultdict(list)
    for node in tree:
        by_fn[node['fn']].append(node)
    for fn, nodes in by_fn.items():
        for idx, node in enumerate(nodes):
            if len(nodes) > 1:
                path = f"{prefix}.f{fn}[{idx}]"
            else:
                path = f"{prefix}.f{fn}"
            yield path, node
            if 'sub' in node:
                yield from walk_paths(node['sub'], path)

def node_summary(node):
    """Compact representation for tabulation."""
    wt = node['wt']
    if wt == WT_VARINT or wt == WT_FIXED32 or wt == WT_FIXED64:
        return f"V={node['val']}"
    elif wt == WT_LEN:
        raw = node['raw']
        # if pure ascii
        try:
            s = raw.decode('utf-8')
            if all(32 <= ord(c) < 127 or c in '\n\r\t' for c in s) and len(s) < 80:
                return f'S="{s}"'
        except UnicodeDecodeError:
            pass
        sha = hashlib.sha256(raw).hexdigest()[:12]
        return f"L{len(raw)}#{sha}"
    return "?"

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    blob_data = {}
    f15_data = {}
    for capdir, num, status in CAPTURES:
        path = find_signup_blob(capdir)
        if not path:
            print(f"WARN: no blob for {capdir}")
            continue
        data = path.read_bytes()
        blob_data[num] = (data, status, capdir, path.name)
        raw15, tree15 = get_f15_subtree(data)
        if raw15 is None:
            print(f"WARN: no f15 in {capdir}")
            continue
        f15_data[num] = (raw15, tree15, status)

    # ----- Pass 1: enumerate every f15 sub-path across all captures -----
    all_paths = defaultdict(dict)  # path -> {acct_num: summary}
    path_kinds = {}  # path -> wt
    for num, (raw15, tree15, status) in f15_data.items():
        seen_paths = {}
        for path, node in walk_paths(tree15, "f15"):
            if path not in seen_paths:
                seen_paths[path] = node_summary(node)
                path_kinds[path] = node['wt']
            else:
                # repeated occurrence — append
                seen_paths[path] = seen_paths[path] + "|" + node_summary(node)
        for path, summary in seen_paths.items():
            all_paths[path][num] = summary

    # ----- Pass 2: classify each path as discriminator vs not -----
    BANNED_NUMS = {n for _, n, s in CAPTURES if s == "BANNED"}
    ALIVE_NUMS = {n for _, n, s in CAPTURES if s == "ALIVE"}

    print("=" * 100)
    print("PHASE 1: enumerate ALL f15 sub-paths across 19 captures")
    print("=" * 100)
    print(f"{'PATH':<35} {'PRESENT':<10} {'BANNED-vals':<35} {'ALIVE-vals':<35} VERDICT")
    print("-" * 130)

    discriminators = []
    for path in sorted(all_paths.keys()):
        present = all_paths[path]
        banned_vals = [v for n, v in present.items() if n in BANNED_NUMS]
        alive_vals = [v for n, v in present.items() if n in ALIVE_NUMS]
        nb_banned = len(set(banned_vals))
        nb_alive = len(set(alive_vals))
        # Cluster check: all banned share value X, all alive share Y, X != Y
        ban_unique = set(banned_vals)
        ali_unique = set(alive_vals)
        if not banned_vals or not alive_vals:
            verdict = "ABSENT-PARTIAL"
        elif ban_unique == ali_unique:
            verdict = "IDENTICAL"
        elif ban_unique.isdisjoint(ali_unique) and nb_banned == 1 and nb_alive == 1:
            verdict = "*** STRICT DISCRIMINATOR ***"
            discriminators.append((path, "STRICT", banned_vals[0], alive_vals[0]))
        elif ban_unique.isdisjoint(ali_unique):
            verdict = "*** PARTITIONED ***"
            discriminators.append((path, "PARTITIONED", sorted(ban_unique), sorted(ali_unique)))
        else:
            overlap = ban_unique & ali_unique
            if len(banned_vals) == len(set(banned_vals)) == 7 and len(alive_vals) == len(set(alive_vals)) == 12:
                verdict = "ALL-UNIQUE (per-account)"
            elif overlap and (nb_banned > 1 or nb_alive > 1):
                verdict = "MIXED"
            else:
                verdict = "?"

        # Compact display
        b_repr = ",".join(sorted(set(banned_vals)))[:33]
        a_repr = ",".join(sorted(set(alive_vals)))[:33]
        print(f"{path:<35} B={len(banned_vals)}/A={len(alive_vals):<3} {b_repr:<35} {a_repr:<35} {verdict}")

    # ----- Pass 3: f15.f9 varint-position analysis -----
    print()
    print("=" * 100)
    print("PHASE 2: f15.f9 packed-varint position-by-position diff (impressionCountIds)")
    print("=" * 100)
    f9_lists = {}
    for num, (raw15, tree15, status) in f15_data.items():
        for node in tree15:
            if node['fn'] == 9 and node['wt'] == WT_LEN:
                # packed varints
                vals = []
                pos = 0
                raw = node['raw']
                while pos < len(raw):
                    try:
                        v, pos = read_varint(raw, pos)
                        vals.append(v)
                    except Exception:
                        break
                f9_lists[num] = vals
                break

    if f9_lists:
        lens = {n: len(v) for n, v in f9_lists.items()}
        print(f"f15.f9 list lengths: {lens}")
        # Check ordering: are the lists same set, same order?
        sigs = {n: hashlib.sha256(",".join(map(str, v)).encode()).hexdigest()[:12] for n, v in f9_lists.items()}
        print("Per-account sha12 of (joined CSV in order):")
        for num in sorted(sigs.keys()):
            tag = "BAN" if num in BANNED_NUMS else "ALI"
            print(f"  #{num:<3} [{tag}] sha={sigs[num]}  len={lens[num]}")
        # Banned-set vs alive-set common?
        ban_sigs = {sigs[n] for n in sigs if n in BANNED_NUMS}
        ali_sigs = {sigs[n] for n in sigs if n in ALIVE_NUMS}
        print(f"banned distinct sha12 count: {len(ban_sigs)}")
        print(f"alive  distinct sha12 count: {len(ali_sigs)}")

    # ----- Pass 4: f15.f12 sub-tree (Argos) -----
    print()
    print("=" * 100)
    print("PHASE 3: f15.f12 (Argos) sub-fields f1 (29B header), f2 length, f6 length")
    print("=" * 100)
    print(f"{'#':<4} {'STATUS':<7} {'f12.f1 sha12':<16} {'f12.f1 len':<12} {'f12.f2 len':<12} {'f12.f6 len':<12}")
    f12_data = {}
    for num, (raw15, tree15, status) in sorted(f15_data.items()):
        for node in tree15:
            if node['fn'] == 12 and node['wt'] == WT_LEN and 'sub' in node:
                f1_raw = None
                f2_len = None
                f6_len = None
                for sub in node['sub']:
                    if sub['fn'] == 1 and sub['wt'] == WT_LEN:
                        f1_raw = sub['raw']
                    elif sub['fn'] == 2 and sub['wt'] == WT_LEN:
                        f2_len = len(sub['raw'])
                    elif sub['fn'] == 6 and sub['wt'] == WT_LEN:
                        f6_len = len(sub['raw'])
                f1_sha = hashlib.sha256(f1_raw).hexdigest()[:12] if f1_raw else "-"
                f1_len = len(f1_raw) if f1_raw else 0
                f12_data[num] = (status, f1_raw, f2_len, f6_len)
                print(f"#{num:<3} {status:<7} {f1_sha:<16} {f1_len:<12} {f2_len:<12} {f6_len:<12}")
                break

    # f12.f1 cluster?
    f12f1_by_status = defaultdict(set)
    for num, (status, f1_raw, _, _) in f12_data.items():
        if f1_raw:
            f12f1_by_status[status].add(hashlib.sha256(f1_raw).hexdigest()[:12])
    print(f"\nf15.f12.f1 unique sha12 in BANNED: {f12f1_by_status['BANNED']}")
    print(f"f15.f12.f1 unique sha12 in ALIVE : {f12f1_by_status['ALIVE']}")

    # f2/f6 length cluster
    f2_by_status = defaultdict(list)
    f6_by_status = defaultdict(list)
    for num, (status, _, f2_len, f6_len) in f12_data.items():
        f2_by_status[status].append(f2_len)
        f6_by_status[status].append(f6_len)
    print(f"\nf15.f12.f2 lengths BANNED: {sorted(f2_by_status['BANNED'])}")
    print(f"f15.f12.f2 lengths ALIVE : {sorted(f2_by_status['ALIVE'])}")
    print(f"f15.f12.f6 lengths BANNED: {sorted(f6_by_status['BANNED'])}")
    print(f"f15.f12.f6 lengths ALIVE : {sorted(f6_by_status['ALIVE'])}")

    # ----- Pass 5: enumerate top-level fields too (not just f15) -----
    print()
    print("=" * 100)
    print("PHASE 4: top-level fields (NOT inside f15)")
    print("=" * 100)
    top_paths = defaultdict(dict)
    for num, (data, status, capdir, fname) in blob_data.items():
        try:
            items = parse_message(data, 0, len(data))
            seen = {}
            by_fn = defaultdict(list)
            for (fn, wt, v, rawbytes) in items:
                node = {'fn': fn, 'wt': wt, 'val': v if wt != WT_LEN else rawbytes, 'raw': rawbytes if wt == WT_LEN else None}
                if wt == WT_LEN:
                    node['len'] = len(rawbytes)
                by_fn[fn].append(node)
            for fn, nodes in by_fn.items():
                if fn == 15:  # already handled
                    continue
                for idx, node in enumerate(nodes):
                    if len(nodes) > 1:
                        path = f"f{fn}[{idx}]"
                    else:
                        path = f"f{fn}"
                    seen[path] = node_summary(node)
            for path, summary in seen.items():
                top_paths[path][num] = summary
        except Exception as e:
            print(f"err {num}: {e}")

    print(f"{'PATH':<15} {'BANNED-vals':<35} {'ALIVE-vals':<35} VERDICT")
    print("-" * 110)
    for path in sorted(top_paths.keys()):
        present = top_paths[path]
        bv = [v for n, v in present.items() if n in BANNED_NUMS]
        av = [v for n, v in present.items() if n in ALIVE_NUMS]
        bs, as_ = set(bv), set(av)
        if not bv or not av:
            verdict = "PARTIAL"
        elif bs == as_:
            verdict = "IDENTICAL"
        elif bs.isdisjoint(as_):
            verdict = "*** DISCRIMINATOR ***"
        else:
            verdict = "MIXED/UNIQUE"
        print(f"{path:<15} {','.join(sorted(bs))[:33]:<35} {','.join(sorted(as_))[:33]:<35} {verdict}")

    # ----- summary -----
    print()
    print("=" * 100)
    print("SUMMARY OF DISCRIMINATORS FOUND IN f15")
    print("=" * 100)
    if not discriminators:
        print("NONE.  No f15 sub-field strictly partitions banned-vs-alive.")
    else:
        for path, kind, b, a in discriminators:
            print(f"{path}  [{kind}]  BANNED={b}  ALIVE={a}")

if __name__ == '__main__':
    main()
