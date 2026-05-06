#!/usr/bin/env python3
"""
body_diff_v2.py — focused 2nd-pass after v1 found no real discriminator.

Tactics:
- Don't auto-recurse into LEN fields that look like UUID strings (ASCII).
- Tabulate STRUCTURAL features only:
  * top-level f15 sub-field PRESENCE set per capture
  * f15 sub-field WIRE TYPE per capture
  * f15.f12.f1 (29-byte plaintext header) VALUE BYTE-BY-BYTE
  * f15.f12.f2 / f15.f12.f6 length classes
  * f15.f9 (impressionCountIds) packed varint LIST: full per-account ordered
  * f15.f16 cert chain (cert[1..3]) byte-identical check
  * any TOP-LEVEL field beyond f1..f8,f15,f16,f17 (i.e., is f9..f14, f18+ ever present?)
"""

import os, sys, json, hashlib
from pathlib import Path
from collections import defaultdict, Counter

CAPTURES_ROOT = Path("D:/Claude Projects/OmniTracker/captures")

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

WT_VARINT, WT_FIXED64, WT_LEN, WT_FIXED32 = 0, 1, 2, 5

def read_varint(buf, pos):
    n, shift = 0, 0
    while True:
        b = buf[pos]; pos += 1
        n |= (b & 0x7f) << shift
        if not (b & 0x80): break
        shift += 7
        if shift > 63: raise ValueError
    return n, pos

def parse_message(buf, start, end):
    out, pos = [], start
    while pos < end:
        try:
            tag, pos = read_varint(buf, pos)
        except Exception:
            break
        fn, wt = tag >> 3, tag & 7
        if wt == WT_VARINT:
            v, pos = read_varint(buf, pos)
            out.append((fn, wt, v, None))
        elif wt == WT_FIXED64:
            v = int.from_bytes(buf[pos:pos+8], 'little'); pos += 8
            out.append((fn, wt, v, None))
        elif wt == WT_LEN:
            ln, pos = read_varint(buf, pos)
            raw = bytes(buf[pos:pos+ln]); pos += ln
            out.append((fn, wt, raw, raw))
        elif wt == WT_FIXED32:
            v = int.from_bytes(buf[pos:pos+4], 'little'); pos += 4
            out.append((fn, wt, v, None))
        else:
            break
    return out

def find_signup_blob(capdir):
    blobs = CAPTURES_ROOT / capdir / "argos_blobs"
    cands = list(blobs.glob("*_signup_grpc_unary_10*B.bin"))
    if not cands:
        cands = sorted(blobs.glob("*.bin"), key=lambda p: p.stat().st_size, reverse=True)
        return cands[0] if cands else None
    return max(cands, key=lambda p: p.stat().st_size)

def hex_summary(b, maxlen=16):
    return b[:maxlen].hex() + ("…" if len(b) > maxlen else "")

def main():
    BANNED = {n for _, n, s in CAPTURES if s == "BANNED"}
    ALIVE  = {n for _, n, s in CAPTURES if s == "ALIVE"}

    blob_data = {}
    for capdir, num, status in CAPTURES:
        path = find_signup_blob(capdir)
        data = path.read_bytes()
        blob_data[num] = (data, status, capdir)

    # ----- top-level field shape per capture -----
    print("=" * 110)
    print("TOP-LEVEL FIELD MAP (field_num x wire_type, per capture)")
    print("=" * 110)
    top_shapes = {}
    for num, (data, status, _) in blob_data.items():
        items = parse_message(data, 0, len(data))
        # multiset (fn,wt) so we capture repeats
        shape = sorted([(fn, wt) for (fn, wt, _, _) in items])
        top_shapes[num] = (status, shape)
    # Are all 19 shapes IDENTICAL?
    shape_sigs = {num: hashlib.sha256(repr(s[1]).encode()).hexdigest()[:8] for num, s in top_shapes.items()}
    sig_groups = defaultdict(list)
    for num, sig in shape_sigs.items():
        sig_groups[sig].append((num, top_shapes[num][0]))
    print("Distinct top-level shape signatures:", len(sig_groups))
    for sig, members in sig_groups.items():
        print(f"  sig={sig}  members={[(n,s) for n,s in members]}")

    # ----- f15 sub-field shape (1 level only) -----
    print()
    print("=" * 110)
    print("f15 SUB-FIELD MAP (field_num x wire_type, depth=1 only, no recursion)")
    print("=" * 110)
    f15_shapes = {}
    for num, (data, status, _) in blob_data.items():
        items = parse_message(data, 0, len(data))
        f15_raw = None
        for fn, wt, v, raw in items:
            if fn == 15 and wt == WT_LEN:
                f15_raw = raw
                break
        if not f15_raw:
            continue
        sub = parse_message(f15_raw, 0, len(f15_raw))
        shape = sorted([(fn, wt) for (fn, wt, _, _) in sub])
        f15_shapes[num] = (status, shape, f15_raw, sub)
    sigs = {num: hashlib.sha256(repr(s[1]).encode()).hexdigest()[:8] for num, s in f15_shapes.items()}
    sig_groups = defaultdict(list)
    for num, sig in sigs.items():
        sig_groups[sig].append((num, f15_shapes[num][0]))
    print("Distinct f15 sub-field shape signatures:", len(sig_groups))
    for sig, members in sig_groups.items():
        # show one representative shape
        rep_num = members[0][0]
        print(f"  sig={sig}  members={[(n,s) for n,s in members]}")
        print(f"    shape: {f15_shapes[rep_num][1]}")

    # ----- f15.f12.f1 (29B header) byte comparison -----
    print()
    print("=" * 110)
    print("f15.f12.f1 (29-byte plaintext header) — full hex per capture")
    print("=" * 110)
    f12f1_data = {}
    for num, (status, _shape, f15_raw, sub) in f15_shapes.items():
        for fn, wt, v, raw in sub:
            if fn == 12 and wt == WT_LEN:
                f12_sub = parse_message(raw, 0, len(raw))
                for sfn, swt, sv, sraw in f12_sub:
                    if sfn == 1 and swt == WT_LEN:
                        f12f1_data[num] = (status, sraw)
                        break
                break
    print(f"{'#':<4} {'STAT':<7} HEX")
    for num in sorted(f12f1_data.keys()):
        status, raw = f12f1_data[num]
        print(f"#{num:<3} {status:<7} {raw.hex()}")
    # Distinct prefixes by first N bytes
    print()
    for prefix_len in [4, 8, 12, 16]:
        prefixes_by_status = defaultdict(set)
        for num, (status, raw) in f12f1_data.items():
            prefixes_by_status[status].add(raw[:prefix_len].hex())
        print(f"f12.f1 prefix-{prefix_len}B: BANNED unique={len(prefixes_by_status['BANNED'])}  ALIVE unique={len(prefixes_by_status['ALIVE'])}")
        if len(prefixes_by_status['BANNED']) == 1 and len(prefixes_by_status['ALIVE']) == 1:
            print(f"  *** STRICT DISCRIMINATOR at prefix-{prefix_len} ***")
            print(f"  BANNED prefix: {list(prefixes_by_status['BANNED'])[0]}")
            print(f"  ALIVE  prefix: {list(prefixes_by_status['ALIVE'])[0]}")
        if prefixes_by_status['BANNED'] & prefixes_by_status['ALIVE']:
            print(f"  overlap: {prefixes_by_status['BANNED'] & prefixes_by_status['ALIVE']}")

    # Position-by-position byte diff in f12.f1
    print()
    print("f12.f1 position-by-position byte-diff (which positions vary, which constant):")
    constant_positions = []
    variable_positions = []
    discriminator_positions = []
    samples = list(f12f1_data.values())
    if samples:
        L = len(samples[0][1])
        for i in range(L):
            bytes_at_i = {num: raw[i] for num, (status, raw) in f12f1_data.items()}
            ban_set = {bytes_at_i[n] for n in bytes_at_i if n in BANNED}
            ali_set = {bytes_at_i[n] for n in bytes_at_i if n in ALIVE}
            all_set = set(bytes_at_i.values())
            if len(all_set) == 1:
                constant_positions.append((i, list(all_set)[0]))
            elif ban_set.isdisjoint(ali_set) and len(ban_set) == 1 and len(ali_set) == 1:
                discriminator_positions.append((i, list(ban_set)[0], list(ali_set)[0]))
            else:
                variable_positions.append(i)
        print(f"  constant bytes ({len(constant_positions)}): " + " ".join(f"[{i}]={b:02x}" for i, b in constant_positions))
        print(f"  variable bytes ({len(variable_positions)}): {variable_positions}")
        if discriminator_positions:
            print(f"  *** discriminator bytes ({len(discriminator_positions)}):")
            for i, b, a in discriminator_positions:
                print(f"      [{i}]: BANNED={b:02x} ALIVE={a:02x}")
        else:
            print("  no per-byte discriminator")

    # ----- f15.f12.f2 / f15.f12.f6 length classes (already in v1, recap with stats) -----
    print()
    print("=" * 110)
    print("f15.f12.f2 + f15.f12.f6 length distribution (banned vs alive)")
    print("=" * 110)
    for tgt_fn, label in [(2, "f2"), (6, "f6")]:
        lens_by_status = defaultdict(list)
        for num, (status, _shape, f15_raw, sub) in f15_shapes.items():
            for fn, wt, v, raw in sub:
                if fn == 12 and wt == WT_LEN:
                    f12_sub = parse_message(raw, 0, len(raw))
                    for sfn, swt, sv, sraw in f12_sub:
                        if sfn == tgt_fn and swt == WT_LEN:
                            lens_by_status[status].append((num, len(sraw)))
                            break
                    break
        print(f"\nf15.f12.{label} lens:")
        for status in ["BANNED", "ALIVE"]:
            data = sorted(lens_by_status[status], key=lambda x: x[1])
            print(f"  {status}: {data}")
            ctr = Counter([l for _, l in data])
            print(f"  {status} length-histogram: {dict(ctr)}")

    # ----- f15.f9 packed varints: full ordered list -----
    print()
    print("=" * 110)
    print("f15.f9 packed-varint full ordered list (per capture, sha256 of CSV)")
    print("=" * 110)
    f9_lists = {}
    for num, (status, _shape, f15_raw, sub) in f15_shapes.items():
        for fn, wt, v, raw in sub:
            if fn == 9 and wt == WT_LEN:
                vals = []
                pos = 0
                while pos < len(raw):
                    try:
                        x, pos = read_varint(raw, pos); vals.append(x)
                    except Exception:
                        break
                f9_lists[num] = (status, vals)
                break
    # Group: any two captures with IDENTICAL list?
    list_to_cap = defaultdict(list)
    for num, (status, vals) in f9_lists.items():
        key = tuple(vals)
        list_to_cap[key].append((num, status))
    print(f"distinct f9 lists: {len(list_to_cap)}")
    for key, members in list_to_cap.items():
        if len(members) > 1:
            print(f"  shared by: {members}  len={len(key)}  sha={hashlib.sha256(','.join(map(str, key)).encode()).hexdigest()[:12]}")
    # length distribution
    len_ctr = Counter()
    for num, (status, vals) in f9_lists.items():
        len_ctr[(status, len(vals))] += 1
    print(f"f9 length×status histogram: {dict(len_ctr)}")
    # Examine positionally: are any positions shared by all banned but different in any alive?
    # First, find common positions
    min_len = min(len(v) for _, v in f9_lists.values())
    print(f"checking position-by-position for first {min_len} indices:")
    pos_disc = []
    for i in range(min_len):
        ban_vals = {f9_lists[n][1][i] for n in f9_lists if n in BANNED}
        ali_vals = {f9_lists[n][1][i] for n in f9_lists if n in ALIVE}
        if ban_vals.isdisjoint(ali_vals):
            pos_disc.append((i, ban_vals, ali_vals))
    if pos_disc:
        print(f"  position-discriminators: {len(pos_disc)}")
        for i, b, a in pos_disc[:5]:
            print(f"    [{i}]: BANNED={b}  ALIVE={a}")
    else:
        print("  no positional discriminator")

    # ----- f15.f16 cert chain hashes -----
    print()
    print("=" * 110)
    print("f15.f16 instances: count + per-instance f13 (cert chain) hashes")
    print("=" * 110)
    cert_data = defaultdict(dict)  # num -> {'count': int, 'cert_hashes': [sha12,...]}
    for num, (status, _shape, f15_raw, sub) in f15_shapes.items():
        f16s = [raw for fn, wt, v, raw in sub if fn == 16 and wt == WT_LEN]
        cert_data[num]['status'] = status
        cert_data[num]['f16_count'] = len(f16s)
        # f15.f16[1] should hold cert chain in f13 (per existing report)
        if len(f16s) >= 2:
            f16_1_sub = parse_message(f16s[1], 0, len(f16s[1]))
            certs = [raw for fn, wt, v, raw in f16_1_sub if fn == 13 and wt == WT_LEN]
            cert_data[num]['cert_count'] = len(certs)
            cert_data[num]['cert_hashes'] = [hashlib.sha256(c).hexdigest()[:12] for c in certs]
    print(f"{'#':<4} {'STAT':<7} {'f16ct':<6} {'certs':<6} cert_hashes(sha12)")
    for num in sorted(cert_data.keys()):
        d = cert_data[num]
        chs = ",".join(d.get('cert_hashes', []))
        print(f"#{num:<3} {d['status']:<7} {d.get('f16_count', '?'):<6} {d.get('cert_count', '?'):<6} {chs}")

    # ----- check for top-level fields beyond f1-f8, f15-f17 -----
    print()
    print("=" * 110)
    print("TOP-LEVEL field numbers present (looking for 'extra' fields)")
    print("=" * 110)
    EXPECTED = {1,2,3,4,5,6,7,8,15,16,17}
    for num, (status, shape) in top_shapes.items():
        present_fns = sorted({fn for fn, wt in shape})
        extras = [fn for fn in present_fns if fn not in EXPECTED]
        if extras:
            print(f"#{num} [{status}] extras: {extras}  full: {present_fns}")
    # All shapes identical?
    print(f"\nAll 19 captures have these top-level fields: {sorted({fn for sh in top_shapes.values() for fn, _ in sh[1]})}")

if __name__ == '__main__':
    main()
