"""
argos_header_diff.py

Forensic byte-level analysis of the 29-byte plaintext header at f15.f12.f1
across 19 Snapchat signup captures.

Tests whether the header contains:
  1. A banned-vs-alive discriminator
  2. Device-derived fingerprint material
"""

import os
import sys
import glob
from pathlib import Path

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


# ---------- protobuf wire-format primitives ----------

def read_varint(buf, off):
    """Returns (value, new_offset)."""
    val = 0
    shift = 0
    while True:
        if off >= len(buf):
            raise ValueError("varint truncated")
        b = buf[off]
        off += 1
        val |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            return val, off
        shift += 7
        if shift > 63:
            raise ValueError("varint too long")


def read_tag(buf, off):
    """Returns (field_number, wire_type, new_offset)."""
    val, off = read_varint(buf, off)
    return (val >> 3), (val & 0x7), off


def find_field(buf, target_field, start=0, end=None):
    """
    Walks top-level fields in buf[start:end], returns (payload_bytes, abs_offset_of_payload)
    for the first field whose field_number == target_field.
    """
    if end is None:
        end = len(buf)
    off = start
    while off < end:
        try:
            fn, wt, off = read_tag(buf, off)
        except Exception:
            return None
        if wt == 0:           # varint
            _, off = read_varint(buf, off)
        elif wt == 1:         # 64-bit
            off += 8
        elif wt == 2:         # length-delimited
            ln, off = read_varint(buf, off)
            payload_off = off
            if fn == target_field:
                return buf[off:off + ln], payload_off
            off += ln
        elif wt == 5:         # 32-bit
            off += 4
        elif wt == 3 or wt == 4:  # group start/end (legacy)
            pass
        else:
            return None
    return None


# ---------- extraction ----------

def find_signup_blob(capture_dir):
    """Returns path to the largest *.bin in argos_blobs/."""
    blobs_dir = capture_dir / "argos_blobs"
    candidates = list(blobs_dir.glob("*_signup_grpc_unary_*.bin"))
    if not candidates:
        return None
    return max(candidates, key=lambda p: p.stat().st_size)


def extract_header(blob_path):
    """Returns (header29_bytes, f12_payload, blob_size, f12_payload_size)."""
    data = blob_path.read_bytes()

    f15 = find_field(data, 15)
    if f15 is None:
        raise RuntimeError(f"f15 not found in {blob_path.name}")
    f15_bytes, _ = f15

    f12 = find_field(f15_bytes, 12)
    if f12 is None:
        raise RuntimeError(f"f15.f12 not found in {blob_path.name}")
    f12_bytes, _ = f12

    f1 = find_field(f12_bytes, 1)
    if f1 is None:
        raise RuntimeError(f"f15.f12.f1 not found in {blob_path.name}")
    f1_bytes, _ = f1

    if len(f1_bytes) < 29:
        raise RuntimeError(f"f15.f12.f1 is only {len(f1_bytes)}B in {blob_path.name}")
    return f1_bytes[:29], f12_bytes, len(data), len(f12_bytes)


def extract_f12_subfield_lens_and_prefixes(f12_bytes):
    """Returns dict { field_num : (length, first4_bytes_hex) } for f1, f2, f6."""
    out = {}
    for fn in (1, 2, 6):
        r = find_field(f12_bytes, fn)
        if r is None:
            continue
        payload, _ = r
        out[fn] = (len(payload), payload[:4].hex())
    return out


# ---------- analysis ----------

def main():
    print("=" * 100)
    print("ARGOS f15.f12.f1 — 29-byte plaintext header — forensic analysis (19 captures)")
    print("=" * 100)

    rows = []  # list of (acct, status, header29_bytes, f12_lens_dict)
    for cap_dir_name, acct, status in CAPTURES:
        cap_dir = CAPTURES_ROOT / cap_dir_name
        blob = find_signup_blob(cap_dir)
        if blob is None:
            print(f"  #{acct:02d} {status:6s}  NO SIGNUP BLOB in {cap_dir_name}")
            continue
        try:
            header, f12_bytes, blob_size, f12_size = extract_header(blob)
        except Exception as e:
            print(f"  #{acct:02d} {status:6s}  EXTRACT FAILED: {e}")
            continue
        sublens = extract_f12_subfield_lens_and_prefixes(f12_bytes)
        rows.append((acct, status, header, sublens, blob_size, f12_size, blob.name))

    # ------ Header byte-by-byte table ------
    print()
    print("BYTE-BY-BYTE TABLE (29 columns x 19 rows)")
    print()
    hdr = "  # St  | " + " ".join(f"{i:02d}" for i in range(29))
    print(hdr)
    print("  " + "-" * (len(hdr) - 2))
    for acct, status, header, _, _, _, _ in rows:
        st_short = "B" if status == "BANNED" else "A"
        print(f" {acct:02d} {st_short:1s}   | " + " ".join(f"{b:02x}" for b in header))

    # ------ Per-position verdict ------
    print()
    print("PER-POSITION ANALYSIS")
    print()
    print("pos  | values across 19          | banned-set            | alive-set            | verdict")
    print("-" * 120)

    banned_hdrs = [h for _, s, h, _, _, _, _ in rows if s == "BANNED"]
    alive_hdrs  = [h for _, s, h, _, _, _, _ in rows if s == "ALIVE"]

    discriminator_positions = []
    constant_positions = []
    varying_positions = []

    for pos in range(29):
        all_vals     = [h[pos] for _, _, h, _, _, _, _ in rows]
        banned_vals  = [h[pos] for h in banned_hdrs]
        alive_vals   = [h[pos] for h in alive_hdrs]

        unique_all     = sorted(set(all_vals))
        unique_banned  = sorted(set(banned_vals))
        unique_alive   = sorted(set(alive_vals))

        if len(unique_all) == 1:
            verdict = "CONSTANT"
            constant_positions.append((pos, unique_all[0]))
        else:
            # check for discriminator: each set has its own constant value, and they differ
            if (len(unique_banned) == 1 and len(unique_alive) == 1
                    and unique_banned[0] != unique_alive[0]):
                verdict = "DISCRIMINATES-BANNED"
                discriminator_positions.append(
                    (pos, unique_banned[0], unique_alive[0])
                )
            else:
                # partial discriminator: sets are disjoint but neither is single-valued
                set_b = set(banned_vals)
                set_a = set(alive_vals)
                if set_b.isdisjoint(set_a):
                    verdict = "DISCRIMINATES-DISJOINT"
                    discriminator_positions.append((pos, sorted(set_b), sorted(set_a)))
                else:
                    verdict = "VARIES-MIXED"
                    varying_positions.append(pos)

        def fmt(vals):
            uniq = sorted(set(vals))
            if len(uniq) <= 4:
                return ",".join(f"{v:02x}" for v in uniq)
            return f"{len(uniq)} unique"

        print(f" {pos:02d}  | {fmt(all_vals):24s}  | {fmt(banned_vals):20s}  | {fmt(alive_vals):20s}  | {verdict}")

    # ------ Magic constant search ------
    print()
    print("MAGIC CONSTANT 0xa0d69180 SEARCH (4 bytes, all endiannesses)")
    print()
    targets = {
        "BE a0 d6 91 80": bytes([0xa0, 0xd6, 0x91, 0x80]),
        "LE 80 91 d6 a0": bytes([0x80, 0x91, 0xd6, 0xa0]),
    }
    for name, needle in targets.items():
        positions = set()
        for _, _, h, _, _, _, _ in rows:
            for i in range(0, 30 - len(needle)):
                if bytes(h[i:i + len(needle)]) == needle:
                    positions.add(i)
        if positions:
            print(f"  {name}  found at offsets {sorted(positions)} (in all rows where present)")
        else:
            print(f"  {name}  NOT FOUND in any header")

    # ------ Summary ------
    print()
    print("SUMMARY")
    print(f"  CONSTANT positions ({len(constant_positions)}): " +
          ", ".join(f"{p}={v:02x}" for p, v in constant_positions))
    print(f"  DISCRIMINATOR positions ({len(discriminator_positions)}): " +
          ", ".join(str(p[0]) for p in discriminator_positions))
    print(f"  VARYING-MIXED positions ({len(varying_positions)}): " +
          ", ".join(str(p) for p in varying_positions))

    if discriminator_positions:
        print()
        print("DISCRIMINATOR DETAIL")
        for d in discriminator_positions:
            if len(d) == 3 and isinstance(d[1], int):
                pos, bv, av = d
                print(f"  pos {pos:02d}: BANNED={bv:02x}  ALIVE={av:02x}")
            else:
                pos, bset, aset = d
                print(f"  pos {pos:02d}: BANNED={[f'{x:02x}' for x in bset]}  ALIVE={[f'{x:02x}' for x in aset]}")

    # ------ f12.f2 / f12.f6 length & prefix analysis ------
    print()
    print("f12 SUB-FIELD LENGTHS AND PREFIXES (BONUS)")
    print()
    print("  # St  | f1.len f1.prefix      | f2.len f2.prefix      | f6.len f6.prefix")
    print("  " + "-" * 96)
    for acct, status, _, sublens, _, _, _ in rows:
        st = "B" if status == "BANNED" else "A"
        line = f" {acct:02d} {st:1s}   |"
        for fn in (1, 2, 6):
            if fn in sublens:
                ln, pfx = sublens[fn]
                line += f" {ln:5d} {pfx}              |"
            else:
                line += "       --                |"
        print(line)

    # banned-vs-alive correlation in f2/f6 lengths
    print()
    for fn in (2, 6):
        b_lens = sorted(set(r[3][fn][0] for r in rows if fn in r[3] and r[1] == "BANNED"))
        a_lens = sorted(set(r[3][fn][0] for r in rows if fn in r[3] and r[1] == "ALIVE"))
        overlap = set(b_lens) & set(a_lens)
        verdict = "DISJOINT (banned-vs-alive correlated!)" if not overlap else "OVERLAPPING (no correlation)"
        print(f"  f12.f{fn} lengths:  banned={b_lens}  alive={a_lens}  -> {verdict}")

        b_pfx = sorted(set(r[3][fn][1] for r in rows if fn in r[3] and r[1] == "BANNED"))
        a_pfx = sorted(set(r[3][fn][1] for r in rows if fn in r[3] and r[1] == "ALIVE"))
        ov = set(b_pfx) & set(a_pfx)
        v = "DISJOINT" if not ov else "OVERLAPPING"
        print(f"  f12.f{fn} 1st-4B:  banned-uniq={len(b_pfx)} alive-uniq={len(a_pfx)} -> {v}")

    # ------ Hex view of headers grouped by status ------
    print()
    print("HEADERS GROUPED BY STATUS (visual diff)")
    print()
    print("  BANNED (7):")
    for acct, status, h, _, _, _, _ in rows:
        if status == "BANNED":
            print(f"    #{acct:02d}  " + h.hex(' '))
    print()
    print("  ALIVE  (12):")
    for acct, status, h, _, _, _, _ in rows:
        if status == "ALIVE":
            print(f"    #{acct:02d}  " + h.hex(' '))


if __name__ == "__main__":
    main()
