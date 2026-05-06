#!/usr/bin/env python3
"""
extract_all.py — pull Snap SQLite databases from a connected device and
dump the consolidated state to a text file.

USAGE:
  python extract_all.py             # pull from device + dump (default)
  python extract_all.py --no-pull   # skip pull, dump existing local copies
  python extract_all.py --pull-only # pull only, no dump

WAL handling:
  Snap uses SQLite in WAL (write-ahead-log) mode while running. The .db file
  alone is the last checkpoint; recent writes live in .db-wal until SQLite
  flushes. To capture LIVE state without forcing a Snap restart, this script
  pulls all 3 sidecar files (.db, .db-wal, .db-shm) when present. SQLite then
  consolidates them automatically when we open the connection.

Known SSAID validation marker (CLAUDE.md inv #End-to-end):
  After 2FA setup, Snap stores `IDENTITY~TFA_VERIFIED_DEVICES` in core.db
  Preferences with id == Long.parseLong(spoofed_ssaid_hex, 16) cast to
  signed int64. The dump highlights this row when present.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent
OUT_PATH = BASE / 'snapchat_full_dump.txt'

SNAP_PKG = 'com.snapchat.android'
DEV_DB_DIR = f'/data/data/{SNAP_PKG}/databases'
DEV_TMP = '/data/local/tmp'

# Each entry: (device basename, host basename, label).
# host basename is what extract_all writes to disk; label is what appears in the dump.
DBS = [
    ('main.db',                         'snap_main.db',              'main.db'),
    ('core.db',                         'snap_core.db',              'core.db'),
    ('simple_db_helper.db',             'snap_simple_db_helper.db',  'simple_db_helper.db'),
    ('valdi_in_app_warning.db',         'valdi_in_app_warning.db',   'valdi/in_app_warning.db'),
    ('tiv.db',                          'tiv.db',                    'tiv.db'),
    ('tivV2.db',                        'tivV2.db',                  'tivV2.db'),
]

# Sidecars SQLite uses while a writer is open. Pulling all 3 captures live
# state without forcing the writer to checkpoint.
SIDECAR_SUFFIXES = ('', '-wal', '-shm')


def adb(*args: str, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    """Run an adb command. MSYS_NO_PATHCONV=1 prevents Git Bash on Windows
    from mangling /data/... paths into C:/Program Files/Git/data/..."""
    env = os.environ.copy()
    env['MSYS_NO_PATHCONV'] = '1'
    env['MSYS2_ARG_CONV_EXCL'] = '*'
    return subprocess.run(['adb', *args], text=True, capture_output=True,
                          timeout=timeout, env=env)


def adb_su(cmd: str, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    return adb('shell', 'su', '-c', cmd, timeout=timeout)


def pull_dbs(verbose: bool = True) -> int:
    """Copy DB files (and their WAL/SHM sidecars) from /data/data/<pkg>/databases
    to /data/local/tmp (root-owned source needs `su` to read), then `adb pull`
    to the host. Returns count of successfully pulled main DBs."""
    if verbose:
        print('[extract_all] Pulling Snap dbs from device...')

    # Stage 1: copy source → /data/local/tmp via root, set readable perms.
    cp_lines = []
    chmod_targets = []
    for dev_name, host_name, _ in DBS:
        for sfx in SIDECAR_SUFFIXES:
            src = f'{DEV_DB_DIR}/{dev_name}{sfx}'
            dst = f'{DEV_TMP}/{host_name}{sfx}'
            cp_lines.append(f"cp {src} {dst} 2>/dev/null")
            chmod_targets.append(dst)
    cp_cmd = '; '.join(cp_lines) + f'; chmod 644 {" ".join(chmod_targets)} 2>/dev/null; true'
    res = adb_su(cp_cmd, timeout=60)
    if res.returncode != 0 and verbose:
        print(f'[extract_all] WARN copy stage stderr: {res.stderr.strip()}')

    # Stage 2: pull each file from /data/local/tmp to host. Missing files are
    # silently skipped (e.g. if .db-wal does not exist because Snap is closed).
    main_pulled = 0
    for dev_name, host_name, _ in DBS:
        for sfx in SIDECAR_SUFFIXES:
            dst = f'{DEV_TMP}/{host_name}{sfx}'
            local = BASE / f'{host_name}{sfx}'
            res = adb('pull', dst, str(local), timeout=30)
            if res.returncode == 0 and local.exists() and local.stat().st_size > 0:
                if sfx == '' and verbose:
                    print(f'  [OK]   {host_name} ({local.stat().st_size:,} bytes)')
                if sfx == '':
                    main_pulled += 1
            else:
                # Sidecar missing is normal; main DB missing is worth flagging.
                if sfx == '' and verbose:
                    print(f'  [MISS] {host_name} (not present on device)')
                # Clean up empty/failed local file so dump doesn't try to open it.
                if local.exists() and local.stat().st_size == 0:
                    try: local.unlink()
                    except OSError: pass

    if verbose:
        print(f'[extract_all] Pulled {main_pulled}/{len(DBS)} main dbs')
    return main_pulled


def dump_db(db_path: Path, db_label: str, f) -> None:
    f.write(f'\n\n{"="*60}\n{db_label}\n{"="*60}\n')
    try:
        # SQLite auto-applies WAL on open as long as the .db-wal sidecar
        # is present alongside the .db file. No special pragma needed.
        con = sqlite3.connect(str(db_path))
        cur = con.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        tables = [r[0] for r in cur.fetchall()]
        for tbl in tables:
            cur.execute(f'SELECT COUNT(*) FROM "{tbl}"')
            count = cur.fetchone()[0]
            if count == 0:
                continue
            cur.execute(f'PRAGMA table_info("{tbl}")')
            cols = [r[1] for r in cur.fetchall()]
            f.write(f'\n--- {tbl} ({count} rows) ---\n')
            cur.execute(f'SELECT * FROM "{tbl}"')
            for row in cur.fetchall():
                d = dict(zip(cols, row))
                clean = {}
                for k, v in d.items():
                    if isinstance(v, bytes):
                        try:
                            decoded = v.decode('utf-8', errors='replace')
                            clean[k] = decoded[:400]
                        except Exception:
                            clean[k] = f'<bytes:{len(v)}>'
                    elif isinstance(v, str) and len(v) > 600:
                        clean[k] = v[:600] + '...[truncated]'
                    else:
                        clean[k] = v
                f.write(f'  {json.dumps(clean, ensure_ascii=False)}\n')
        con.close()
    except Exception as e:
        f.write(f'  ERROR: {e}\n')


def highlight_ssaid_marker() -> dict | None:
    """Look for IDENTITY~TFA_VERIFIED_DEVICES in core.db (incl. WAL).
    If present, decode the embedded id back to hex and return a dict
    suitable for printing — this is the end-to-end SSAID validation marker
    per CLAUDE.md inv. Returns None if not present (e.g. account without 2FA)."""
    core_db = BASE / 'snap_core.db'
    if not core_db.exists():
        return None
    try:
        con = sqlite3.connect(str(core_db))
        cur = con.cursor()
        cur.execute("SELECT key, stringValue FROM Preferences "
                    "WHERE key = 'IDENTITY~TFA_VERIFIED_DEVICES'")
        row = cur.fetchone()
        con.close()
        if not row or not row[1]:
            return None
        data = json.loads(row[1])
        if not data or not isinstance(data, list):
            return None
        first = data[0]
        signed_id = int(first.get('id', 0))
        # Convert signed int64 back to unsigned then hex (mirror Java
        # Long.parseLong(hex,16) cast to int64).
        unsigned = signed_id + (1 << 64) if signed_id < 0 else signed_id
        ssaid_hex = f'{unsigned:016x}'
        return {
            'tfa_id_signed': signed_id,
            'tfa_id_unsigned': unsigned,
            'ssaid_hex_decoded': ssaid_hex,
            'device_name': first.get('name'),
            'last_login': first.get('last_login'),
        }
    except Exception as e:
        return {'error': str(e)}


def write_dump() -> tuple[int, int]:
    """Run dump pass over local DB files and write to OUT_PATH.
    Returns (line_count, byte_size)."""
    with open(OUT_PATH, 'w', encoding='utf-8') as f:
        # Header with SSAID marker highlight if present.
        marker = highlight_ssaid_marker()
        if marker and 'tfa_id_signed' in marker:
            f.write('=== SSAID end-to-end validation marker (CLAUDE.md inv) ===\n')
            f.write(json.dumps(marker, ensure_ascii=False, indent=2) + '\n')
            f.write('=' * 60 + '\n')

        for _, host_name, label in DBS:
            path = BASE / host_name
            if path.exists() and path.stat().st_size > 0:
                dump_db(path, label, f)
            else:
                f.write(f'\n[MISSING] {host_name}\n')

    size = OUT_PATH.stat().st_size
    with open(OUT_PATH, encoding='utf-8') as f:
        lines = sum(1 for _ in f)
    return lines, size


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--no-pull', action='store_true',
                        help='Skip pulling from device; dump existing local files only.')
    parser.add_argument('--pull-only', action='store_true',
                        help='Pull from device but skip dumping.')
    parser.add_argument('--quiet', '-q', action='store_true',
                        help='Suppress per-file pull lines.')
    args = parser.parse_args()

    if not args.no_pull:
        pulled = pull_dbs(verbose=not args.quiet)
        if pulled == 0:
            print('[extract_all] WARN: no dbs pulled from device. Is adb attached + Snap installed?',
                  file=sys.stderr)

    if args.pull_only:
        return 0

    lines, size = write_dump()
    print(f'Done: {lines} lines, {size:,} bytes')
    print(f'File: {OUT_PATH}')

    marker = highlight_ssaid_marker()
    if marker and 'tfa_id_signed' in marker:
        print(f'\n[SSAID marker] device="{marker["device_name"]}" '
              f'id_signed={marker["tfa_id_signed"]} '
              f'ssaid_hex={marker["ssaid_hex_decoded"]}')
    elif marker is None:
        print('[SSAID marker] not present (account without 2FA OR core.db missing)')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
