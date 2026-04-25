import sqlite3, json, os, sys

base = 'D:/Claude Projects/OmniTracker'
out_path = f'{base}/snapchat_full_dump.txt'

def dump_db(db_path, db_label, f):
    f.write(f'\n\n{"="*60}\n{db_label}\n{"="*60}\n')
    try:
        con = sqlite3.connect(db_path)
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
                        except:
                            clean[k] = f'<bytes:{len(v)}>'
                    elif isinstance(v, str) and len(v) > 600:
                        clean[k] = v[:600] + '...[truncated]'
                    else:
                        clean[k] = v
                f.write(f'  {json.dumps(clean, ensure_ascii=False)}\n')
        con.close()
    except Exception as e:
        f.write(f'  ERROR: {e}\n')

dbs = [
    ('snap_main.db',             'main.db'),
    ('snap_core.db',             'core.db'),
    ('snap_simple_db_helper.db', 'simple_db_helper.db'),
    ('valdi_in_app_warning.db',  'valdi/in_app_warning.db'),
    ('tiv.db',                   'tiv.db'),
    ('tivV2.db',                 'tivV2.db'),
]

with open(out_path, 'w', encoding='utf-8') as f:
    for fname, label in dbs:
        path = f'{base}/{fname}'
        if os.path.exists(path):
            dump_db(path, label, f)
        else:
            f.write(f'\n[MISSING] {fname}\n')

size = os.path.getsize(out_path)
with open(out_path, encoding='utf-8') as f:
    lines = sum(1 for _ in f)
print(f'Done: {lines} lines, {size:,} bytes')
print(f'File: {out_path}')
