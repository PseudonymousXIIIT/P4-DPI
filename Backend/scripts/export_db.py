#!/usr/bin/env python3
"""
Export packets and flows from SQLite DB to JSON/CSV.
Useful when in-memory exporter produced empty files earlier.
"""
import os
import sys
import json
import csv
import sqlite3
from datetime import datetime
import argparse


def export_packets(db_file: str, out_dir: str, limit: int = None):
    os.makedirs(out_dir, exist_ok=True)
    conn = sqlite3.connect(db_file)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    q = 'SELECT * FROM packets ORDER BY id ASC'
    if limit:
        q += f' LIMIT {int(limit)}'
    rows = cur.execute(q).fetchall()

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    json_path = os.path.join(out_dir, f'packets_export_db_{timestamp}.json')
    csv_path = os.path.join(out_dir, f'packets_export_db_{timestamp}.csv')

    # JSON
    with open(json_path, 'w') as f:
        json.dump([dict(r) for r in rows], f, indent=2)

    # CSV
    if rows:
        with open(csv_path, 'w', newline='') as f:
            w = csv.writer(f)
            headers = rows[0].keys()
            w.writerow(headers)
            for r in rows:
                w.writerow([r[h] for h in headers])
    else:
        with open(csv_path, 'w') as f:
            f.write('')

    print(f"Exported {len(rows)} packets to:\n  {json_path}\n  {csv_path}")

    conn.close()


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--db', default='logs/packets.db')
    p.add_argument('--out', default='logs')
    p.add_argument('--limit', type=int, default=None)
    args = p.parse_args()

    export_packets(args.db, args.out, args.limit)


if __name__ == '__main__':
    main()
