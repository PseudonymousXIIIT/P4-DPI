#!/usr/bin/env python3
import sqlite3

conn = sqlite3.connect('logs/packets.db')
cur = conn.cursor()

# Get tables
tables = [r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'")]
print(f"Tables in database: {tables}")

if 'packets' in tables:
    count = cur.execute("SELECT COUNT(*) FROM packets").fetchone()[0]
    print(f"Total packets logged: {count}")
    
    # Sample some packets
    print("\nSample packets (first 5):")
    for row in cur.execute("SELECT * FROM packets LIMIT 5"):
        print(row)
else:
    print("No 'packets' table found")

conn.close()
