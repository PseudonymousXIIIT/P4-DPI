#!/usr/bin/env python3
"""Analyze traffic distribution."""
import sqlite3

conn = sqlite3.connect('logs/packets.db')
cur = conn.cursor()

total = cur.execute('SELECT COUNT(*) FROM packets').fetchone()[0]
port443 = cur.execute('SELECT COUNT(*) FROM packets WHERE src_port=443 OR dst_port=443').fetchone()[0]
tls = cur.execute('SELECT COUNT(*) FROM packets WHERE tls_version IS NOT NULL AND tls_version != ""').fetchone()[0]

print(f"Total packets: {total}")
print(f"Port 443 packets: {port443} ({port443*100//total if total else 0}%)")
print(f"TLS packets: {tls} ({tls*100//total if total else 0}%)")
print(f"\nTLS coverage: {tls}/{port443} = {tls*100//port443 if port443 else 0}% of HTTPS traffic has TLS payloads")

conn.close()
