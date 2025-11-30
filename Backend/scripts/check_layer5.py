#!/usr/bin/env python3
"""Check Layer 5 (Session) data in packets database."""
import sqlite3

db_path = 'logs/packets.db'
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

print("=== Layer 5 Session Data Analysis ===\n")

# Check if new columns exist
cursor.execute("PRAGMA table_info(packets)")
columns = [row[1] for row in cursor.fetchall()]
layer5_cols = ['session_id', 'tls_version', 'tls_cipher', 'tls_sni', 'http2_stream_id']
missing = [col for col in layer5_cols if col not in columns]

if missing:
    print(f"⚠️  Missing columns: {', '.join(missing)}")
    print("Database needs schema update. Delete logs/packets.db and restart.")
    conn.close()
    exit(1)

print("✓ All Layer 5 columns present in schema\n")

# Count packets with TLS data
cursor.execute("SELECT COUNT(*) FROM packets WHERE tls_version IS NOT NULL AND tls_version != ''")
tls_count = cursor.fetchone()[0]
print(f"Packets with TLS version: {tls_count}")

cursor.execute("SELECT COUNT(*) FROM packets WHERE tls_sni IS NOT NULL AND tls_sni != ''")
sni_count = cursor.fetchone()[0]
print(f"Packets with SNI: {sni_count}")

cursor.execute("SELECT COUNT(*) FROM packets WHERE session_id IS NOT NULL AND session_id != ''")
session_count = cursor.fetchone()[0]
print(f"Packets with Session ID: {session_count}\n")

# Show sample TLS packets
print("=== Sample TLS Packets ===")
cursor.execute("""
    SELECT id, src_ip, dst_ip, dst_port, tls_version, tls_sni, session_id 
    FROM packets 
    WHERE tls_version IS NOT NULL AND tls_version != ''
    LIMIT 10
""")

rows = cursor.fetchall()
if rows:
    for row in rows:
        pid, src, dst, port, ver, sni, sess = row
        print(f"  Packet {pid}: {src}:{port} -> {dst}")
        print(f"    TLS: {ver}, SNI: {sni or '(none)'}, SessionID: {sess or '(none)'}")
else:
    print("  No TLS packets found yet.\n")
    print("To generate test TLS traffic, run:")
    print("  python3 scripts/test_tls_layer5.py")

# Check session_data table
cursor.execute("SELECT COUNT(*) FROM session_data")
session_table_count = cursor.fetchone()[0]
print(f"\nSessions in session_data table: {session_table_count}")

conn.close()
print("\n✓ Layer 5 inspection complete!")
