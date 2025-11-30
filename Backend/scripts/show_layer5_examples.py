#!/usr/bin/env python3
"""Show specific Layer 5 examples."""
import sqlite3

conn = sqlite3.connect('logs/packets.db')
cur = conn.cursor()

print("=== TLS Packets with Cipher Suites ===")
rows = cur.execute("""
    SELECT id, src_ip, dst_ip, dst_port, tls_version, tls_cipher, tls_sni, session_id
    FROM packets 
    WHERE tls_cipher IS NOT NULL AND tls_cipher != ''
    LIMIT 5
""").fetchall()

for row in rows:
    pid, src, dst, port, ver, cipher, sni, sess = row
    print(f"\nPacket {pid}: {src}:{port} -> {dst}:{port}")
    print(f"  TLS Version: {ver}")
    print(f"  Cipher: {cipher}")
    print(f"  SNI: {sni}")
    print(f"  Session ID: {sess}")

print("\n\n=== HTTP/2 Packets ===")
rows = cur.execute("""
    SELECT id, src_ip, dst_ip, dst_port, http2_stream_id
    FROM packets 
    WHERE http2_stream_id > 0
    LIMIT 5
""").fetchall()

for row in rows:
    pid, src, dst, port, stream = row
    print(f"\nPacket {pid}: {src} -> {dst}:{port}")
    print(f"  HTTP/2 Stream ID: {stream}")

conn.close()
