#!/usr/bin/env python3
"""Check Layer 5 (Session) data with cipher suites and HTTP/2."""
import sqlite3

conn = sqlite3.connect('logs/packets.db')
cur = conn.cursor()

print("=== Layer 5 Session Data Analysis ===\n")

# Count packets with Layer 5 data
tls_count = cur.execute("SELECT COUNT(*) FROM packets WHERE tls_version IS NOT NULL AND tls_version != ''").fetchone()[0]
sni_count = cur.execute("SELECT COUNT(*) FROM packets WHERE tls_sni IS NOT NULL AND tls_sni != ''").fetchone()[0]
session_count = cur.execute("SELECT COUNT(*) FROM packets WHERE session_id IS NOT NULL AND session_id != ''").fetchone()[0]
cipher_count = cur.execute("SELECT COUNT(*) FROM packets WHERE tls_cipher IS NOT NULL AND tls_cipher != ''").fetchone()[0]
http2_count = cur.execute("SELECT COUNT(*) FROM packets WHERE http2_stream_id > 0").fetchone()[0]

print(f"Packets with TLS version: {tls_count}")
print(f"Packets with SNI: {sni_count}")
print(f"Packets with Session ID: {session_count}")
print(f"Packets with TLS Cipher: {cipher_count}")
print(f"Packets with HTTP/2 Stream ID: {http2_count}")

# Show sample TLS packets with cipher info
if tls_count > 0:
    print("\n=== Sample TLS Packets ===")
    tls_samples = cur.execute("""
        SELECT id, src_ip, src_port, dst_ip, dst_port, tls_version, tls_sni, session_id, tls_cipher
        FROM packets 
        WHERE tls_version IS NOT NULL AND tls_version != ''
        ORDER BY id
        LIMIT 10
    """).fetchall()
    
    for row in tls_samples:
        pid, src_ip, src_port, dst_ip, dst_port, tls_ver, sni, sess_id, cipher = row
        print(f"  Packet {pid}: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
        print(f"    TLS: {tls_ver}, SNI: {sni}, SessionID: {sess_id}")
        if cipher:
            print(f"    Cipher: {cipher}")

# Show sample HTTP/2 packets
if http2_count > 0:
    print("\n=== Sample HTTP/2 Packets ===")
    h2_samples = cur.execute("""
        SELECT id, src_ip, src_port, dst_ip, dst_port, http2_stream_id
        FROM packets 
        WHERE http2_stream_id > 0
        ORDER BY id
        LIMIT 10
    """).fetchall()
    
    for row in h2_samples:
        pid, src_ip, src_port, dst_ip, dst_port, stream_id = row
        print(f"  Packet {pid}: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
        print(f"    HTTP/2 Stream ID: {stream_id}")

# Unique cipher suites
if cipher_count > 0:
    print("\n=== Cipher Suite Distribution ===")
    cipher_dist = cur.execute("""
        SELECT tls_cipher, COUNT(*) as count
        FROM packets 
        WHERE tls_cipher IS NOT NULL AND tls_cipher != ''
        GROUP BY tls_cipher
        ORDER BY count DESC
    """).fetchall()
    
    for cipher, count in cipher_dist:
        print(f"  {cipher}: {count} packets")

conn.close()
print("\n✓ Layer 5 inspection complete!")
