#!/usr/bin/env python3
"""Check if exported JSON has Layer 5 fields populated."""
import json
import sys

json_file = sys.argv[1] if len(sys.argv) > 1 else 'logs/packets_export_db_20251118_143349.json'

with open(json_file) as f:
    packets = json.load(f)

print(f"Total packets: {len(packets)}")

tls_packets = [p for p in packets if p.get('tls_version')]
print(f"TLS packets: {len(tls_packets)}")

if tls_packets:
    print("\n=== Sample TLS Packet ===")
    sample = tls_packets[0]
    print(f"ID: {sample['id']}")
    print(f"Timestamp: {sample['timestamp']}")
    print(f"Flow: {sample['src_ip']}:{sample['src_port']} -> {sample['dst_ip']}:{sample['dst_port']}")
    print(f"Session ID: {sample['session_id']}")
    print(f"TLS Version: {sample['tls_version']}")
    print(f"TLS SNI: {sample['tls_sni']}")
    print(f"TLS Cipher: {sample['tls_cipher']}")
    print(f"HTTP/2 Stream ID: {sample['http2_stream_id']}")
else:
    print("\n⚠️ No TLS packets found in export!")
    
    # Check if fields exist but are empty
    port_443 = [p for p in packets if p.get('dst_port') == 443 or p.get('src_port') == 443]
    print(f"Packets on port 443: {len(port_443)}")
    
    if port_443:
        print("\nSample port 443 packet (should have TLS data):")
        sample = port_443[0]
        print(f"ID: {sample['id']}")
        print(f"Flow: {sample['src_ip']}:{sample['src_port']} -> {sample['dst_ip']}:{sample['dst_port']}")
        print(f"Session ID: '{sample['session_id']}'")
        print(f"TLS Version: '{sample['tls_version']}'")
        print(f"TLS SNI: '{sample['tls_sni']}'")
