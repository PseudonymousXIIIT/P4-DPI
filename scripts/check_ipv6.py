#!/usr/bin/env python3
import sqlite3

c = sqlite3.connect('logs/packets.db')
all_ips = c.execute("select src_ip from packets").fetchall()

ipv4 = sum(1 for r in all_ips if "." in r[0] and ":" not in r[0])
ipv6 = sum(1 for r in all_ips if ":" in r[0])
total = ipv4 + ipv6

print(f"Total packets: {total}")
print(f"IPv4 packets: {ipv4} ({ipv4*100.0/total:.1f}%)")
print(f"IPv6 packets: {ipv6} ({ipv6*100.0/total:.1f}%)")

# Show protocol breakdown
protocols = c.execute("select protocol, count(*) from packets group by protocol").fetchall()
print("\nProtocol breakdown:")
for proto, count in protocols:
    print(f"  {proto}: {count}")

c.close()
