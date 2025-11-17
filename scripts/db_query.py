#!/usr/bin/env python3
import sqlite3
import sys

DB='logs/packets.db'
if len(sys.argv)>1:
    DB=sys.argv[1]
conn=sqlite3.connect(DB)
cur=conn.cursor()
print('total=', cur.execute('select count(*) from packets').fetchone()[0])
print('tcp80=', cur.execute("select count(*) from packets where protocol='TCP' and dst_port=80").fetchone()[0])
print('udp53=', cur.execute("select count(*) from packets where protocol='UDP' and dst_port=53").fetchone()[0])
print('icmp=', cur.execute("select count(*) from packets where protocol='ICMP'").fetchone()[0])
print('last10=')
for r in cur.execute('select src_ip,dst_ip,src_port,dst_port,protocol,packet_size,timestamp from packets order by id desc limit 10').fetchall():
    print(r)
