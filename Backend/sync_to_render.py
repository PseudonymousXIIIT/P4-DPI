#!/usr/bin/env python3
"""
Sync local P4 DPI packets to Render API
Run this periodically to upload packets from local DPI engine to cloud
"""

import sqlite3
import requests
import argparse
import logging
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("sync_to_render")

def sync_packets(local_db_path, render_url, batch_size=1000, last_id=0):
    """
    Sync packets from local SQLite to Render API
    
    Args:
        local_db_path: Path to local packets.db
        render_url: Your Render API URL
        batch_size: Number of packets per batch
        last_id: Last synced packet ID (to avoid duplicates)
    """
    try:
        # Connect to local database
        conn = sqlite3.connect(local_db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Get packet count
        cursor.execute("SELECT COUNT(*) FROM packets WHERE id > ?", (last_id,))
        total = cursor.fetchone()[0]
        
        if total == 0:
            logger.info("No new packets to sync")
            return last_id
        
        logger.info(f"Found {total} new packets to sync")
        
        # Fetch packets in batches
        cursor.execute("""
            SELECT * FROM packets 
            WHERE id > ? 
            ORDER BY id ASC 
            LIMIT ?
        """, (last_id, batch_size))
        
        rows = cursor.fetchall()
        packets = []
        
        for row in rows:
            packet = {
                "timestamp": row["timestamp"],
                "switch_id": row["switch_id"],
                "src_mac": row["src_mac"],
                "dst_mac": row["dst_mac"],
                "src_ip": row["src_ip"],
                "dst_ip": row["dst_ip"],
                "src_port": row["src_port"],
                "dst_port": row["dst_port"],
                "protocol": row["protocol"],
                "packet_size": row["packet_size"],
                "ttl": row.get("ttl"),
                "tos": row.get("tos"),
                "is_suspicious": row.get("is_suspicious", 0),
                "is_malformed": row.get("is_malformed", 0),
                "flow_id": row.get("flow_id")
            }
            packets.append(packet)
            last_id = max(last_id, row["id"])
        
        conn.close()
        
        # Upload to Render
        logger.info(f"Uploading {len(packets)} packets to {render_url}")
        
        response = requests.post(
            f"{render_url}/api/upload",
            json={"packets": packets},
            timeout=30
        )
        
        if response.status_code == 200:
            logger.info(f"✓ Successfully synced {len(packets)} packets")
            return last_id
        else:
            logger.error(f"✗ Upload failed: {response.status_code} - {response.text}")
            return last_id
            
    except Exception as e:
        logger.error(f"Error syncing packets: {e}")
        return last_id

def main():
    parser = argparse.ArgumentParser(description="Sync P4 DPI packets to Render")
    parser.add_argument("--db", default="logs/packets.db", help="Local database path")
    parser.add_argument("--url", required=True, help="Render API URL (e.g., https://your-app.onrender.com)")
    parser.add_argument("--batch", type=int, default=1000, help="Batch size")
    parser.add_argument("--last-id", type=int, default=0, help="Last synced packet ID")
    parser.add_argument("--continuous", action="store_true", help="Run continuously")
    parser.add_argument("--interval", type=int, default=60, help="Sync interval in seconds (for continuous mode)")
    
    args = parser.parse_args()
    
    if args.continuous:
        import time
        logger.info(f"Starting continuous sync every {args.interval}s")
        last_id = args.last_id
        
        while True:
            try:
                last_id = sync_packets(args.db, args.url, args.batch, last_id)
                logger.info(f"Next sync in {args.interval}s (last_id={last_id})")
                time.sleep(args.interval)
            except KeyboardInterrupt:
                logger.info("Stopped by user")
                break
    else:
        sync_packets(args.db, args.url, args.batch, args.last_id)

if __name__ == "__main__":
    main()
