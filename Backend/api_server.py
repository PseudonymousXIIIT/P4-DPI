#!/usr/bin/env python3
"""
Flask API Server for Render Deployment
Simplified version without P4/Mininet dependencies
"""

import os
import sqlite3
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List

from flask import Flask, jsonify, request, Response, stream_with_context
from flask_cors import CORS

# ---------------------------------------------------------------
# Logging
# ---------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("DPI_API")

# ---------------------------------------------------------------
# Flask Setup
# ---------------------------------------------------------------

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})

# Support both local and Render paths
DB_PATH = os.getenv('DB_PATH', os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "logs", "packets.db"
))

# Ensure directory exists
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

TIME_OFFSET_SECONDS = 60

# ---------------------------------------------------------------
# Database Initialization
# ---------------------------------------------------------------

def init_db():
    """Initialize database with schema if it doesn't exist"""
    if not os.path.exists(DB_PATH):
        logger.info(f"Creating database at {DB_PATH}")
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Create packets table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                switch_id TEXT,
                src_mac TEXT,
                dst_mac TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT,
                packet_size INTEGER,
                ttl INTEGER,
                tos INTEGER,
                flags INTEGER,
                sequence INTEGER,
                ack_number INTEGER,
                window_size INTEGER,
                link_protocol TEXT,
                network_protocol TEXT,
                layer4_protocol TEXT,
                is_suspicious INTEGER DEFAULT 0,
                is_malformed INTEGER DEFAULT 0,
                flow_id TEXT
            )
        """)
        
        # Create indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON packets(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_flow_id ON packets(flow_id)")
        
        conn.commit()
        conn.close()
        logger.info("Database initialized successfully")

# ---------------------------------------------------------------
# Data Provider
# ---------------------------------------------------------------

class PacketDataProvider:
    def __init__(self, db_path: str):
        self.db_path = db_path

    def get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def transform_packet(self, row: sqlite3.Row) -> Dict:
        action = "dropped" if (row.get('is_suspicious') or row.get('is_malformed')) else "forwarded"
        return {
            "timestamp": row["timestamp"],
            "packet_id": row["id"],
            "source_ip": row["src_ip"] or "N/A",
            "dest_ip": row["dst_ip"] or "N/A",
            "source_port": row["src_port"] or 0,
            "dest_port": row["dst_port"] or 0,
            "protocol": self._format_protocol(row),
            "packet_size": row["packet_size"] or 0,
            "action": action,
            "src_mac": row["src_mac"] or "N/A",
            "dst_mac": row["dst_mac"] or "N/A",
            "is_suspicious": bool(row.get("is_suspicious", 0)),
            "is_malformed": bool(row.get("is_malformed", 0)),
            "ttl": row.get("ttl", 0),
        }

    def _format_protocol(self, row):
        parts = []
        if row.get("layer4_protocol"):
            parts.append(row["layer4_protocol"].upper())
        elif row.get("protocol"):
            parts.append(row["protocol"].upper())

        dst_port = row.get("dst_port", 0)
        if dst_port == 80:
            parts.append("HTTP")
        elif dst_port == 443:
            parts.append("HTTPS")
        elif dst_port == 22:
            parts.append("SSH")
        elif dst_port == 53:
            parts.append("DNS")

        return "/".join(parts) if parts else "UNKNOWN"

    def get_packets_with_offset(self, offset_seconds=TIME_OFFSET_SECONDS, limit=100):
        try:
            conn = self.get_connection()
            cursor = conn.cursor()

            target_time = datetime.now() - timedelta(seconds=offset_seconds)
            start = (target_time - timedelta(seconds=7)).strftime("%Y-%m-%d %H:%M:%S")
            end = (target_time + timedelta(seconds=3)).strftime("%Y-%m-%d %H:%M:%S")

            query = """
                SELECT * FROM packets
                WHERE timestamp BETWEEN ? AND ?
                ORDER BY timestamp DESC
                LIMIT ?
            """
            cursor.execute(query, (start, end, limit))
            rows = cursor.fetchall()
            conn.close()

            return [self.transform_packet(row) for row in rows]
        except Exception as e:
            logger.error(f"Error fetching packets: {e}")
            return []

    def get_recent_packets(self, limit=100):
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM packets
                ORDER BY id DESC
                LIMIT ?
            """, (limit,))
            rows = cursor.fetchall()
            conn.close()
            return [self.transform_packet(row) for row in rows]
        except Exception as e:
            logger.error(f"Error fetching recent packets: {e}")
            return []

    def get_stats(self):
        try:
            conn = self.get_connection()
            cursor = conn.cursor()

            # Total packets
            cursor.execute("SELECT COUNT(*) FROM packets")
            total = cursor.fetchone()[0]

            # Protocol distribution
            cursor.execute("""
                SELECT protocol, COUNT(*) as count
                FROM packets
                GROUP BY protocol
                ORDER BY count DESC
                LIMIT 10
            """)
            protocols = [{"protocol": row[0], "count": row[1]} for row in cursor.fetchall()]

            # Top source IPs
            cursor.execute("""
                SELECT src_ip, COUNT(*) as count
                FROM packets
                WHERE src_ip IS NOT NULL
                GROUP BY src_ip
                ORDER BY count DESC
                LIMIT 10
            """)
            top_sources = [{"ip": row[0], "count": row[1]} for row in cursor.fetchall()]

            # Top destination IPs
            cursor.execute("""
                SELECT dst_ip, COUNT(*) as count
                FROM packets
                WHERE dst_ip IS NOT NULL
                GROUP BY dst_ip
                ORDER BY count DESC
                LIMIT 10
            """)
            top_destinations = [{"ip": row[0], "count": row[1]} for row in cursor.fetchall()]

            # Suspicious packets
            cursor.execute("SELECT COUNT(*) FROM packets WHERE is_suspicious = 1")
            suspicious = cursor.fetchone()[0]

            conn.close()

            return {
                "total_packets": total,
                "suspicious_packets": suspicious,
                "protocols": protocols,
                "top_sources": top_sources,
                "top_destinations": top_destinations
            }
        except Exception as e:
            logger.error(f"Error fetching stats: {e}")
            return {
                "total_packets": 0,
                "suspicious_packets": 0,
                "protocols": [],
                "top_sources": [],
                "top_destinations": []
            }

# Initialize
init_db()
data_provider = PacketDataProvider(DB_PATH)

# ---------------------------------------------------------------
# Flask Endpoints
# ---------------------------------------------------------------

@app.route("/")
def index():
    return jsonify({
        "service": "P4 DPI API",
        "version": "1.0",
        "status": "running",
        "endpoints": [
            "/api/health",
            "/api/packets",
            "/api/packets/recent",
            "/api/stats",
            "/stream"
        ]
    })

@app.route("/api/packets")
def api_packets():
    offset = int(request.args.get("offset", TIME_OFFSET_SECONDS))
    limit = int(request.args.get("limit", 1000))
    packets = data_provider.get_packets_with_offset(offset, limit)
    return jsonify({"success": True, "count": len(packets), "data": packets})

@app.route("/api/packets/recent")
def api_recent_packets():
    limit = int(request.args.get("limit", 100))
    packets = data_provider.get_recent_packets(limit)
    return jsonify({"success": True, "count": len(packets), "data": packets})

@app.route("/api/stats")
def api_stats():
    return jsonify({"success": True, "data": data_provider.get_stats()})

@app.route("/api/health")
def health():
    try:
        conn = data_provider.get_connection()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM packets")
        count = cur.fetchone()[0]
        conn.close()
        return jsonify({
            "status": "healthy",
            "packet_count": count,
            "db_path": DB_PATH,
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return jsonify({"status": "unhealthy", "error": str(e)}), 500

@app.route('/stream')
def stream_packets():
    """Server-Sent Events endpoint for real-time packet streaming"""
    import time
    
    @stream_with_context
    def generate():
        while True:
            packets = data_provider.get_recent_packets(limit=50)
            payload = {
                "timestamp": datetime.now().isoformat(),
                "count": len(packets),
                "packets": packets
            }
            yield f"data: {json.dumps(payload)}\n\n"
            time.sleep(5)

    response = Response(generate(), mimetype='text/event-stream')
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Cache-Control"] = "no-cache"
    response.headers["X-Accel-Buffering"] = "no"
    return response

@app.route('/api/upload', methods=['POST'])
def upload_packets():
    """Bulk upload packets from local DPI engine"""
    try:
        data = request.get_json()
        packets = data.get('packets', [])
        
        if not packets:
            return jsonify({"success": False, "error": "No packets provided"}), 400
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        inserted = 0
        for packet in packets:
            try:
                cursor.execute("""
                    INSERT INTO packets (
                        timestamp, switch_id, src_mac, dst_mac, src_ip, dst_ip,
                        src_port, dst_port, protocol, packet_size, ttl, tos,
                        is_suspicious, is_malformed, flow_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    packet.get('timestamp'),
                    packet.get('switch_id'),
                    packet.get('src_mac'),
                    packet.get('dst_mac'),
                    packet.get('src_ip'),
                    packet.get('dst_ip'),
                    packet.get('src_port'),
                    packet.get('dst_port'),
                    packet.get('protocol'),
                    packet.get('packet_size'),
                    packet.get('ttl'),
                    packet.get('tos'),
                    packet.get('is_suspicious', 0),
                    packet.get('is_malformed', 0),
                    packet.get('flow_id')
                ))
                inserted += 1
            except Exception as e:
                logger.warning(f"Failed to insert packet: {e}")
                continue
        
        conn.commit()
        conn.close()
        
        logger.info(f"Uploaded {inserted}/{len(packets)} packets")
        
        return jsonify({
            "success": True,
            "inserted": inserted,
            "total": len(packets),
            "timestamp": datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Upload error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

# ---------------------------------------------------------------
# Server Bootstrap
# ---------------------------------------------------------------

def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=int(os.getenv('PORT', 5000)))
    args = parser.parse_args()

    logger.info(f"Starting Flask REST API on {args.host}:{args.port}")
    logger.info(f"Database path: {DB_PATH}")
    app.run(host=args.host, port=args.port)

if __name__ == "__main__":
    main()
