#!/usr/bin/env python3
"""
Flask API Server + Raw TCP Socket Streaming Server
P4 DPI Dashboard — Refactored Version
"""

import os
import sys
import sqlite3
import json
import logging
import socket
import threading
import time
from datetime import datetime, timedelta
from typing import Dict, List

from flask import Flask, jsonify, request, Response, stream_with_context, send_from_directory
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

# Determine static folder path (handles both local and production)
import os
if os.path.exists('/app/static'):
    static_folder = '/app/static'
else:
    static_folder = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'frontend-build')

app = Flask(__name__, static_folder=static_folder, static_url_path='')
CORS(app, resources={r"/api/*": {"origins": "*"}})

logger.info(f"Static folder: {static_folder}")
logger.info(f"Static folder exists: {os.path.exists(static_folder)}")

DB_PATH = os.getenv('DB_PATH', os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "logs", "packets.db"
))

# Ensure logs directory exists
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
logger.info(f"Database path: {DB_PATH}")

TIME_OFFSET_SECONDS = 60


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
        action = "dropped" if (row['is_suspicious'] or row['is_malformed']) else "forwarded"
        return {
            "timestamp": row["timestamp"],
            "packet_id": row["id"],
            "source_ip": row["src_ip"] or "N/A",
            "dest_ip": row["dst_ip"] or "N/A",
            "source_port": row["src_port"] or "N/A",
            "dest_port": row["dst_port"] or "N/A",
            "protocol": self._format_protocol(row),
            "packet_size": row["packet_size"] or 0,
            "action": action,
            "src_mac": row["src_mac"] or "N/A",
            "dst_mac": row["dst_mac"] or "N/A",
            "is_suspicious": bool(row["is_suspicious"]),
            "is_malformed": bool(row["is_malformed"]),
            "ttl": row["ttl"] or 0,
        }

    def _format_protocol(self, row):
        parts = []
        if row["layer4_protocol"]:
            parts.append(row["layer4_protocol"].upper())
        elif row["protocol"]:
            parts.append(row["protocol"].upper())

        if row["dst_port"] == 80:
            parts.append("HTTP")
        elif row["dst_port"] == 443:
            parts.append("HTTPS")
        elif row["dst_port"] == 22:
            parts.append("SSH")
        elif row["dst_port"] == 53:
            parts.append("DNS")

        return "/".join(parts) if parts else "UNKNOWN"

    def get_packets_with_offset(self, offset_seconds=TIME_OFFSET_SECONDS, limit=100):
        try:
            conn = self.get_connection()
            cursor = conn.cursor()

            target_time = datetime.now() - timedelta(seconds=offset_seconds)
            start = (target_time - timedelta(seconds=7)).strftime("%Y-%m-%d %H:%M:%S")
            end = (target_time + timedelta(seconds=8)).strftime("%Y-%m-%d %H:%M:%S")

            cursor.execute("""
                SELECT * FROM packets 
                ORDER BY timestamp DESC 
                LIMIT ?
            """, (limit,))

            rows = cursor.fetchall()
            conn.close()

            return [self.transform_packet(r) for r in rows]

        except Exception as e:
            logger.error(f"Error fetching packets: {e}")
            return []

    def get_stats(self):
        try:
            conn = self.get_connection()
            cursor = conn.cursor()

            cursor.execute("SELECT COUNT(*) AS total FROM packets")
            total = cursor.fetchone()["total"]

            cursor.execute("""
                SELECT 
                    SUM(CASE WHEN is_suspicious = 1 OR is_malformed = 1 THEN 1 ELSE 0 END) AS dropped,
                    SUM(CASE WHEN is_suspicious = 0 AND is_malformed = 0 THEN 1 ELSE 0 END) AS forwarded,
                    AVG(packet_size) AS avg_size
                FROM packets
            """)
            row = cursor.fetchone()
            conn.close()

            return {
                "total_packets": total,
                "forwarded": row["forwarded"] or 0,
                "dropped": row["dropped"] or 0,
                "avg_packet_size": round(row["avg_size"] or 0, 2)
            }
        except Exception as e:
            logger.error(f"Error fetching stats: {e}")
            return {"total_packets": 0, "forwarded": 0, "dropped": 0, "avg_packet_size": 0}


# ---------------------------------------------------------------
# Database Initialization
# ---------------------------------------------------------------

def initialize_database():
    """Initialize database schema if it doesn't exist"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Create packets table if it doesn't exist
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
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
        ''')
        
        conn.commit()
        conn.close()
        logger.info(f"Database initialized successfully at {DB_PATH}")
    except Exception as e:
        logger.error(f"Error initializing database: {e}")

# Initialize database before creating data provider
initialize_database()

data_provider = PacketDataProvider(DB_PATH)

# ---------------------------------------------------------------
# Flask Endpoints
# ---------------------------------------------------------------

# Serve React frontend
@app.route('/')
def serve_frontend():
    """Serve the React frontend"""
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/<path:path>')
def serve_static_files(path):
    """Serve static files from React build"""
    try:
        return send_from_directory(app.static_folder, path)
    except:
        # If file not found, serve index.html (for React routing)
        return send_from_directory(app.static_folder, 'index.html')

# API Routes
@app.route("/api/info")
def api_info():
    return jsonify({
        "service": "P4 DPI API",
        "version": "1.0",
        "status": "running",
        "endpoints": [
            "/api/health",
            "/api/packets",
            "/api/stats",
            "/stream",
            "/api/upload"
        ]
    })

@app.route("/api/packets")
def api_packets():
    offset = int(request.args.get("offset", TIME_OFFSET_SECONDS))
    limit = int(request.args.get("limit", 1000))
    packets = data_provider.get_packets_with_offset(offset, limit)
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
        return jsonify({"status": "healthy", "packet_count": count, "db_path": DB_PATH})
    except Exception as e:
        return jsonify({"status": "unhealthy", "error": str(e)}), 500

@app.route('/api/upload', methods=['POST'])
def upload_packets():
    """Bulk upload packets from local DPI or sync script"""
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
# SOCKET STREAMING SERVER (RAW TCP)
# ---------------------------------------------------------------

# CLIENTS = []
# STREAMING = False


# def broadcast(data: dict):
#     """Send JSON to all connected clients"""
#     dead = []
#     for conn in CLIENTS:
#         try:
#             conn.send((json.dumps(data) + "\n").encode())
#         except:
#             dead.append(conn)

#     # Remove disconnected clients
#     for conn in dead:
#         CLIENTS.remove(conn)


# def client_handler(conn, addr):
#     logger.info(f"Socket client connected: {addr}")
#     CLIENTS.append(conn)

#     try:
#         while True:
#             msg = conn.recv(1024).decode().strip()
#             if not msg:
#                 break

#             if msg == "start_stream":
#                 global STREAMING
#                 STREAMING = True
#                 conn.send(b"{\"status\":\"streaming_started\"}\n")

#             elif msg == "stop_stream":
#                 STREAMING = False
#                 conn.send(b"{\"status\":\"streaming_stopped\"}\n")

#     except:
#         pass

#     finally:
#         logger.info(f"Client disconnected: {addr}")
#         CLIENTS.remove(conn)
#         conn.close()


# def tcp_server(host="0.0.0.0", port=6000):
#     """TCP server for live packet streaming"""
#     s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     s.bind((host, port))
#     s.listen(5)

#     logger.info(f"TCP Streaming Server running on {host}:{port}")

#     while True:
#         conn, addr = s.accept()
#         threading.Thread(target=client_handler, args=(conn, addr), daemon=True).start()


# def stream_loop():
#     """Background stream loop sending packets every 5s"""
#     global STREAMING
#     logger.info("Streaming loop started")

#     while True:
#         if STREAMING:
#             packets = data_provider.get_packets_with_offset(limit=50)
#             if packets:
#                 broadcast({
#                     "timestamp": datetime.now().isoformat(),
#                     "count": len(packets),
#                     "packets": packets
#                 })
#         time.sleep(5)

@app.route('/stream')
def stream_packets():
    @stream_with_context
    def generate():
        while True:
            packets = data_provider.get_packets_with_offset(limit=50)
            payload = {
                "timestamp": datetime.now().isoformat(),
                "count": len(packets),
                "packets": packets
            }
            yield f"data: {json.dumps(payload)}\n\n"
            time.sleep(5)

    # IMPORTANT: SSE endpoint must manually include CORS headers
    response = Response(generate(), mimetype='text/event-stream')
    response.headers["Access-Control-Allow-Origin"] = "*"     # ← Fix
    response.headers["Cache-Control"] = "no-cache"
    response.headers["X-Accel-Buffering"] = "no"              # Nginx support (optional)
    return response


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