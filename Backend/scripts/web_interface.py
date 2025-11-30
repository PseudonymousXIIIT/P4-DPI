#!/usr/bin/env python3
"""
Web Interface for P4 DPI Tool
Provides a real-time monitoring dashboard for the Deep Packet Inspection system
"""

import os
import sys
import json
import time
import logging
import threading
from datetime import datetime, timedelta
from flask import Flask, render_template, jsonify, request, send_file
from flask_cors import CORS
import pandas as pd
import sqlite3
from typing import Dict, List, Optional
import yaml

# Add current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

app = Flask(__name__)
CORS(app)

class DPIWebInterface:
    def __init__(self, config_file: str = "config/dpi_config.yaml"):
        """Initialize the web interface"""
        self.config = self.load_config(config_file)
        self.setup_logging()
        self.db_file = self.config.get('performance', {}).get('database', {}).get('file', 'logs/packets.db')
        self.stats_cache = {}
        self.cache_lock = threading.Lock()
        
        # Start background data refresh
        self.start_background_refresh()
    
    def load_config(self, config_file: str) -> dict:
        """Load configuration"""
        try:
            with open(config_file, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            return {
                'web_interface': {
                    'host': '0.0.0.0',
                    'port': 5000,
                    'debug': False
                },
                'performance': {
                    'database': {
                        'file': 'logs/packets.db'
                    }
                }
            }
    
    def setup_logging(self):
        """Setup logging"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('logs/web_interface.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger('WebInterface')
    
    def start_background_refresh(self):
        """Start background data refresh thread"""
        refresh_thread = threading.Thread(target=self.refresh_data, daemon=True)
        refresh_thread.start()
    
    def refresh_data(self):
        """Refresh cached data periodically"""
        while True:
            try:
                with self.cache_lock:
                    self.stats_cache = self.get_system_stats()
                time.sleep(5)  # Refresh every 5 seconds
            except Exception as e:
                self.logger.error(f"Error refreshing data: {e}")
    
    def get_system_stats(self) -> dict:
        """Get system statistics from database"""
        try:
            if not os.path.exists(self.db_file):
                return {}
            
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            # Get packet statistics
            cursor.execute('''
                SELECT 
                    COUNT(*) as total_packets,
                    COUNT(CASE WHEN protocol = 'TCP' THEN 1 END) as tcp_packets,
                    COUNT(CASE WHEN protocol = 'UDP' THEN 1 END) as udp_packets,
                    COUNT(CASE WHEN protocol = 'ICMP' THEN 1 END) as icmp_packets,
                    COUNT(CASE WHEN is_suspicious = 1 THEN 1 END) as suspicious_packets,
                    COUNT(CASE WHEN is_fragment = 1 THEN 1 END) as fragmented_packets,
                    COUNT(CASE WHEN is_malformed = 1 THEN 1 END) as malformed_packets
                FROM packets
                WHERE timestamp > datetime('now', '-1 hour')
            ''')
            
            packet_stats = cursor.fetchone()
            
            # Get top protocols
            cursor.execute('''
                SELECT protocol, COUNT(*) as count
                FROM packets
                WHERE timestamp > datetime('now', '-1 hour')
                GROUP BY protocol
                ORDER BY count DESC
                LIMIT 10
            ''')
            
            top_protocols = dict(cursor.fetchall())
            
            # Get top ports
            cursor.execute('''
                SELECT dst_port, COUNT(*) as count
                FROM packets
                WHERE timestamp > datetime('now', '-1 hour')
                GROUP BY dst_port
                ORDER BY count DESC
                LIMIT 10
            ''')
            
            top_ports = dict(cursor.fetchall())
            
            # Get top IPs
            cursor.execute('''
                SELECT dst_ip, COUNT(*) as count
                FROM packets
                WHERE timestamp > datetime('now', '-1 hour')
                GROUP BY dst_ip
                ORDER BY count DESC
                LIMIT 10
            ''')
            
            top_ips = dict(cursor.fetchall())
            
            # Get recent flows
            cursor.execute('''
                SELECT flow_id, src_ip, dst_ip, src_port, dst_port, protocol, 
                       packet_count, total_bytes, is_suspicious
                FROM flows
                WHERE end_time > datetime('now', '-1 hour')
                ORDER BY end_time DESC
                LIMIT 50
            ''')
            
            recent_flows = []
            for row in cursor.fetchall():
                recent_flows.append({
                    'flow_id': row[0],
                    'src_ip': row[1],
                    'dst_ip': row[2],
                    'src_port': row[3],
                    'dst_port': row[4],
                    'protocol': row[5],
                    'packet_count': row[6],
                    'total_bytes': row[7],
                    'is_suspicious': bool(row[8])
                })
            
            conn.close()
            
            return {
                'timestamp': datetime.now().isoformat(),
                'packet_stats': {
                    'total_packets': packet_stats[0] or 0,
                    'tcp_packets': packet_stats[1] or 0,
                    'udp_packets': packet_stats[2] or 0,
                    'icmp_packets': packet_stats[3] or 0,
                    'suspicious_packets': packet_stats[4] or 0,
                    'fragmented_packets': packet_stats[5] or 0,
                    'malformed_packets': packet_stats[6] or 0
                },
                'top_protocols': top_protocols,
                'top_ports': top_ports,
                'top_ips': top_ips,
                'recent_flows': recent_flows
            }
            
        except Exception as e:
            self.logger.error(f"Error getting system stats: {e}")
            return {}

# Create web interface instance
web_interface = DPIWebInterface()

@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('dashboard.html')

@app.route('/api/stats')
def get_stats():
    """Get system statistics"""
    with web_interface.cache_lock:
        return jsonify(web_interface.stats_cache)

@app.route('/api/packets')
def get_packets():
    """Get recent packets"""
    try:
        limit = request.args.get('limit', 100, type=int)
        format_type = request.args.get('format', 'json')
        
        if not os.path.exists(web_interface.db_file):
            return jsonify([])
        
        conn = sqlite3.connect(web_interface.db_file)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT timestamp, switch_id, src_mac, dst_mac, src_ip, dst_ip,
                   src_port, dst_port, protocol, packet_size, tcp_flags,
                   icmp_type, icmp_code, is_fragment, is_malformed, is_suspicious,
                   layer2_protocol, layer3_protocol, layer4_protocol, ttl, tos, flow_id
            FROM packets
            ORDER BY timestamp DESC
            LIMIT ?
        ''', (limit,))
        
        columns = [description[0] for description in cursor.description]
        packets = []
        
        for row in cursor.fetchall():
            packet = dict(zip(columns, row))
            packets.append(packet)
        
        conn.close()
        
        if format_type == 'csv':
            df = pd.DataFrame(packets)
            csv_data = df.to_csv(index=False)
            return csv_data, 200, {'Content-Type': 'text/csv'}
        else:
            return jsonify(packets)
            
    except Exception as e:
        web_interface.logger.error(f"Error getting packets: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/flows')
def get_flows():
    """Get network flows"""
    try:
        active_only = request.args.get('active', 'false').lower() == 'true'
        limit = request.args.get('limit', 100, type=int)
        
        if not os.path.exists(web_interface.db_file):
            return jsonify([])
        
        conn = sqlite3.connect(web_interface.db_file)
        cursor = conn.cursor()
        
        if active_only:
            cursor.execute('''
                SELECT flow_id, src_ip, dst_ip, src_port, dst_port, protocol,
                       start_time, end_time, packet_count, total_bytes, is_suspicious
                FROM flows
                WHERE end_time > datetime('now', '-5 minutes')
                ORDER BY end_time DESC
                LIMIT ?
            ''', (limit,))
        else:
            cursor.execute('''
                SELECT flow_id, src_ip, dst_ip, src_port, dst_port, protocol,
                       start_time, end_time, packet_count, total_bytes, is_suspicious
                FROM flows
                ORDER BY end_time DESC
                LIMIT ?
            ''', (limit,))
        
        columns = [description[0] for description in cursor.description]
        flows = []
        
        for row in cursor.fetchall():
            flow = dict(zip(columns, row))
            flows.append(flow)
        
        conn.close()
        
        return jsonify(flows)
        
    except Exception as e:
        web_interface.logger.error(f"Error getting flows: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/alerts')
def get_alerts():
    """Get security alerts"""
    try:
        severity = request.args.get('severity', 'all')
        limit = request.args.get('limit', 50, type=int)
        
        if not os.path.exists(web_interface.db_file):
            return jsonify([])
        
        conn = sqlite3.connect(web_interface.db_file)
        cursor = conn.cursor()
        
        # Get suspicious packets as alerts
        cursor.execute('''
            SELECT timestamp, src_ip, dst_ip, src_port, dst_port, protocol,
                   packet_size, is_suspicious, is_fragment, is_malformed
            FROM packets
            WHERE is_suspicious = 1 OR is_malformed = 1
            ORDER BY timestamp DESC
            LIMIT ?
        ''', (limit,))
        
        columns = [description[0] for description in cursor.description]
        alerts = []
        
        for row in cursor.fetchall():
            alert = dict(zip(columns, row))
            alert['severity'] = 'high' if alert['is_suspicious'] else 'medium'
            alert['type'] = 'suspicious' if alert['is_suspicious'] else 'malformed'
            alerts.append(alert)
        
        conn.close()
        
        # Filter by severity if specified
        if severity != 'all':
            alerts = [alert for alert in alerts if alert['severity'] == severity]
        
        return jsonify(alerts)
        
    except Exception as e:
        web_interface.logger.error(f"Error getting alerts: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/export')
def export_data():
    """Export data in various formats"""
    try:
        format_type = request.args.get('format', 'json')
        data_type = request.args.get('type', 'packets')
        limit = request.args.get('limit', 1000, type=int)
        
        if not os.path.exists(web_interface.db_file):
            return jsonify({'error': 'Database not found'}), 404
        
        conn = sqlite3.connect(web_interface.db_file)
        cursor = conn.cursor()
        
        if data_type == 'packets':
            cursor.execute('''
                SELECT * FROM packets
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (limit,))
            table_name = 'packets'
        elif data_type == 'flows':
            cursor.execute('''
                SELECT * FROM flows
                ORDER BY end_time DESC
                LIMIT ?
            ''', (limit,))
            table_name = 'flows'
        else:
            return jsonify({'error': 'Invalid data type'}), 400
        
        columns = [description[0] for description in cursor.description]
        data = []
        
        for row in cursor.fetchall():
            record = dict(zip(columns, row))
            data.append(record)
        
        conn.close()
        
        if format_type == 'json':
            return jsonify(data)
        elif format_type == 'csv':
            df = pd.DataFrame(data)
            csv_data = df.to_csv(index=False)
            return csv_data, 200, {'Content-Type': 'text/csv'}
        else:
            return jsonify({'error': 'Unsupported format'}), 400
            
    except Exception as e:
        web_interface.logger.error(f"Error exporting data: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/health')
def health_check():
    """Health check endpoint"""
    try:
        health_status = {
            'status': 'healthy',
            'timestamp': datetime.now().isoformat(),
            'database': os.path.exists(web_interface.db_file),
            'uptime': time.time() - web_interface.start_time if hasattr(web_interface, 'start_time') else 0
        }
        
        return jsonify(health_status)
        
    except Exception as e:
        return jsonify({'status': 'unhealthy', 'error': str(e)}), 500

# Create templates directory and HTML template
def create_templates():
    """Create HTML templates for the web interface"""
    os.makedirs('templates', exist_ok=True)
    
    dashboard_html = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>P4 DPI Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
            text-align: center;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
        }
        .stat-number {
            font-size: 2em;
            font-weight: bold;
            color: #667eea;
        }
        .stat-label {
            color: #666;
            margin-top: 5px;
        }
        .chart-container {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        .table-container {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            overflow-x: auto;
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th, td {
            padding: 10px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #f8f9fa;
            font-weight: bold;
        }
        .suspicious {
            background-color: #ffebee;
            color: #c62828;
        }
        .normal {
            background-color: #e8f5e8;
            color: #2e7d32;
        }
        .refresh-btn {
            background: #667eea;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            margin: 10px 0;
        }
        .refresh-btn:hover {
            background: #5a6fd8;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>P4 Deep Packet Inspection Dashboard</h1>
            <p>Real-time Network Monitoring and Analysis</p>
        </div>
        
        <button class="refresh-btn" onclick="refreshData()">Refresh Data</button>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number" id="total-packets">0</div>
                <div class="stat-label">Total Packets</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="tcp-packets">0</div>
                <div class="stat-label">TCP Packets</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="udp-packets">0</div>
                <div class="stat-label">UDP Packets</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="suspicious-packets">0</div>
                <div class="stat-label">Suspicious Packets</div>
            </div>
        </div>
        
        <div class="chart-container">
            <h3>Protocol Distribution</h3>
            <canvas id="protocolChart" width="400" height="200"></canvas>
        </div>
        
        <div class="table-container">
            <h3>Recent Flows</h3>
            <table id="flows-table">
                <thead>
                    <tr>
                        <th>Source IP</th>
                        <th>Dest IP</th>
                        <th>Source Port</th>
                        <th>Dest Port</th>
                        <th>Protocol</th>
                        <th>Packets</th>
                        <th>Bytes</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody id="flows-tbody">
                </tbody>
            </table>
        </div>
    </div>

    <script>
        let protocolChart;
        
        function initChart() {
            const ctx = document.getElementById('protocolChart').getContext('2d');
            protocolChart = new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels: [],
                    datasets: [{
                        data: [],
                        backgroundColor: [
                            '#FF6384',
                            '#36A2EB',
                            '#FFCE56',
                            '#4BC0C0',
                            '#9966FF'
                        ]
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false
                }
            });
        }
        
        function updateStats(data) {
            if (data.packet_stats) {
                document.getElementById('total-packets').textContent = data.packet_stats.total_packets;
                document.getElementById('tcp-packets').textContent = data.packet_stats.tcp_packets;
                document.getElementById('udp-packets').textContent = data.packet_stats.udp_packets;
                document.getElementById('suspicious-packets').textContent = data.packet_stats.suspicious_packets;
            }
            
            if (data.top_protocols && protocolChart) {
                const labels = Object.keys(data.top_protocols);
                const values = Object.values(data.top_protocols);
                
                protocolChart.data.labels = labels;
                protocolChart.data.datasets[0].data = values;
                protocolChart.update();
            }
        }
        
        function updateFlowsTable(flows) {
            const tbody = document.getElementById('flows-tbody');
            tbody.innerHTML = '';
            
            flows.forEach(flow => {
                const row = document.createElement('tr');
                row.className = flow.is_suspicious ? 'suspicious' : 'normal';
                
                row.innerHTML = `
                    <td>${flow.src_ip}</td>
                    <td>${flow.dst_ip}</td>
                    <td>${flow.src_port}</td>
                    <td>${flow.dst_port}</td>
                    <td>${flow.protocol}</td>
                    <td>${flow.packet_count}</td>
                    <td>${flow.total_bytes}</td>
                    <td>${flow.is_suspicious ? 'Suspicious' : 'Normal'}</td>
                `;
                
                tbody.appendChild(row);
            });
        }
        
        async function fetchData() {
            try {
                const [statsResponse, flowsResponse] = await Promise.all([
                    fetch('/api/stats'),
                    fetch('/api/flows?limit=20')
                ]);
                
                const stats = await statsResponse.json();
                const flows = await flowsResponse.json();
                
                updateStats(stats);
                updateFlowsTable(flows);
                
            } catch (error) {
                console.error('Error fetching data:', error);
            }
        }
        
        function refreshData() {
            fetchData();
        }
        
        // Initialize chart and fetch initial data
        initChart();
        fetchData();
        
        // Auto-refresh every 5 seconds
        setInterval(fetchData, 5000);
    </script>
</body>
</html>
    '''
    
    with open('templates/dashboard.html', 'w') as f:
        f.write(dashboard_html)

def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='P4 DPI Web Interface')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=5000, help='Port to bind to')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    
    args = parser.parse_args()
    
    # Create templates
    create_templates()
    
    # Set start time for health check
    web_interface.start_time = time.time()
    
    # Start the web server
    web_interface.logger.info(f"Starting web interface on {args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=args.debug)

if __name__ == "__main__":
    main()
