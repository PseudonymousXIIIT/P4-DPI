#!/usr/bin/env python3
"""
Packet Logger for P4 DPI Tool
Handles detailed packet logging with timestamps, protocol analysis, and statistics
"""

import json
import time
import logging
import threading
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import pandas as pd
import numpy as np
from collections import defaultdict, Counter
import os
import csv
import sqlite3
from dataclasses import dataclass, asdict
import yaml
from scapy.all import sniff
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest

@dataclass
class PacketInfo:
    """Data class for packet information"""
    timestamp: str
    switch_id: str
    src_mac: str
    dst_mac: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    packet_size: int
    tcp_flags: int
    icmp_type: int
    icmp_code: int
    is_fragment: bool
    is_malformed: bool
    is_suspicious: bool
    layer2_protocol: str
    layer3_protocol: str
    layer4_protocol: str
    ttl: int
    tos: int
    flow_id: str

class PacketLogger:
    def __init__(self, config_file: str = "config/logging_config.yaml"):
        """Initialize the packet logger"""
        self.config = self.load_config(config_file)
        self.setup_logging()
        self.packets = []
        self.stats = defaultdict(int)
        self.flows = defaultdict(list)
        self.suspicious_flows = []
        self.lock = threading.Lock()
        
        # Database setup
        self.setup_database()
        
        # Start background tasks
        self.start_background_tasks()
    
    def load_config(self, config_file: str) -> dict:
        """Load logging configuration"""
        try:
            with open(config_file, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            return {
                'database': {
                    'enabled': True,
                    'file': 'logs/packets.db'
                },
                'export': {
                    'enabled': True,
                    'formats': ['json', 'csv', 'pcap'],
                    'interval': 300  # 5 minutes
                },
                'analysis': {
                    'enabled': True,
                    'flow_analysis': True,
                    'anomaly_detection': True,
                    'statistics_interval': 60
                },
                'retention': {
                    'max_packets': 100000,
                    'max_age_days': 7
                }
            }
    
    def setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('logs/packet_logger.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger('PacketLogger')
    
    def setup_database(self):
        """Setup SQLite database for packet storage"""
        if not self.config.get('database', {}).get('enabled', True):
            return
        
        db_file = self.config['database'].get('file', 'logs/packets.db')
        os.makedirs(os.path.dirname(db_file), exist_ok=True)
        
        self.conn = sqlite3.connect(db_file, check_same_thread=False)
        self.cursor = self.conn.cursor()
        
        # Create packets table
        self.cursor.execute('''
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
                tcp_flags INTEGER,
                icmp_type INTEGER,
                icmp_code INTEGER,
                is_fragment BOOLEAN,
                is_malformed BOOLEAN,
                is_suspicious BOOLEAN,
                layer2_protocol TEXT,
                layer3_protocol TEXT,
                layer4_protocol TEXT,
                ttl INTEGER,
                tos INTEGER,
                flow_id TEXT
            )
        ''')
        
        # Create flows table
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS flows (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                flow_id TEXT UNIQUE,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT,
                start_time TEXT,
                end_time TEXT,
                packet_count INTEGER,
                total_bytes INTEGER,
                is_suspicious BOOLEAN
            )
        ''')
        
        # Create statistics table
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS statistics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                total_packets INTEGER,
                tcp_packets INTEGER,
                udp_packets INTEGER,
                icmp_packets INTEGER,
                suspicious_packets INTEGER,
                top_protocols TEXT,
                top_ports TEXT,
                top_ips TEXT
            )
        ''')
        
        self.conn.commit()
        self.logger.info("Database setup completed")
    
    def log_packet(self, packet_data: dict):
        """Log a packet with detailed information"""
        try:
            # Create packet info object
            packet_info = PacketInfo(
                timestamp=datetime.now().isoformat(),
                switch_id=packet_data.get('switch_id', 'unknown'),
                src_mac=packet_data.get('src_mac', ''),
                dst_mac=packet_data.get('dst_mac', ''),
                src_ip=packet_data.get('src_ip', ''),
                dst_ip=packet_data.get('dst_ip', ''),
                src_port=packet_data.get('src_port', 0),
                dst_port=packet_data.get('dst_port', 0),
                protocol=packet_data.get('protocol', ''),
                packet_size=packet_data.get('packet_size', 0),
                tcp_flags=packet_data.get('tcp_flags', 0),
                icmp_type=packet_data.get('icmp_type', 0),
                icmp_code=packet_data.get('icmp_code', 0),
                is_fragment=packet_data.get('is_fragment', False),
                is_malformed=packet_data.get('is_malformed', False),
                is_suspicious=packet_data.get('is_suspicious', False),
                layer2_protocol=packet_data.get('layer2_protocol', ''),
                layer3_protocol=packet_data.get('layer3_protocol', ''),
                layer4_protocol=packet_data.get('layer4_protocol', ''),
                ttl=packet_data.get('ttl', 0),
                tos=packet_data.get('tos', 0),
                flow_id=self.generate_flow_id(packet_data)
            )
            
            with self.lock:
                # Add to memory
                self.packets.append(packet_info)
                
                # Update statistics
                self.update_statistics(packet_info)
                
                # Update flows
                self.update_flows(packet_info)
                
                # Check for anomalies
                if self.config.get('analysis', {}).get('anomaly_detection', True):
                    self.detect_anomalies(packet_info)
                
                # Store in database
                if self.config.get('database', {}).get('enabled', True):
                    self.store_packet_db(packet_info)
                
                # Log to file
                self.logger.info(f"Packet logged: {packet_info.src_ip}:{packet_info.src_port} -> "
                               f"{packet_info.dst_ip}:{packet_info.dst_port} "
                               f"({packet_info.protocol})")
            
        except Exception as e:
            self.logger.error(f"Error logging packet: {e}")
    
    def generate_flow_id(self, packet_data: dict) -> str:
        """Generate a unique flow ID for the packet"""
        src_ip = packet_data.get('src_ip', '')
        dst_ip = packet_data.get('dst_ip', '')
        src_port = packet_data.get('src_port', 0)
        dst_port = packet_data.get('dst_port', 0)
        protocol = packet_data.get('protocol', '')
        
        # Create bidirectional flow ID
        if src_ip < dst_ip:
            flow_id = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
        else:
            flow_id = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{protocol}"
        
        return flow_id
    
    def update_statistics(self, packet_info: PacketInfo):
        """Update packet statistics"""
        self.stats['total_packets'] += 1
        self.stats[f'{packet_info.protocol.lower()}_packets'] += 1
        
        if packet_info.is_suspicious:
            self.stats['suspicious_packets'] += 1
        
        if packet_info.is_fragment:
            self.stats['fragmented_packets'] += 1
        
        if packet_info.is_malformed:
            self.stats['malformed_packets'] += 1
        
        # Update protocol statistics
        self.stats[f'protocol_{packet_info.protocol.lower()}'] += 1
        
        # Update port statistics
        self.stats[f'port_{packet_info.dst_port}'] += 1
        
        # Update IP statistics
        self.stats[f'ip_{packet_info.dst_ip}'] += 1
    
    def update_flows(self, packet_info: PacketInfo):
        """Update flow information"""
        flow_id = packet_info.flow_id
        
        if flow_id not in self.flows:
            self.flows[flow_id] = {
                'src_ip': packet_info.src_ip,
                'dst_ip': packet_info.dst_ip,
                'src_port': packet_info.src_port,
                'dst_port': packet_info.dst_port,
                'protocol': packet_info.protocol,
                'start_time': packet_info.timestamp,
                'end_time': packet_info.timestamp,
                'packet_count': 0,
                'total_bytes': 0,
                'is_suspicious': False
            }
        
        flow = self.flows[flow_id]
        flow['end_time'] = packet_info.timestamp
        flow['packet_count'] += 1
        flow['total_bytes'] += packet_info.packet_size
        
        if packet_info.is_suspicious:
            flow['is_suspicious'] = True
    
    def detect_anomalies(self, packet_info: PacketInfo):
        """Detect anomalous packet patterns"""
        # Check for port scanning
        if self.detect_port_scanning(packet_info):
            packet_info.is_suspicious = True
        
        # Check for DDoS patterns
        if self.detect_ddos(packet_info):
            packet_info.is_suspicious = True
        
        # Check for unusual protocols
        if self.detect_unusual_protocols(packet_info):
            packet_info.is_suspicious = True
    
    def detect_port_scanning(self, packet_info: PacketInfo) -> bool:
        """Detect port scanning patterns"""
        # Simple port scanning detection
        # In a real implementation, this would be more sophisticated
        src_ip = packet_info.src_ip
        current_time = time.time()
        
        # Count unique destination ports from same source IP in last minute
        recent_packets = [p for p in self.packets[-1000:] 
                         if p.src_ip == src_ip and 
                         (current_time - datetime.fromisoformat(p.timestamp).timestamp()) < 60]
        
        unique_ports = set(p.dst_port for p in recent_packets)
        
        # If more than 10 unique ports in last minute, flag as suspicious
        return len(unique_ports) > 10
    
    def detect_ddos(self, packet_info: PacketInfo) -> bool:
        """Detect DDoS attack patterns"""
        # Simple DDoS detection
        dst_ip = packet_info.dst_ip
        current_time = time.time()
        
        # Count packets to same destination in last second
        recent_packets = [p for p in self.packets[-1000:] 
                         if p.dst_ip == dst_ip and 
                         (current_time - datetime.fromisoformat(p.timestamp).timestamp()) < 1]
        
        # If more than 100 packets per second to same destination, flag as suspicious
        return len(recent_packets) > 100
    
    def detect_unusual_protocols(self, packet_info: PacketInfo) -> bool:
        """Detect unusual protocol usage"""
        # Check for uncommon protocols on common ports
        unusual_combinations = {
            (80, 'UDP'): True,    # UDP on HTTP port
            (443, 'UDP'): True,   # UDP on HTTPS port
            (22, 'UDP'): True,    # UDP on SSH port
        }
        
        return unusual_combinations.get((packet_info.dst_port, packet_info.protocol), False)
    
    def store_packet_db(self, packet_info: PacketInfo):
        """Store packet information in database"""
        try:
            self.cursor.execute('''
                INSERT INTO packets (
                    timestamp, switch_id, src_mac, dst_mac, src_ip, dst_ip,
                    src_port, dst_port, protocol, packet_size, tcp_flags,
                    icmp_type, icmp_code, is_fragment, is_malformed, is_suspicious,
                    layer2_protocol, layer3_protocol, layer4_protocol, ttl, tos, flow_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                packet_info.timestamp, packet_info.switch_id, packet_info.src_mac,
                packet_info.dst_mac, packet_info.src_ip, packet_info.dst_ip,
                packet_info.src_port, packet_info.dst_port, packet_info.protocol,
                packet_info.packet_size, packet_info.tcp_flags, packet_info.icmp_type,
                packet_info.icmp_code, packet_info.is_fragment, packet_info.is_malformed,
                packet_info.is_suspicious, packet_info.layer2_protocol,
                packet_info.layer3_protocol, packet_info.layer4_protocol,
                packet_info.ttl, packet_info.tos, packet_info.flow_id
            ))
            
            # Update flows table
            flow = self.flows[packet_info.flow_id]
            self.cursor.execute('''
                INSERT OR REPLACE INTO flows (
                    flow_id, src_ip, dst_ip, src_port, dst_port, protocol,
                    start_time, end_time, packet_count, total_bytes, is_suspicious
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                packet_info.flow_id, flow['src_ip'], flow['dst_ip'],
                flow['src_port'], flow['dst_port'], flow['protocol'],
                flow['start_time'], flow['end_time'], flow['packet_count'],
                flow['total_bytes'], flow['is_suspicious']
            ))
            
            self.conn.commit()
            
        except Exception as e:
            self.logger.error(f"Error storing packet in database: {e}")
    
    def start_background_tasks(self):
        """Start background tasks for data management"""
        # Statistics update task
        stats_thread = threading.Thread(target=self.update_statistics_periodic, daemon=True)
        stats_thread.start()
        
        # Data export task
        if self.config.get('export', {}).get('enabled', True):
            export_thread = threading.Thread(target=self.export_data_periodic, daemon=True)
            export_thread.start()
        
        # Data cleanup task
        cleanup_thread = threading.Thread(target=self.cleanup_old_data, daemon=True)
        cleanup_thread.start()

        # Passive sniffers to capture real traffic from Mininet interfaces
        sniff_cfg = self.config.get('sniffing', {})
        enable_sniffing = sniff_cfg.get('enabled', True)
        if enable_sniffing:
            try:
                interfaces = sniff_cfg.get('interfaces')
                if not interfaces:
                    interfaces = self.detect_sniff_interfaces()
                if interfaces:
                    self.logger.info(f"Starting sniffers on interfaces: {interfaces}")
                    for iface in interfaces:
                        t = threading.Thread(target=self._sniff_on_interface, args=(iface,), daemon=True)
                        t.start()
                else:
                    self.logger.warning("No interfaces detected for sniffing; packet DB may remain empty")
            except Exception as e:
                self.logger.error(f"Failed to start sniffers: {e}")

    def detect_sniff_interfaces(self) -> List[str]:
        """Auto-detect Mininet interfaces to sniff (all s*-eth* and h*-eth*)."""
        candidates = []
        try:
            for name in os.listdir('/sys/class/net'):
                if ((name.startswith('s') or name.startswith('h')) and '-eth' in name):
                    candidates.append(name)
        except Exception:
            pass
        return candidates

    def _sniff_on_interface(self, iface: str):
        """Sniff packets on a given interface and log them via PacketLogger."""
        try:
            sniff(iface=iface, prn=self._handle_scapy_packet, store=False)
        except Exception as e:
            self.logger.error(f"Sniffer error on {iface}: {e}")

    def _handle_scapy_packet(self, pkt):
        """Convert a Scapy packet to our packet_data dict and log it."""
        try:
            layer2_protocol = 'Ethernet' if pkt.haslayer(Ether) else ''
            src_mac = pkt[Ether].src if pkt.haslayer(Ether) else ''
            dst_mac = pkt[Ether].dst if pkt.haslayer(Ether) else ''

            protocol = ''
            src_ip = ''
            dst_ip = ''
            src_port = 0
            dst_port = 0
            ttl = 0
            tos = 0
            layer3_protocol = ''
            layer4_protocol = ''
            icmp_type = 0
            icmp_code = 0

            if pkt.haslayer(IP):
                ip = pkt[IP]
                src_ip = ip.src
                dst_ip = ip.dst
                ttl = int(getattr(ip, 'ttl', 0) or 0)
                tos = int(getattr(ip, 'tos', 0) or 0)
                layer3_protocol = 'IPv4'
                if pkt.haslayer(TCP):
                    t = pkt[TCP]
                    protocol = 'TCP'
                    layer4_protocol = 'TCP'
                    src_port = int(t.sport)
                    dst_port = int(t.dport)
                elif pkt.haslayer(UDP):
                    u = pkt[UDP]
                    protocol = 'UDP'
                    layer4_protocol = 'UDP'
                    src_port = int(u.sport)
                    dst_port = int(u.dport)
                elif pkt.haslayer(ICMP):
                    ic = pkt[ICMP]
                    protocol = 'ICMP'
                    layer4_protocol = 'ICMP'
                    icmp_type = int(getattr(ic, 'type', 0) or 0)
                    icmp_code = int(getattr(ic, 'code', 0) or 0)
            elif pkt.haslayer(IPv6):
                ip6 = pkt[IPv6]
                src_ip = ip6.src
                dst_ip = ip6.dst
                # Hop limit is akin to TTL; not stored for now
                layer3_protocol = 'IPv6'
                if pkt.haslayer(TCP):
                    t = pkt[TCP]
                    protocol = 'TCP'
                    layer4_protocol = 'TCP'
                    src_port = int(t.sport)
                    dst_port = int(t.dport)
                elif pkt.haslayer(UDP):
                    u = pkt[UDP]
                    protocol = 'UDP'
                    layer4_protocol = 'UDP'
                    src_port = int(u.sport)
                    dst_port = int(u.dport)
                elif pkt.haslayer(ICMPv6EchoRequest):
                    protocol = 'ICMP'
                    layer4_protocol = 'ICMP'

            packet_data = {
                'switch_id': self._infer_switch_from_iface(pkt.sniffed_on) if hasattr(pkt, 'sniffed_on') else 's1',
                'src_mac': src_mac,
                'dst_mac': dst_mac,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'protocol': protocol,
                'packet_size': len(pkt) if hasattr(pkt, '__len__') else 0,
                'tcp_flags': int(getattr(pkt[TCP], 'flags', 0)) if pkt.haslayer(TCP) else 0,
                'icmp_type': icmp_type,
                'icmp_code': icmp_code,
                'is_fragment': False,
                'is_malformed': False,
                'is_suspicious': False,
                'layer2_protocol': layer2_protocol,
                'layer3_protocol': layer3_protocol,
                'layer4_protocol': layer4_protocol,
                'ttl': ttl,
                'tos': tos,
            }
            # Only log if we have at least L3 info
            if protocol or layer3_protocol:
                self.log_packet(packet_data)
        except Exception as e:
            self.logger.error(f"Error handling sniffed packet: {e}")

    def _infer_switch_from_iface(self, iface: Optional[str]) -> str:
        if not iface:
            return 's1'
        # Example: s1-eth2 -> s1
        parts = iface.split('-')
        return parts[0] if parts else 's1'
    
    def update_statistics_periodic(self):
        """Update statistics periodically"""
        while True:
            time.sleep(self.config.get('analysis', {}).get('statistics_interval', 60))
            
            try:
                self.store_statistics_db()
                self.logger.info(f"Statistics updated: {dict(self.stats)}")
            except Exception as e:
                self.logger.error(f"Error updating statistics: {e}")
    
    def store_statistics_db(self):
        """Store statistics in database"""
        try:
            # Get top protocols, ports, and IPs
            top_protocols = dict(Counter({k: v for k, v in self.stats.items() 
                                        if k.startswith('protocol_')}).most_common(10))
            top_ports = dict(Counter({k: v for k, v in self.stats.items() 
                                    if k.startswith('port_')}).most_common(10))
            top_ips = dict(Counter({k: v for k, v in self.stats.items() 
                                  if k.startswith('ip_')}).most_common(10))
            
            self.cursor.execute('''
                INSERT INTO statistics (
                    timestamp, total_packets, tcp_packets, udp_packets, icmp_packets,
                    suspicious_packets, top_protocols, top_ports, top_ips
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                datetime.now().isoformat(),
                self.stats['total_packets'],
                self.stats.get('protocol_tcp', 0),
                self.stats.get('protocol_udp', 0),
                self.stats.get('protocol_icmp', 0),
                self.stats['suspicious_packets'],
                json.dumps(top_protocols),
                json.dumps(top_ports),
                json.dumps(top_ips)
            ))
            
            self.conn.commit()
            
        except Exception as e:
            self.logger.error(f"Error storing statistics: {e}")
    
    def export_data_periodic(self):
        """Export data periodically"""
        while True:
            time.sleep(self.config.get('export', {}).get('interval', 300))
            
            try:
                self.export_data()
            except Exception as e:
                self.logger.error(f"Error exporting data: {e}")
    
    def export_data(self, formats: List[str] = None):
        """Export packet data in various formats"""
        if formats is None:
            formats = self.config.get('export', {}).get('formats', ['json', 'csv'])
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        with self.lock:
            packets_data = [asdict(packet) for packet in self.packets]
        
        for format_type in formats:
            try:
                if format_type == 'json':
                    filename = f'logs/packets_export_{timestamp}.json'
                    with open(filename, 'w') as f:
                        json.dump(packets_data, f, indent=2)
                
                elif format_type == 'csv':
                    filename = f'logs/packets_export_{timestamp}.csv'
                    df = pd.DataFrame(packets_data)
                    df.to_csv(filename, index=False)
                
                self.logger.info(f"Data exported to {filename}")
                
            except Exception as e:
                self.logger.error(f"Error exporting {format_type}: {e}")
    
    def cleanup_old_data(self):
        """Clean up old data based on retention policy"""
        while True:
            time.sleep(3600)  # Run every hour
            
            try:
                max_packets = self.config.get('retention', {}).get('max_packets', 100000)
                max_age_days = self.config.get('retention', {}).get('max_age_days', 7)
                
                # Clean up old packets from memory
                if len(self.packets) > max_packets:
                    with self.lock:
                        self.packets = self.packets[-max_packets:]
                
                # Clean up old database entries
                cutoff_date = datetime.now().timestamp() - (max_age_days * 24 * 3600)
                self.cursor.execute('DELETE FROM packets WHERE timestamp < ?', 
                                  (datetime.fromtimestamp(cutoff_date).isoformat(),))
                self.conn.commit()
                
                self.logger.info("Old data cleanup completed")
                
            except Exception as e:
                self.logger.error(f"Error during cleanup: {e}")
    
    def get_statistics(self) -> dict:
        """Get current statistics"""
        with self.lock:
            return dict(self.stats)
    
    def get_flows(self) -> dict:
        """Get current flows"""
        with self.lock:
            return dict(self.flows)
    
    def get_suspicious_flows(self) -> List[dict]:
        """Get suspicious flows"""
        with self.lock:
            return [flow for flow in self.flows.values() if flow['is_suspicious']]
    
    def close(self):
        """Close the logger and database connections"""
        if hasattr(self, 'conn'):
            self.conn.close()
        self.logger.info("Packet logger closed")

if __name__ == "__main__":
    # Test the packet logger
    logger = PacketLogger()
    
    # Simulate some packets
    test_packets = [
        {
            'switch_id': 's1',
            'src_mac': '00:00:00:00:00:01',
            'dst_mac': '00:00:00:00:00:02',
            'src_ip': '10.0.1.1',
            'dst_ip': '10.0.2.1',
            'src_port': 12345,
            'dst_port': 80,
            'protocol': 'TCP',
            'packet_size': 64,
            'tcp_flags': 2,
            'layer2_protocol': 'Ethernet',
            'layer3_protocol': 'IPv4',
            'layer4_protocol': 'TCP'
        },
        {
            'switch_id': 's1',
            'src_mac': '00:00:00:00:00:02',
            'dst_mac': '00:00:00:00:00:01',
            'src_ip': '10.0.2.1',
            'dst_ip': '10.0.1.1',
            'src_port': 80,
            'dst_port': 12345,
            'protocol': 'TCP',
            'packet_size': 128,
            'tcp_flags': 18,
            'layer2_protocol': 'Ethernet',
            'layer3_protocol': 'IPv4',
            'layer4_protocol': 'TCP'
        }
    ]
    
    for packet in test_packets:
        logger.log_packet(packet)
        time.sleep(0.1)
    
    # Print statistics
    print("Statistics:", logger.get_statistics())
    print("Flows:", logger.get_flows())
    
    # Export data
    logger.export_data(['json', 'csv'])
    
    logger.close()
