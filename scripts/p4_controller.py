#!/usr/bin/env python3
"""
P4 DPI Controller - Control plane for Deep Packet Inspection
Handles P4Runtime communication, packet logging, and traffic analysis
"""

import json
import time
import logging
import threading
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import grpc
from p4.config.v1 import p4info_pb2
from p4runtime_sh.shell import setup as p4rt_setup, teardown as p4rt_teardown, TableEntry, FwdPipeConfig
import pandas as pd
import yaml
import os
import signal
import sys

class DPIController:
    def __init__(self, config_file: str = "config/dpi_config.yaml"):
        """Initialize the DPI Controller"""
        self.config = self.load_config(config_file)
        self.setup_logging()
        self.switches = {}
        self.packet_logs = []
        self.log_lock = threading.Lock()
        self.running = False
        
        # Statistics
        self.stats = {
            'total_packets': 0,
            'tcp_packets': 0,
            'udp_packets': 0,
            'icmp_packets': 0,
            'suspicious_packets': 0,
            'dropped_packets': 0,
            'protocols': {},
            'top_ports': {},
            'top_ips': {}
        }
        
        # Load P4 info
        self.p4info = self.load_p4info()
        
    def load_config(self, config_file: str) -> dict:
        """Load configuration from YAML file"""
        try:
            with open(config_file, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            # Default configuration
            return {
                'switches': [
                    {
                        'name': 's1',
                        'device_id': 1,
                        'grpc_port': 50051,
                        'cpu_port': 255
                    }
                ],
                'logging': {
                    'level': 'INFO',
                    'file': 'logs/dpi.log',
                    'max_size': 10485760,  # 10MB
                    'backup_count': 5
                },
                'monitoring': {
                    'enable_real_time': True,
                    'log_interval': 1,  # seconds
                    'stats_interval': 10  # seconds
                }
            }
    
    def setup_logging(self):
        """Setup logging configuration"""
        log_config = self.config.get('logging', {})
        
        # Create logs directory if it doesn't exist
        os.makedirs(os.path.dirname(log_config.get('file', 'logs/dpi.log')), exist_ok=True)
        
        # Configure logging
        logging.basicConfig(
            level=getattr(logging, log_config.get('level', 'INFO')),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_config.get('file', 'logs/dpi.log')),
                logging.StreamHandler()
            ]
        )
        
        self.logger = logging.getLogger('DPI_Controller')
        self.logger.info("DPI Controller initialized")
    
    def load_p4info(self):
        """Load P4Info from compiled P4 program"""
        try:
            with open('p4_programs/dpi_l2_l4.p4info.txt', 'r') as f:
                p4info = p4info_pb2.P4Info()
                from google.protobuf import text_format
                text_format.Parse(f.read(), p4info)
                return p4info
        except FileNotFoundError:
            self.logger.error("P4Info file not found. Please compile the P4 program first.")
            return None
    
    def connect_to_switch(self, switch_config: dict):
        """Connect to a P4 switch"""
        try:
            grpc_addr = f"127.0.0.1:{switch_config['grpc_port']}"
            device_id = switch_config.get('device_id', 1)
            self.logger.info(f"Connecting to switch '{switch_config['name']}' (device_id={device_id}) at {grpc_addr}")

            # Tear down any existing P4Runtime session to clear stale connections
            try:
                p4rt_teardown()
                self.logger.info("Cleaned up any previous P4Runtime session")
            except Exception:
                pass  # No existing session to tear down
            
            time.sleep(1)  # Brief pause after teardown

            # Resolve paths
            p4info_path = switch_config.get('p4info_file', 'p4_programs/dpi_l2_l4.p4info.txt')
            json_path = switch_config.get('runtime_json_file', 'p4_programs/dpi_l2_l4.json')
            if not os.path.exists(p4info_path):
                self.logger.error(f"p4info file missing: {p4info_path}")
                return
            if not os.path.exists(json_path):
                self.logger.error(f"BMv2 JSON file missing: {json_path}")
                return

            # gRPC readiness check
            import grpc
            channel = grpc.insecure_channel(grpc_addr)
            try:
                grpc.channel_ready_future(channel).result(timeout=5)
                self.logger.info("gRPC channel ready")
            except grpc.FutureTimeoutError:
                self.logger.error("gRPC channel timeout; switch not reachable yet")
                return

            # Prepare config with FILE PATHS (required by p4runtime_sh)
            cfg = FwdPipeConfig(p4info=p4info_path, bin=json_path)
            self.logger.info(f"Installing pipeline (p4info={p4info_path}, json={json_path})")
            try:
                p4rt_setup(
                    device_id=device_id,
                    grpc_addr=grpc_addr,
                    election_id=(0, 1),
                    config=cfg,
                    verbose=True
                )
                self.logger.info("✓ P4Runtime pipeline installed successfully")
            except Exception as setup_ex:
                import traceback
                self.logger.error(f"✗ Pipeline setup failed: {setup_ex}")
                self.logger.error(traceback.format_exc())
                return

            self.switches[switch_config['name']] = {
                'device_id': device_id,
                'grpc_addr': grpc_addr
            }
            self.logger.info(f"✓ Switch '{switch_config['name']}' fully operational with pipeline")

            # Install default table entries
            self.install_default_entries()

        except Exception as e:
            import traceback
            self.logger.error(f"Unhandled error connecting to switch '{switch_config.get('name','?')}': {e}")
            self.logger.error(traceback.format_exc())
    
    def install_default_entries(self):
        """Install default table entries for packet processing"""
        try:
            # Install entries in packet_classifier table
            self.install_packet_classifier_entries()
            
            # Install entries in protocol_filter table
            self.install_protocol_filter_entries()
            
            # Install entries in suspicious_detector table
            self.install_suspicious_detector_entries()
            
            self.logger.info("Default table entries installed successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to install default entries: {e}")
    
    def install_packet_classifier_entries(self):
        """Install entries in packet_classifier table"""
        self.logger.info("Skipping packet_classifier entries (no entries needed for default logging)")
    
    def install_protocol_filter_entries(self):
        """Install entries in protocol_filter table"""
        self.logger.info("Skipping protocol_filter entries (using default action)")
    
    def install_suspicious_detector_entries(self):
        """Install entries in suspicious_detector table"""
        self.logger.info("Skipping suspicious_detector entries (using default action)")
    
    def start_packet_monitoring(self):
        """Start monitoring packets from switches"""
        self.running = True
        
        # Start packet monitoring thread for each switch
        for switch_name, switch in self.switches.items():
            thread = threading.Thread(
                target=self.monitor_switch_packets,
                args=(switch_name, switch),
                daemon=True
            )
            thread.start()
        
        # Start statistics thread
        stats_thread = threading.Thread(target=self.update_statistics, daemon=True)
        stats_thread.start()
        
        self.logger.info("Packet monitoring started")
    
    def monitor_switch_packets(self, switch_name: str, switch):
        """Monitor packets from a specific switch"""
        try:
            # This would typically involve reading from a packet capture interface
            # For now, we'll simulate packet monitoring
            while self.running:
                # In a real implementation, this would read actual packet data
                # from the switch's packet capture interface
                time.sleep(0.1)
                
        except Exception as e:
            self.logger.error(f"Error monitoring switch {switch_name}: {e}")
    
    def log_packet(self, packet_data: dict):
        """Log packet information"""
        with self.log_lock:
            timestamp = datetime.now().isoformat()
            log_entry = {
                'timestamp': timestamp,
                'switch': packet_data.get('switch', 'unknown'),
                'src_mac': packet_data.get('src_mac', ''),
                'dst_mac': packet_data.get('dst_mac', ''),
                'src_ip': packet_data.get('src_ip', ''),
                'dst_ip': packet_data.get('dst_ip', ''),
                'src_port': packet_data.get('src_port', 0),
                'dst_port': packet_data.get('dst_port', 0),
                'protocol': packet_data.get('protocol', ''),
                'packet_size': packet_data.get('packet_size', 0),
                'tcp_flags': packet_data.get('tcp_flags', 0),
                'is_fragment': packet_data.get('is_fragment', False),
                'is_malformed': packet_data.get('is_malformed', False),
                'is_suspicious': packet_data.get('is_suspicious', False)
            }
            
            self.packet_logs.append(log_entry)
            
            # Update statistics
            self.update_packet_stats(log_entry)
            
            # Log to file
            self.logger.info(f"Packet: {log_entry}")
    
    def update_packet_stats(self, packet_data: dict):
        """Update packet statistics"""
        self.stats['total_packets'] += 1
        
        protocol = packet_data.get('protocol', '')
        if protocol == 'TCP':
            self.stats['tcp_packets'] += 1
        elif protocol == 'UDP':
            self.stats['udp_packets'] += 1
        elif protocol == 'ICMP':
            self.stats['icmp_packets'] += 1
        
        if packet_data.get('is_suspicious', False):
            self.stats['suspicious_packets'] += 1
        
        # Update protocol statistics
        if protocol in self.stats['protocols']:
            self.stats['protocols'][protocol] += 1
        else:
            self.stats['protocols'][protocol] = 1
        
        # Update port statistics
        dst_port = packet_data.get('dst_port', 0)
        if dst_port in self.stats['top_ports']:
            self.stats['top_ports'][dst_port] += 1
        else:
            self.stats['top_ports'][dst_port] = 1
        
        # Update IP statistics
        dst_ip = packet_data.get('dst_ip', '')
        if dst_ip in self.stats['top_ips']:
            self.stats['top_ips'][dst_ip] += 1
        else:
            self.stats['top_ips'][dst_ip] = 1
    
    def update_statistics(self):
        """Update and log statistics periodically"""
        while self.running:
            time.sleep(self.config.get('monitoring', {}).get('stats_interval', 10))
            
            if self.stats['total_packets'] > 0:
                self.logger.info(f"Statistics: {self.stats}")
                
                # Save statistics to file
                self.save_statistics()
    
    def save_statistics(self):
        """Save statistics to file"""
        try:
            with open('logs/statistics.json', 'w') as f:
                json.dump(self.stats, f, indent=2)
        except Exception as e:
            self.logger.error(f"Failed to save statistics: {e}")
    
    def export_logs(self, format: str = 'json') -> str:
        """Export packet logs in specified format"""
        with self.log_lock:
            if format == 'json':
                return json.dumps(self.packet_logs, indent=2)
            elif format == 'csv':
                df = pd.DataFrame(self.packet_logs)
                return df.to_csv(index=False)
            else:
                return str(self.packet_logs)
    
    def get_real_time_stats(self) -> dict:
        """Get real-time statistics"""
        return {
            'timestamp': datetime.now().isoformat(),
            'stats': self.stats,
            'active_switches': list(self.switches.keys()),
            'total_logs': len(self.packet_logs)
        }
    
    def stop(self):
        """Stop the controller"""
        self.running = False
        self.logger.info("DPI Controller stopped")
    
    def run(self):
        """Run the DPI controller"""
        try:
            # Connect to all switches
            for switch_config in self.config['switches']:
                self.connect_to_switch(switch_config)
            
            # Start packet monitoring
            self.start_packet_monitoring()
            
            # Keep running
            while self.running:
                time.sleep(1)
                
        except KeyboardInterrupt:
            self.logger.info("Received interrupt signal")
        except Exception as e:
            self.logger.error(f"Error in main loop: {e}")
        finally:
            self.stop()
            try:
                p4rt_teardown()
            except Exception:
                pass

def signal_handler(signum, frame):
    """Handle interrupt signals"""
    print("\nShutting down DPI Controller...")
    sys.exit(0)

if __name__ == "__main__":
    # Set up signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Create and run controller
    controller = DPIController()
    controller.run()
