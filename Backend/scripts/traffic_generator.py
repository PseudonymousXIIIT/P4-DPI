#!/usr/bin/env python3
"""
Traffic Generator for P4 DPI Tool
Generates various types of network traffic for testing DPI capabilities
"""

import time
import random
import threading
import logging
from datetime import datetime
from typing import Dict, List, Optional
import socket
import struct
import subprocess
import os
import sys
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest
from scapy.layers.l2 import Ether, ARP
import yaml

class TrafficGenerator:
    def __init__(self, config_file: str = "config/traffic_config.yaml", mininet_net=None):
        """Initialize the traffic generator"""
        self.config = self.load_config(config_file)
        self.setup_logging()
        self.running = False
        self.threads = []
        self.mininet_net = mininet_net
        self.mininet_lock = threading.Lock()  # Lock for thread-safe Mininet access
        
        # Network configuration
        self.src_ips = self.config.get('src_ips', ['10.0.1.1', '10.0.1.2', '10.0.3.1'])
        self.dst_ips = self.config.get('dst_ips', ['10.0.2.1', '10.0.2.2'])
        self.src_ports = self.config.get('src_ports', list(range(1024, 65535)))
        self.dst_ports = self.config.get('dst_ports', [80, 443, 22, 53, 21, 25, 110, 143])
        
        # Traffic patterns
        self.traffic_patterns = self.config.get('patterns', {})
        
    def load_config(self, config_file: str) -> dict:
        """Load traffic generation configuration"""
        try:
            with open(config_file, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            return {
                'src_ips': ['10.0.1.1', '10.0.1.2', '10.0.3.1'],
                'dst_ips': ['10.0.2.1', '10.0.2.2'],
                'src_ports': list(range(1024, 65535)),
                'dst_ports': [80, 443, 22, 53, 21, 25, 110, 143],
                'patterns': {
                    'normal_traffic': {
                        'enabled': True,
                        'rate': 2,  # packets per second
                        'duration': 300  # seconds
                    },
                    'http_traffic': {
                        'enabled': True,
                        'rate': 1,
                        'duration': 300
                    },
                    'dns_traffic': {
                        'enabled': True,
                        'rate': 1,
                        'duration': 300
                    },
                    'ping_traffic': {
                        'enabled': True,  # Re-enabled with socket-based ICMP
                        'rate': 1,
                        'duration': 300
                    },
                    'port_scan': {
                        'enabled': False,  # Disable aggressive patterns
                        'rate': 5,
                        'duration': 60
                    },
                    'ddos_attack': {
                        'enabled': False,  # Disable aggressive patterns
                        'rate': 10,
                        'duration': 30
                    }
                }
            }
    
    def setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('logs/traffic_generator.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger('TrafficGenerator')
    
    def start_traffic_generation(self):
        """Start all traffic generation patterns"""
        self.running = True
        self.logger.info("Starting traffic generation")
        
        # Start each traffic pattern
        for pattern_name, pattern_config in self.traffic_patterns.items():
            if pattern_config.get('enabled', False):
                thread = threading.Thread(
                    target=self.run_traffic_pattern,
                    args=(pattern_name, pattern_config),
                    daemon=True
                )
                thread.start()
                self.threads.append(thread)
                self.logger.info(f"Started {pattern_name} traffic pattern")
        
        # Wait for all threads to complete
        for thread in self.threads:
            thread.join()
    
    def run_traffic_pattern(self, pattern_name: str, config: dict):
        """Run a specific traffic pattern"""
        rate = config.get('rate', 1)
        duration = config.get('duration', 60)
        interval = max(0.1, 1.0 / rate)  # Minimum 0.1 second interval
        
        start_time = time.time()
        packet_count = 0
        error_count = 0
        
        while self.running and (time.time() - start_time) < duration:
            try:
                if pattern_name == 'normal_traffic':
                    self.generate_normal_traffic()
                elif pattern_name == 'http_traffic':
                    self.generate_http_traffic()
                elif pattern_name == 'dns_traffic':
                    self.generate_dns_traffic()
                elif pattern_name == 'ping_traffic':
                    self.generate_ping_traffic()
                elif pattern_name == 'port_scan':
                    self.generate_port_scan()
                elif pattern_name == 'ddos_attack':
                    self.generate_ddos_attack()
                
                packet_count += 1
                time.sleep(interval)
                
            except Exception as e:
                error_count += 1
                if error_count % 10 == 0:  # Log every 10th error to avoid spam
                    self.logger.error(f"Error in {pattern_name}: {e}")
        
        self.logger.info(f"Completed {pattern_name}: {packet_count} packets generated, {error_count} errors")
    
    def generate_normal_traffic(self):
        """Generate normal network traffic"""
        if self.mininet_net:
            # Use Mininet hosts to generate real traffic
            src_host = random.choice(['h1', 'h2', 'h5'])
            dst_host = random.choice(['h3', 'h4'])
            protocol = random.choice(['TCP', 'UDP'])
            dst_port = random.choice(self.dst_ports)
            try:
                with self.mininet_lock:
                    h_src = self.mininet_net.get(src_host)
                    h_dst = self.mininet_net.get(dst_host)
                    if h_src and h_dst:
                        dst_ip = h_dst.IP()
                        if protocol == 'TCP':
                            h_src.cmd(f'timeout 1 nc -zv {dst_ip} {dst_port} > /dev/null 2>&1 &')
                        else:
                            h_src.cmd(f'echo "test" | timeout 1 nc -u {dst_ip} {dst_port} > /dev/null 2>&1 &')
                        self.logger.debug(f"Sent {protocol} traffic from {src_host} to {dst_host}:{dst_port}")
            except Exception as e:
                self.logger.error(f"Error in Mininet traffic generation: {e}")
        else:
            src_ip = random.choice(self.src_ips)
            dst_ip = random.choice(self.dst_ips)
            src_port = random.choice(self.src_ports)
            dst_port = random.choice(self.dst_ports)
            protocol = random.choice(['TCP', 'UDP'])
            if protocol == 'TCP':
                self.send_tcp_packet(src_ip, dst_ip, src_port, dst_port)
            else:
                self.send_udp_packet(src_ip, dst_ip, src_port, dst_port)
    
    def generate_http_traffic(self):
        """Generate HTTP traffic"""
        if self.mininet_net:
            # Use Mininet hosts to generate real HTTP traffic
            src_host = random.choice(['h1', 'h2', 'h5'])
            dst_host = random.choice(['h3', 'h4'])
            try:
                with self.mininet_lock:
                    h_src = self.mininet_net.get(src_host)
                    h_dst = self.mininet_net.get(dst_host)
                    if h_src and h_dst:
                        dst_ip = h_dst.IP()
                        # Try HTTP connection
                        h_src.cmd(f'timeout 1 nc -zv {dst_ip} 80 > /dev/null 2>&1 &')
                        self.logger.debug(f"Sent HTTP traffic from {src_host} to {dst_host}")
            except Exception as e:
                self.logger.error(f"Error in Mininet HTTP traffic: {e}")
        else:
            src_ip = random.choice(self.src_ips)
            dst_ip = random.choice(self.dst_ips)
            src_port = random.choice(self.src_ports)
            # HTTP request
            self.send_tcp_packet(src_ip, dst_ip, src_port, 80)
            # HTTPS request
            self.send_tcp_packet(src_ip, dst_ip, src_port, 443)
    
    def generate_dns_traffic(self):
        """Generate DNS traffic"""
        if self.mininet_net:
            # Use Mininet hosts to generate real DNS traffic
            src_host = random.choice(['h1', 'h2', 'h5'])
            dst_host = random.choice(['h3', 'h4'])
            try:
                with self.mininet_lock:
                    h_src = self.mininet_net.get(src_host)
                    h_dst = self.mininet_net.get(dst_host)
                    if h_src and h_dst:
                        dst_ip = h_dst.IP()
                        # Send UDP to port 53 using nc
                        h_src.cmd(f'echo "test" | timeout 1 nc -u {dst_ip} 53 > /dev/null 2>&1 &')
                        self.logger.debug(f"Sent DNS traffic from {src_host} to {dst_host}")
            except Exception as e:
                self.logger.error(f"Error in Mininet DNS traffic: {e}")
        else:
            src_ip = random.choice(self.src_ips)
            dst_ip = random.choice(self.dst_ips)
            src_port = random.choice(self.src_ports)
            # DNS query
            self.send_udp_packet(src_ip, dst_ip, src_port, 53)
    
    def generate_ping_traffic(self):
        """Generate ICMP ping traffic"""
        if self.mininet_net:
            # Use Mininet hosts to generate real traffic
            hosts = ['h1', 'h2', 'h3', 'h4', 'h5']
            src_host = random.choice(['h1', 'h2', 'h5'])
            dst_host = random.choice(['h3', 'h4'])
            try:
                with self.mininet_lock:
                    h_src = self.mininet_net.get(src_host)
                    h_dst = self.mininet_net.get(dst_host)
                    if h_src and h_dst:
                        dst_ip = h_dst.IP()
                        h_src.cmd(f'ping -c 1 -W 1 {dst_ip} > /dev/null 2>&1 &')
                        self.logger.debug(f"Sent ping from {src_host} to {dst_host} ({dst_ip})")
            except Exception as e:
                self.logger.error(f"Error in Mininet ping: {e}")
        else:
            src_ip = random.choice(self.src_ips)
            dst_ip = random.choice(self.dst_ips)
            self.send_icmp_packet(src_ip, dst_ip)
    
    def generate_port_scan(self):
        """Generate port scanning traffic (suspicious)"""
        src_ip = random.choice(self.src_ips)
        dst_ip = random.choice(self.dst_ips)
        src_port = random.choice(self.src_ports)
        
        # Scan multiple ports
        for port in random.sample(self.dst_ports, min(5, len(self.dst_ports))):
            self.send_tcp_packet(src_ip, dst_ip, src_port, port)
    
    def generate_ddos_attack(self):
        """Generate DDoS attack traffic (suspicious)"""
        dst_ip = random.choice(self.dst_ips)
        dst_port = random.choice(self.dst_ports)
        
        # Multiple sources attacking same destination
        for _ in range(10):
            src_ip = f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
            src_port = random.choice(self.src_ports)
            self.send_tcp_packet(src_ip, dst_ip, src_port, dst_port)
    
    def send_tcp_packet(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int):
        """Send a TCP packet"""
        try:
            # Use socket-based approach instead of raw packets
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            
            # Try to connect (this will generate TCP traffic)
            result = sock.connect_ex((dst_ip, dst_port))
            sock.close()
            
            # Log the attempt (connection may fail, but traffic is generated)
            self.logger.debug(f"TCP connection attempt: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
            
        except Exception as e:
            self.logger.error(f"Error sending TCP packet: {e}")
    
    def send_udp_packet(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int):
        """Send a UDP packet"""
        try:
            # Use socket-based approach for UDP
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1)
            
            # Send UDP data
            message = f"UDP test from {src_ip}:{src_port}"
            sock.sendto(message.encode(), (dst_ip, dst_port))
            sock.close()
            
            self.logger.debug(f"Sent UDP packet: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
            
        except Exception as e:
            self.logger.error(f"Error sending UDP packet: {e}")
    
    def send_icmp_packet(self, src_ip: str, dst_ip: str):
        """Send an ICMP packet"""
        try:
            # Use ping command for ICMP with full path
            ping_path = '/usr/bin/ping'
            result = subprocess.run([ping_path, '-c', '1', '-W', '1', dst_ip], 
                                  capture_output=True, text=True, timeout=2)
            
            if result.returncode == 0:
                self.logger.debug(f"Sent ICMP packet: {src_ip} -> {dst_ip}")
            else:
                self.logger.debug(f"ICMP ping attempt: {src_ip} -> {dst_ip}")
            
        except Exception as e:
            self.logger.error(f"Error sending ICMP packet: {e}")
    
    def stop_traffic_generation(self):
        """Stop traffic generation"""
        self.running = False
        self.logger.info("Stopping traffic generation")
    
    def generate_custom_traffic(self, traffic_config: dict):
        """Generate custom traffic based on configuration"""
        src_ip = traffic_config.get('src_ip', random.choice(self.src_ips))
        dst_ip = traffic_config.get('dst_ip', random.choice(self.dst_ips))
        src_port = traffic_config.get('src_port', random.choice(self.src_ports))
        dst_port = traffic_config.get('dst_port', random.choice(self.dst_ports))
        protocol = traffic_config.get('protocol', 'TCP')
        count = traffic_config.get('count', 1)
        interval = traffic_config.get('interval', 1.0)
        
        for _ in range(count):
            if protocol.upper() == 'TCP':
                self.send_tcp_packet(src_ip, dst_ip, src_port, dst_port)
            elif protocol.upper() == 'UDP':
                self.send_udp_packet(src_ip, dst_ip, src_port, dst_port)
            elif protocol.upper() == 'ICMP':
                self.send_icmp_packet(src_ip, dst_ip)
            
            time.sleep(interval)

class NetworkTester:
    def __init__(self):
        """Initialize the network tester"""
        self.setup_logging()
    
    def setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('logs/network_tester.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger('NetworkTester')
    
    def test_connectivity(self, src_host: str, dst_host: str) -> bool:
        """Test connectivity between two hosts"""
        try:
            # Ping test
            result = subprocess.run(['ping', '-c', '1', dst_host], 
                                  capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                self.logger.info(f"Connectivity test passed: {src_host} -> {dst_host}")
                return True
            else:
                self.logger.warning(f"Connectivity test failed: {src_host} -> {dst_host}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error testing connectivity: {e}")
            return False
    
    def test_port_connectivity(self, host: str, port: int, protocol: str = 'tcp') -> bool:
        """Test port connectivity"""
        try:
            if protocol.lower() == 'tcp':
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                result = sock.connect_ex((host, port))
                sock.close()
                
                if result == 0:
                    self.logger.info(f"Port test passed: {host}:{port} ({protocol})")
                    return True
                else:
                    self.logger.warning(f"Port test failed: {host}:{port} ({protocol})")
                    return False
                    
            elif protocol.lower() == 'udp':
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(5)
                try:
                    sock.sendto(b'test', (host, port))
                    sock.close()
                    self.logger.info(f"UDP port test: {host}:{port}")
                    return True
                except:
                    sock.close()
                    return False
                    
        except Exception as e:
            self.logger.error(f"Error testing port connectivity: {e}")
            return False
    
    def run_comprehensive_test(self, hosts: List[str], ports: List[int]):
        """Run comprehensive network tests"""
        self.logger.info("Starting comprehensive network test")
        
        results = {
            'connectivity': {},
            'ports': {},
            'timestamp': datetime.now().isoformat()
        }
        
        # Test connectivity between all hosts
        for i, src_host in enumerate(hosts):
            for j, dst_host in enumerate(hosts):
                if i != j:
                    results['connectivity'][f"{src_host}->{dst_host}"] = \
                        self.test_connectivity(src_host, dst_host)
        
        # Test port connectivity
        for host in hosts:
            for port in ports:
                results['ports'][f"{host}:{port}"] = \
                    self.test_port_connectivity(host, port)
        
        # Save results
        with open('logs/network_test_results.json', 'w') as f:
            import json
            json.dump(results, f, indent=2)
        
        self.logger.info("Comprehensive network test completed")
        return results

def main():
    """Main function for testing"""
    import argparse
    
    parser = argparse.ArgumentParser(description='P4 DPI Traffic Generator')
    parser.add_argument('--mode', choices=['generate', 'test'], default='generate',
                       help='Mode: generate traffic or test network')
    parser.add_argument('--config', default='config/traffic_config.yaml',
                       help='Configuration file')
    parser.add_argument('--duration', type=int, default=300,
                       help='Traffic generation duration in seconds')
    
    args = parser.parse_args()
    
    if args.mode == 'generate':
        # Generate traffic
        generator = TrafficGenerator(args.config)
        
        try:
            generator.start_traffic_generation()
        except KeyboardInterrupt:
            generator.stop_traffic_generation()
    
    elif args.mode == 'test':
        # Test network
        tester = NetworkTester()
        
        hosts = ['10.0.1.1', '10.0.1.2', '10.0.2.1', '10.0.2.2']
        ports = [80, 443, 22, 53]
        
        results = tester.run_comprehensive_test(hosts, ports)
        print("Test results:", results)

if __name__ == "__main__":
    main()
