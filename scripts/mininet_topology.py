#!/usr/bin/env python3
"""
Mininet Topology for P4 DPI Tool
Creates a network topology with P4 switches for deep packet inspection
"""

import os
import sys
import time
import logging
from mininet.net import Mininet
from mininet.node import Host, Switch, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
# Custom P4 switch and host classes
class P4Switch(Switch):
    """P4 Switch implementation using basic Switch"""
    def __init__(self, name, sw_path='simple_switch_grpc', grpc_port=50051, 
                 cpu_port=255, p4info_file=None, runtime_json=None, device_id=0, **kwargs):
        super(P4Switch, self).__init__(name, **kwargs)
        # Try to find simple_switch_grpc, fallback to simple_switch
        import shutil
        # Prefer the actual compiled binary if the libtool wrapper is present
        compiled_bin = '/p4-dpi/bmv2/targets/simple_switch_grpc/.libs/simple_switch_grpc'
        wrapper_bin = '/usr/local/bin/simple_switch_grpc'
        if os.path.exists(compiled_bin):
            self.sw_path = compiled_bin
        elif shutil.which('simple_switch_grpc'):
            # Some installs put a libtool wrapper at /usr/local/bin/simple_switch_grpc
            # which expects a sibling .libs directory. If that's the case, this may fail at runtime.
            self.sw_path = 'simple_switch_grpc'
        elif os.path.exists(wrapper_bin):
            self.sw_path = wrapper_bin
        else:
            # Use simple_switch - will check for gRPC support at runtime
            self.sw_path = '/usr/local/bin/simple_switch'
        self.grpc_port = grpc_port
        self.cpu_port = cpu_port
        self.p4info_file = p4info_file
        self.runtime_json = runtime_json
        self.device_id = device_id
        self.exe = self.sw_path
        self.prefix = name
    
    def start(self, controllers):
        """Start the simple_switch_grpc process"""
        import subprocess
        import os
        
        # Setup logger
        logger = logging.getLogger(f'P4Switch.{self.name}')
        
        # Get the list of interfaces for this switch
        intfs = []
        for intf in self.intfList():
            if intf.name and intf.name != 'lo':
                # Format: port@interface_name or just port
                port = len(intfs)  # Use sequential port numbers
                if '@' in intf.name:
                    intfs.append(intf.name)
                else:
                    intfs.append(f"{port}@{intf.name}")
        
        if not intfs:
            intfs = ['0']
        
        # Build command to start simple_switch_grpc
        cmd = [self.sw_path]
        
        # Add interfaces
        for intf in intfs:
            cmd.extend(['-i', intf])
        
        # For simple_switch target (non-gRPC), use Thrift as a fallback (not ideal)
        if 'simple_switch_grpc' not in self.sw_path:
            # For simple_switch, try using Thrift port as fallback
            # Note: P4Runtime may not work with simple_switch
            cmd.extend(['--thrift-port', str(self.grpc_port)])
            logger.warning(f"Using simple_switch without gRPC - P4Runtime may not work properly. Please install simple_switch_grpc.")
        
        # Add device ID
        cmd.extend(['--device-id', str(self.device_id)])
        
        # Enable console logging to see detailed startup messages
        cmd.append('--log-console')
        
    # cpu-port is a target-specific option for simple_switch_grpc; add it after '--' below

    # Do not set --log-file to avoid spdlog rotating sink issues; stdout/stderr are redirected to /tmp/{name}_switch.out
        
        # Add P4Info and JSON files if provided (use absolute paths since cwd is /tmp)
        base_dir = '/p4-dpi'
        p4info_path = None
        json_path = None
        # Note: p4info is used by the controller, not by simple_switch_grpc; do not add --p4info here
        if self.p4info_file:
            p4info_path = self.p4info_file if os.path.isabs(self.p4info_file) else os.path.join(base_dir, self.p4info_file)
            if not os.path.exists(p4info_path):
                logger.warning(f"P4Info file not found (for controller reference): {p4info_path}")
        if self.runtime_json:
            json_path = self.runtime_json if os.path.isabs(self.runtime_json) else os.path.join(base_dir, self.runtime_json)
            if not os.path.exists(json_path):
                logger.warning(f"P4 JSON file not found: {json_path}")
                json_path = None

        # For p4runtime-driven programming, start without pre-loading a P4 JSON
        json_path = None

        # Target-specific options must be after '--'
        if 'simple_switch_grpc' in self.sw_path:
            # Ensure we start without loading a P4 JSON so the controller can push pipeline.
            # This is a general BMv2 option and must appear BEFORE the target-specific options.
            if '--no-p4' not in cmd:
                cmd.append('--no-p4')
            cmd.append('--')
            cmd.extend(['--grpc-server-addr', f'0.0.0.0:{self.grpc_port}'])
            # Add cpu-port as target-specific option
            cmd.extend(['--cpu-port', str(self.cpu_port)])

        # (log-file already added above)
        
        logger.info(f"Starting {self.name} with command: {' '.join(cmd)}")
        # Also write the exact command to /tmp for debugging
        try:
            with open(f"/tmp/{self.name}_cmd.txt", "w") as f:
                f.write("CMD: " + " ".join(cmd) + "\n")
        except Exception as _:
            pass
        
        # Start the process
        try:
            with open(f'/tmp/{self.name}_switch.out', 'w') as outfile:
                # Set LD_LIBRARY_PATH for BMv2 shared libraries
                env = os.environ.copy()
                lib_paths = [
                    '/usr/local/lib',
                    '/p4-dpi/bmv2/targets/simple_switch_grpc/.libs',
                    env.get('LD_LIBRARY_PATH', '')
                ]
                env['LD_LIBRARY_PATH'] = ':'.join(filter(None, lib_paths))
                
                self.cmd_handle = subprocess.Popen(
                    cmd,
                    stdout=outfile,
                    stderr=subprocess.STDOUT,
                    cwd='/tmp',
                    env=env
                )
            logger.info(f"{self.name} started with PID {self.cmd_handle.pid}")
            
            # Wait a bit for the switch to initialize
            import time
            time.sleep(2)
            
        except Exception as e:
            logger.error(f"Failed to start {self.name}: {e}")
            raise
    
    def stop(self, deleteIntfs=True):
        """Stop the simple_switch_grpc process"""
        logger = logging.getLogger(f'P4Switch.{self.name}')
        if hasattr(self, 'cmd_handle'):
            try:
                self.cmd_handle.terminate()
                self.cmd_handle.wait(timeout=5)
                logger.info(f"{self.name} stopped")
            except Exception as e:
                logger.error(f"Error stopping {self.name}: {e}")
                if hasattr(self, 'cmd_handle'):
                    self.cmd_handle.kill()
        super(P4Switch, self).stop(deleteIntfs)

class P4Host(Host):
    """P4 Host implementation"""
    def __init__(self, name, **kwargs):
        super(P4Host, self).__init__(name, **kwargs)
import subprocess
import threading

# Add the current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

class DPITopology:
    def __init__(self):
        self.net = None
        self.switches = {}
        self.hosts = {}
        self.setup_logging()
        
    def setup_logging(self):
        """Setup logging for the topology"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('logs/mininet.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger('DPI_Topology')
    
    def create_topology(self):
        """Create the network topology"""
        info('*** Creating DPI Network Topology\n')

        # Proactively clean any stale Mininet state & veth pairs from prior runs
        try:
            os.system('mn -c >/dev/null 2>&1')
            # Remove any leftover s{1,2,3}-eth{1..6} links which cause RTNETLINK file exists
            for sw in ('s1','s2','s3'):
                for idx in range(1, 7):
                    os.system(f"ip link del {sw}-eth{idx} >/dev/null 2>&1")
        except Exception:
            pass
        
        # Create Mininet network
        self.net = Mininet(
            topo=None,
            switch=P4Switch,
            host=P4Host,
            controller=None,
            link=TCLink,
            autoSetMacs=True
        )
        
        # Add controller (we'll use P4Runtime directly)
        info('*** Adding controller\n')
        # No external controller needed for P4Runtime
        
        # Add switches
        info('*** Adding switches\n')
        self.add_switches()
        
        # Add hosts
        info('*** Adding hosts\n')
        self.add_hosts()
        
        # Add links
        info('*** Adding links\n')
        self.add_links()
        
        # Start network
        info('*** Starting network\n')
        self.net.start()
        
        # Manually start P4 switches after network is initialized
        info('*** Starting P4 switches\n')
        for switch_name, switch in self.switches.items():
            if isinstance(switch, P4Switch):
                try:
                    switch.start([])  # Pass empty controllers list
                    self.logger.info(f"Started P4 switch {switch_name}")
                except Exception as e:
                    self.logger.error(f"Failed to start switch {switch_name}: {e}")
        
        # Wait for switches to initialize
        import time
        time.sleep(3)
        
        # Configure switches
        info('*** Configuring switches\n')
        self.configure_switches()
        
        # Configure hosts
        info('*** Configuring hosts\n')
        self.configure_hosts()
        
        self.logger.info("Topology created successfully")
    
    def add_switches(self):
        """Add P4 switches to the topology"""
        # Main DPI switch
        s1 = self.net.addSwitch(
            's1',
            sw_path='simple_switch_grpc',
            grpc_port=50051,
            cpu_port=255,
            device_id=1,
            p4info_file='p4_programs/dpi_l2_l4.p4info.txt',
            runtime_json='p4_programs/dpi_l2_l4.json',
            log_console=True
        )
        self.switches['s1'] = s1
        
        # Edge switches for different network segments
        s2 = self.net.addSwitch(
            's2',
            sw_path='simple_switch_grpc',
            grpc_port=50052,
            cpu_port=255,
            device_id=2,
            p4info_file='p4_programs/dpi_l2_l4.p4info.txt',
            runtime_json='p4_programs/dpi_l2_l4.json',
            log_console=True
        )
        self.switches['s2'] = s2
        
        s3 = self.net.addSwitch(
            's3',
            sw_path='simple_switch_grpc',
            grpc_port=50053,
            cpu_port=255,
            device_id=3,
            p4info_file='p4_programs/dpi_l2_l4.p4info.txt',
            runtime_json='p4_programs/dpi_l2_l4.json',
            log_console=True
        )
        self.switches['s3'] = s3
    
    def add_hosts(self):
        """Add hosts to the topology"""
        # Disable IPv6 at kernel level before creating hosts to prevent Router Solicitation
        import subprocess
        try:
            subprocess.run(['sysctl', '-w', 'net.ipv6.conf.all.disable_ipv6=1'], 
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(['sysctl', '-w', 'net.ipv6.conf.default.disable_ipv6=1'], 
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass
        
        # Client hosts
        h1 = self.net.addHost(
            'h1',
            ip='10.0.1.1/24',
            mac='00:00:00:00:00:01'
        )
        self.hosts['h1'] = h1
        
        h2 = self.net.addHost(
            'h2',
            ip='10.0.1.2/24',
            mac='00:00:00:00:00:02'
        )
        self.hosts['h2'] = h2
        
        # Server hosts
        h3 = self.net.addHost(
            'h3',
            ip='10.0.2.1/24',
            mac='00:00:00:00:00:03'
        )
        self.hosts['h3'] = h3
        
        h4 = self.net.addHost(
            'h4',
            ip='10.0.2.2/24',
            mac='00:00:00:00:00:04'
        )
        self.hosts['h4'] = h4
        
        # Attacker host (for testing DPI capabilities)
        h5 = self.net.addHost(
            'h5',
            ip='10.0.3.1/24',
            mac='00:00:00:00:00:05'
        )
        self.hosts['h5'] = h5
        
        # Monitoring host
        h6 = self.net.addHost(
            'h6',
            ip='10.0.4.1/24',
            mac='00:00:00:00:00:06'
        )
        self.hosts['h6'] = h6
    
    def add_links(self):
        """Add links between switches and hosts"""
        # Connect hosts to edge switches
        self.net.addLink('h1', 's2', port1=1, port2=1)
        self.net.addLink('h2', 's2', port1=1, port2=2)
        self.net.addLink('h3', 's3', port1=1, port2=1)
        self.net.addLink('h4', 's3', port1=1, port2=2)
        self.net.addLink('h5', 's2', port1=1, port2=3)
        self.net.addLink('h6', 's1', port1=1, port2=1)
        
        # Connect switches
        self.net.addLink('s2', 's1', port1=4, port2=2)
        self.net.addLink('s3', 's1', port1=3, port2=3)
    
    def configure_switches(self):
        """Configure P4 switches"""
        for switch_name, switch in self.switches.items():
            self.logger.info(f"Configuring switch {switch_name}")
            
            # Set up routing tables
            if switch_name == 's1':
                # Main DPI switch - routes between networks
                self.setup_routing_table(switch, [
                    ('10.0.1.0/24', 2),  # Route to s2
                    ('10.0.2.0/24', 3),  # Route to s3
                    ('10.0.3.0/24', 2),  # Route to s2
                    ('10.0.4.0/24', 1),  # Local network
                ])
            elif switch_name == 's2':
                # Edge switch for client network
                self.setup_routing_table(switch, [
                    ('10.0.1.0/24', 1),  # Local network
                    ('10.0.2.0/24', 4),  # Route to s1
                    ('10.0.3.0/24', 3),  # Local network
                    ('10.0.4.0/24', 4),  # Route to s1
                ])
            elif switch_name == 's3':
                # Edge switch for server network
                self.setup_routing_table(switch, [
                    ('10.0.1.0/24', 3),  # Route to s1
                    ('10.0.2.0/24', 1),  # Local network
                    ('10.0.3.0/24', 3),  # Route to s1
                    ('10.0.4.0/24', 3),  # Route to s1
                ])
    
    def setup_routing_table(self, switch, routes):
        """Setup routing table for a switch"""
        for network, port in routes:
            self.logger.info(f"Adding route {network} -> port {port}")
            # This would be implemented with P4Runtime table entries
            # For now, we'll use basic IP forwarding
    
    def configure_hosts(self):
        """Configure hosts with proper network settings"""
        for host_name, host in self.hosts.items():
            self.logger.info(f"Configuring host {host_name}")
            # Prefer IPv4 for tests: disable IPv6 to avoid v6-only traffic dominating
            host.cmd('sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1')
            host.cmd('sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1')
            
            # Also disable IPv6 on each interface of this host
            for intf in host.intfList():
                if intf.name and intf.name != 'lo':
                    host.cmd(f'sysctl -w net.ipv6.conf.{intf.name}.disable_ipv6=1 >/dev/null 2>&1')
            
            # Set default routes
            if host_name in ['h1', 'h2', 'h5']:
                # Client hosts route through s2
                host.cmd('ip route add default via 10.0.1.254')
            elif host_name in ['h3', 'h4']:
                # Server hosts route through s3
                host.cmd('ip route add default via 10.0.2.254')
            elif host_name == 'h6':
                # Monitoring host routes through s1
                host.cmd('ip route add default via 10.0.4.254')
            
            # Enable IP forwarding
            host.cmd('sysctl net.ipv4.ip_forward=1')
            
            # Set up packet capture (for monitoring)
            if host_name == 'h6':
                self.setup_packet_capture(host)
    
    def setup_packet_capture(self, host):
        """Setup packet capture on monitoring host"""
        self.logger.info("Setting up packet capture on monitoring host")
        
        # Create capture script
        capture_script = '''
#!/bin/bash
# Packet capture script for DPI monitoring
tcpdump -i any -w /tmp/dpi_capture.pcap -s 0 &
echo $! > /tmp/tcpdump.pid
'''
        
        host.cmd(f'echo "{capture_script}" > /tmp/start_capture.sh')
        host.cmd('chmod +x /tmp/start_capture.sh')
        host.cmd('/tmp/start_capture.sh')
    
    def start_traffic_generation(self):
        """Start traffic generation for testing"""
        self.logger.info("Starting traffic generation")
        
        # Start HTTP server on h3
        self.hosts['h3'].cmd('python3 -m http.server 80 &')
        
        # Start traffic generation
        traffic_thread = threading.Thread(target=self.generate_traffic)
        traffic_thread.daemon = True
        traffic_thread.start()
    
    def generate_traffic(self):
        """Generate various types of traffic for testing using Scapy for reliability"""
        self.logger.info("Starting continuous traffic generation using Scapy")
        time.sleep(2)  # Wait for network to stabilize

        # Import Scapy for packet crafting
        from scapy.all import Ether, IP, IPv6, TCP, UDP, ICMP, ICMPv6EchoRequest, sendp, get_if_list, Raw
        import random

        # Continuous traffic generation loop using raw packet injection
        iteration = 0
        sent = 0  # approximate packets sent counter
        # Allow simple tuning via environment variables without code changes
        # Hard-coded, gentle defaults; other env knobs remain for structure/randomness only
        try:
            randomize = int(os.getenv('DPI_TRAFFIC_RANDOM', '1')) != 0
            target_packets = int(os.getenv('DPI_TRAFFIC_TARGET_PACKETS', '0'))  # 0 = unlimited
        except Exception:
            randomize = True
            target_packets = 0

        # Enforce hard-coded rate in 12–16 packets/sec (total)
        # We send on 1 interface, 1 packet per iteration; sleep chosen per-iteration for 12–16 pps
        iface_limit = 1
        per_iter = 1
        burst = 1
        RATE_MIN_PPS = 12.0
        RATE_MAX_PPS = 16.0

        while True:
            iteration += 1
            try:
                # Build dynamic endpoint lists from Mininet hosts when available
                client_names = ['h1', 'h2', 'h5']
                server_names = ['h3', 'h4']
                clients = [self.hosts[n] for n in client_names if n in self.hosts]
                servers = [self.hosts[n] for n in server_names if n in self.hosts]

                def pick_pair():
                    if clients and servers and randomize:
                        a = random.choice(clients)
                        b = random.choice(servers)
                        # 50% chance to flip directions to vary traffic
                        if random.random() < 0.5:
                            a, b = b, a
                        return a, b
                    # Fallback to fixed host mapping if topology not ready
                    return self.hosts.get('h1'), self.hosts.get('h3')

                def rand_ttl():
                    return random.randint(32, 128) if randomize else 64

                def rand_tos():
                    return random.choice([0, 16, 32, 40]) if randomize else 0

                def rand_sport():
                    return random.randint(1024, 65535) if randomize else 50000 + iteration

                def rand_payload():
                    size = random.randint(20, 120) if randomize else 20
                    return os.urandom(size)
                
                def create_tls_client_hello():
                    """Create a minimal TLS ClientHello for testing Layer 5 parsing."""
                    # TLS Record: Handshake (0x16), TLS 1.2 (0x0303), Length
                    tls_record = bytes([0x16, 0x03, 0x03, 0x00, 0x70])  # 112 bytes
                    # Handshake: ClientHello (0x01), Length
                    handshake = bytes([0x01, 0x00, 0x00, 0x6C])  # 108 bytes
                    # Version TLS 1.2, Random (32 bytes)
                    version = bytes([0x03, 0x03])
                    random_data = os.urandom(32)
                    # Session ID: 8 bytes
                    session_id_len = bytes([0x08])
                    session_id = os.urandom(8)
                    # Cipher suites: vary cipher suite for diversity
                    cipher_options = [
                        bytes([0x00, 0x02, 0x00, 0x2F]),  # TLS_RSA_WITH_AES_128_CBC_SHA
                        bytes([0x00, 0x02, 0x00, 0x35]),  # TLS_RSA_WITH_AES_256_CBC_SHA
                        bytes([0x00, 0x02, 0xC0, 0x2F]),  # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                        bytes([0x00, 0x02, 0xC0, 0x30]),  # TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
                        bytes([0x00, 0x02, 0x00, 0x9C]),  # TLS_RSA_WITH_AES_128_GCM_SHA256
                        bytes([0x00, 0x02, 0x13, 0x01]),  # TLS_AES_128_GCM_SHA256 (TLS 1.3)
                    ]
                    cipher = random.choice(cipher_options) if randomize else cipher_options[0]
                    # Compression: none
                    compression = bytes([0x01, 0x00])
                    # Extensions with SNI
                    ext_len = bytes([0x00, 0x10])
                    sni_ext = bytes([0x00, 0x00, 0x00, 0x0C, 0x00, 0x0A, 0x00, 0x00, 0x07]) + b'test.io'
                    payload = (tls_record + handshake + version + random_data + 
                              session_id_len + session_id + cipher + compression + ext_len + sni_ext)
                    return payload
                
                def create_http2_frame(stream_id=1):
                    """Create a minimal HTTP/2 HEADERS frame for testing."""
                    # HTTP/2 frame format:
                    # 3 bytes: Length (24-bit)
                    # 1 byte: Type (0x01 = HEADERS)
                    # 1 byte: Flags (0x04 = END_HEADERS)
                    # 4 bytes: Stream ID (31-bit, reserved bit = 0)
                    # Payload: minimal headers
                    
                    payload = b'\x82\x86\x84\x41\x0f\x77\x77\x77\x2e\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63\x6f\x6d'  # Compressed headers
                    length = len(payload)
                    frame = bytes([
                        (length >> 16) & 0xFF,
                        (length >> 8) & 0xFF,
                        length & 0xFF,
                        0x01,  # HEADERS frame type
                        0x04,  # END_HEADERS flag
                        (stream_id >> 24) & 0xFF,
                        (stream_id >> 16) & 0xFF,
                        (stream_id >> 8) & 0xFF,
                        stream_id & 0xFF
                    ]) + payload
                    return frame

                # Assemble a batch of mixed-protocol packets (IPv4 + IPv6)
                batch = []
                n = max(1, per_iter)
                for _ in range(n):
                    src_host, dst_host = pick_pair()
                    if not src_host or not dst_host:
                        # Topology not ready; skip this packet
                        continue
                    src_mac = src_host.MAC()
                    # Keep dest MAC stable to ensure forwarding via switch
                    dst_mac = '00:aa:00:00:00:01'
                    
                    # 70% IPv4, 30% IPv6 mix
                    use_ipv6 = random.random() < 0.3 if randomize else False
                    
                    if use_ipv6:
                        # Generate IPv6 addresses based on host IPs
                        # Convert 10.0.x.y to fe80::x:y for link-local
                        src_ipv4 = src_host.IP()
                        dst_ipv4 = dst_host.IP()
                        src_parts = src_ipv4.split('.')
                        dst_parts = dst_ipv4.split('.')
                        src_ipv6 = f"fe80::{src_parts[2]}:{src_parts[3]}"
                        dst_ipv6 = f"fe80::{dst_parts[2]}:{dst_parts[3]}"
                        
                        proto = random.choice(['ICMPv6', 'TCP', 'UDP']) if randomize else 'ICMPv6'
                        
                        if proto == 'ICMPv6':
                            # ICMPv6 Echo Request (type=128) or Neighbor Solicitation (type=135)
                            icmp_type = random.choice([128, 135]) if randomize else 128
                            pkt = Ether(src=src_mac, dst=dst_mac) / \
                                  IPv6(src=src_ipv6, dst=dst_ipv6, hlim=rand_ttl()) / \
                                  ICMPv6EchoRequest(id=random.randint(1000, 60000), seq=iteration)
                        elif proto == 'TCP':
                            dport = random.choice([80, 443, 22, 8080]) if randomize else 80
                            tcp_pkt = Ether(src=src_mac, dst=dst_mac) / \
                                      IPv6(src=src_ipv6, dst=dst_ipv6, hlim=rand_ttl()) / \
                                      TCP(sport=rand_sport(), dport=dport, flags='S')
                            # Add TLS ClientHello for HTTPS (80% chance)
                            if dport == 443 and randomize and random.random() < 0.8:
                                tcp_pkt = tcp_pkt / Raw(load=create_tls_client_hello())
                            # Add HTTP/2 frame for HTTP (20% chance)
                            elif dport == 80 and randomize and random.random() < 0.2:
                                stream_id = random.randint(1, 100)
                                tcp_pkt = tcp_pkt / Raw(load=create_http2_frame(stream_id))
                            pkt = tcp_pkt
                        else:  # UDP
                            dport = random.choice([53, 123, 5000, 25000]) if randomize else 53
                            pkt = Ether(src=src_mac, dst=dst_mac) / \
                                  IPv6(src=src_ipv6, dst=dst_ipv6, hlim=rand_ttl()) / \
                                  UDP(sport=rand_sport(), dport=dport) / Raw(rand_payload())
                    else:
                        # IPv4 packets (original logic)
                        src_ip = src_host.IP()
                        dst_ip = dst_host.IP()
                        proto = random.choice(['ICMP', 'TCP', 'UDP']) if randomize else 'ICMP'

                        if proto == 'ICMP':
                            pkt = Ether(src=src_mac, dst=dst_mac) / \
                                  IP(src=src_ip, dst=dst_ip, ttl=rand_ttl(), tos=rand_tos()) / \
                                  ICMP(type=8, code=0, id=random.randint(1000, 60000), seq=iteration)
                        elif proto == 'TCP':
                            dport = random.choice([80, 443, 22, 8080]) if randomize else 80
                            tcp_pkt = Ether(src=src_mac, dst=dst_mac) / \
                                      IP(src=src_ip, dst=dst_ip, ttl=rand_ttl(), tos=rand_tos()) / \
                                      TCP(sport=rand_sport(), dport=dport, flags='S')
                            # Add TLS ClientHello payload for HTTPS traffic (80% chance)
                            if dport == 443 and randomize and random.random() < 0.8:
                                tcp_pkt = tcp_pkt / Raw(load=create_tls_client_hello())
                            # Add HTTP/2 frame for HTTP (20% chance)
                            elif dport == 80 and randomize and random.random() < 0.2:
                                stream_id = random.randint(1, 100)
                                tcp_pkt = tcp_pkt / Raw(load=create_http2_frame(stream_id))
                            pkt = tcp_pkt
                        else:  # UDP
                            dport = random.choice([53, 123, 5000, 25000]) if randomize else 53
                            pkt = Ether(src=src_mac, dst=dst_mac) / \
                                  IP(src=src_ip, dst=dst_ip, ttl=rand_ttl(), tos=rand_tos()) / \
                                  UDP(sport=rand_sport(), dport=dport) / Raw(rand_payload())
                    batch.append(pkt)

                # Send packets on available switch interfaces
                # Use multiple available interfaces (s1-eth*, s2-eth*) to expand coverage and throughput
                ifaces = [iface for iface in get_if_list() if ('s1-eth' in iface or 's2-eth' in iface)]
                # Filter to currently-present interfaces to avoid OSError(19)
                present = []
                for iface in ifaces:
                    try:
                        if os.path.exists(f'/sys/class/net/{iface}'):
                            present.append(iface)
                    except Exception:
                        continue

                if present:
                    # Limit to first few to avoid excessive duplication
                    target_ifaces = present[:max(1, iface_limit)]
                    for _ in range(max(1, burst)):
                        for tif in target_ifaces:
                            try:
                                sendp(batch, iface=tif, verbose=0)
                                sent += len(batch)
                            except OSError:
                                # Interface may have disappeared; skip quietly
                                continue

                # Stop when approximate target reached
                if target_packets > 0 and sent >= target_packets:
                    self.logger.info(f"Traffic generation target reached (~{sent} packets). Stopping generator.")
                    return

            except Exception as e:
                # Avoid log flooding; surface concise message
                self.logger.error(f"Error generating traffic: {e!r}")

            # Hard-coded 12–16 pps: choose a random target rate and sleep accordingly
            try:
                pps_target = random.uniform(RATE_MIN_PPS, RATE_MAX_PPS)
            except Exception:
                pps_target = (RATE_MIN_PPS + RATE_MAX_PPS) / 2.0
            iter_sleep = max(0.03, per_iter / float(pps_target))

            if iteration % 10 == 0:
                try:
                    ifaces_str = ','.join(target_ifaces) if 'target_ifaces' in locals() else 'NONE'
                except Exception:
                    ifaces_str = 'NONE'
                self.logger.info(f"Traffic generation iter {iteration} sent~{sent} target={target_packets} pps~{pps_target:.1f} ifaces={ifaces_str}")

            time.sleep(iter_sleep)
    
    def run_cli(self):
        """Run Mininet CLI"""
        info('*** Running CLI\n')
        CLI(self.net)
    
    def stop(self):
        """Stop the network"""
        if self.net:
            info('*** Stopping network\n')
            self.net.stop()
            self.logger.info("Network stopped")

def main():
    """Main function"""
    setLogLevel('info')
    
    # Create topology
    topology = DPITopology()
    
    try:
        # Create and start topology
        topology.create_topology()
        
        # Start traffic generation
        topology.start_traffic_generation()
        
        # Run CLI
        topology.run_cli()
        
    except KeyboardInterrupt:
        info('*** Interrupted\n')
    except Exception as e:
        topology.logger.error(f"Error: {e}")
    finally:
        topology.stop()

if __name__ == '__main__':
    main()
