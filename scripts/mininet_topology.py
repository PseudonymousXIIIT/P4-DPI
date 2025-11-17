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
                self.cmd_handle = subprocess.Popen(
                    cmd,
                    stdout=outfile,
                    stderr=subprocess.STDOUT,
                    cwd='/tmp'
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
        """Generate various types of traffic for testing"""
        time.sleep(5)  # Wait for network to stabilize
        
        # HTTP traffic
        self.hosts['h1'].cmd('curl -s http://10.0.2.1/ > /dev/null &')
        self.hosts['h2'].cmd('curl -s http://10.0.2.1/ > /dev/null &')
        
        # Ping traffic
        self.hosts['h1'].cmd('ping -c 5 10.0.2.1 &')
        self.hosts['h2'].cmd('ping -c 5 10.0.2.2 &')
        
        # UDP traffic (DNS simulation)
        self.hosts['h1'].cmd('nslookup google.com 8.8.8.8 &')
        
        # TCP connection test
        self.hosts['h1'].cmd('nc -z 10.0.2.1 80 &')
        
        self.logger.info("Traffic generation started")
    
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
