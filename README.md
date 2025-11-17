# P4 Deep Packet Inspection (DPI) Tool

A comprehensive P4-based Deep Packet Inspection tool with full L2/L3/L4 forwarding and monitoring capabilities. Built on BMv2 simple_switch_grpc with P4Runtime control plane, this system provides programmable packet inspection in a multi-switch Mininet topology.

## Features

### Core Capabilities
- **Multi-Layer Packet Inspection**: L2 (Ethernet), L3 (IPv4/IPv6/ARP), L4 (TCP/UDP/ICMP)
- **L2/L3 Forwarding**: MAC-based switching, IPv4 routing with ARP gateway support
- **P4Runtime Control Plane**: Dynamic pipeline programming with per-switch controller workers
- **Real-time Traffic Analysis**: Passive packet capture with Scapy on all switch/host interfaces
- **Advanced Logging**: SQLite-based packet storage with flow tracking and statistics
- **Traffic Generation**: Built-in Mininet-based traffic generator (HTTP, ping, DNS simulation)
- **Docker Containerization**: Complete P4 toolchain (p4c, BMv2, Mininet) in a single container
- **Multi-Switch Topology**: 3 P4 switches (s1, s2, s3) with 6 hosts in isolated subnets

### P4 Data Plane Features
- **ARP Gateway**: s1 replies to ARP requests for 10.0.{1,2,3,4}.254 with router MAC (00:aa:00:00:00:01)
- **IPv4 Routing**: Static per-host routes on s1 with L2 rewrite and TTL decrement
- **MAC Forwarding**: L2 forwarding tables on all switches for local and inter-switch traffic
- **Protocol Filtering**: Configurable tables for packet classification and suspicious traffic detection

### Monitoring & Analysis
- **Passive Packet Capture**: Scapy sniffers on all s*-eth* and h*-eth* interfaces
- **Flow Tracking**: Automatic flow ID generation and per-flow statistics
- **Real-time Statistics**: Protocol distribution, top ports, top IPs
- **Export Formats**: JSON and CSV exports from SQLite DB (per-run and periodic)
- **Retention Policies**: Configurable packet cleanup and database size limits

## Architecture

### Network Topology
```
    10.0.1.0/24          10.0.3.0/24                 10.0.2.0/24
    ┌────┐  ┌────┐       ┌────┐                     ┌────┐  ┌────┐
    │ h1 │  │ h2 │       │ h5 │                     │ h3 │  │ h4 │
    └─┬──┘  └─┬──┘       └─┬──┘                     └─┬──┘  └─┬──┘
      │       │            │                          │       │
      └───┬───┴────────────┘                          └───┬───┘
          │                                               │
        ┌─┴───┐                                         ┌─┴───┐
        │ s2  │ ◄───────── (s2-eth4 ◄─► s1-eth2) ─────►│ s3  │
        └─────┘             port 4 ◄─► port 2          └─────┘
                                  │                     port 3
                                ┌─┴───┐                   │
                                │ s1  │ ◄─────────────────┘
                                └──┬──┘      s3-eth3 ◄─► s1-eth3
                                   │
                                 ┌─┴──┐
                                 │ h6 │  (monitoring)
                                 └────┘
                               10.0.4.0/24

P4 Switches: s1 (core router), s2/s3 (edge)
Hosts: h1,h2,h5 on s2; h3,h4 on s3; h6 on s1
Default Gateways: 10.0.{1,2,3,4}.254 (all via s1 ARP replies)
```

### System Components
```
┌─────────────────────────────────────────────────────────────┐
│                      Docker Container                        │
│  ┌────────────────────────────────────────────────────────┐ │
│  │  P4 Toolchain: p4c (compiler), BMv2 (simple_switch_grpc)│ │
│  └────────────────────────────────────────────────────────┘ │
│  ┌────────────────────────────────────────────────────────┐ │
│  │  Mininet Topology: 3 switches + 6 hosts                │ │
│  └────────────────────────────────────────────────────────┘ │
│  ┌────────────────────────────────────────────────────────┐ │
│  │  P4Runtime Control: per-switch controller workers       │ │
│  │    • s1: ARP, IPv4 routing, MAC forwarding              │ │
│  │    • s2/s3: MAC forwarding to local hosts and uplink    │ │
│  └────────────────────────────────────────────────────────┘ │
│  ┌────────────────────────────────────────────────────────┐ │
│  │  Packet Logger: Scapy sniffers → SQLite DB             │ │
│  └────────────────────────────────────────────────────────┘ │
│  ┌────────────────────────────────────────────────────────┐ │
│  │  Traffic Generator: HTTP server, curl, ping, DNS       │ │
│  └────────────────────────────────────────────────────────┘ │
│  ┌────────────────────────────────────────────────────────┐ │
│  │  Monitoring: Statistics, exports (JSON/CSV), health    │ │
│  └────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

## Prerequisites

### System Requirements
- **Operating System**: Linux (Ubuntu 20.04+) or Windows with WSL2
- **Docker**: Version 20.10+ with BuildKit support
- **Memory**: Minimum 4GB RAM (8GB+ recommended for full topology)
- **Storage**: ~5GB for Docker image + logs/DB
- **CPU**: Multi-core recommended (for parallel switch processes)

### Software Dependencies (inside Docker)
- **P4 Compiler**: p4c (v1.2.4.9+) with BMv2 backend
- **BMv2**: simple_switch_grpc target (v1.15.0+)
- **Mininet**: 2.3.0 (built from source)
- **Python**: 3.10+ with grpcio, p4runtime-sh, scapy, pandas, pyyaml
- **gRPC**: For P4Runtime communication (ports 50051-50053)

## Installation

### 1. Build the Docker Image
```bash
docker-compose build
```
This compiles BMv2, p4c, and Mininet from source (~20-30 minutes first time).

### 2. Start the Container
```bash
docker-compose up -d
```

### 3. Run the DPI System
```bash
docker exec p4-dpi-container bash -c "cd /p4-dpi && python3 scripts/start_dpi.py --mode start"
```

The startup sequence:
1. Compiles `dpi_l2_l4.p4` → generates `.json` and `.p4info.txt`
2. Starts Mininet topology (s1, s2, s3, h1-h6)
3. Launches simple_switch_grpc on each switch (ports 50051-50053)
4. Spawns per-switch P4Runtime controller workers to program tables
5. Starts packet logger with Scapy sniffers on all interfaces
6. Starts traffic generator (HTTP server on h3, periodic pings/curls)
7. Begins monitoring and statistics collection

### 4. Verify Operation
```bash
# Check processes
docker exec p4-dpi-container bash -c "ps -ef | grep simple_switch_grpc"

# Check controller logs
docker exec p4-dpi-container bash -c "tail -n 50 logs/dpi_controller_worker.log"

# Query packet database
docker exec p4-dpi-container bash -c "cd /p4-dpi && python3 scripts/db_query.py"
```

## Quick Start

### Start the System
```bash
docker-compose up -d
docker exec -d p4-dpi-container bash -c "cd /p4-dpi && python3 scripts/start_dpi.py --mode start"
```

### Monitor Logs in Real-Time
```bash
# System log
docker exec p4-dpi-container bash -c "tail -f logs/dpi_system.log"

# Controller log
docker exec p4-dpi-container bash -c "tail -f logs/dpi_controller_worker.log"

# Packet logger
docker exec p4-dpi-container bash -c "tail -f logs/packet_logger.log"
```

### Check Packet Capture
```bash
# Query statistics from DB
docker exec p4-dpi-container bash -c "cd /p4-dpi && python3 scripts/db_query.py"

# Export current DB snapshot
docker exec p4-dpi-container bash -c "cd /p4-dpi && python3 scripts/export_db.py --db logs/packets.db --out logs"
```

### Sniff Live Traffic
```bash
# IPv4 on s1-s2 uplink
docker exec p4-dpi-container bash -c "timeout 10 tcpdump -i s1-eth2 -n ip"

# ARP on s2 host port
docker exec p4-dpi-container bash -c "timeout 10 tcpdump -i s2-eth1 -n arp"
```

### Test Connectivity
```bash
# Check if h1 can reach h3 via routing
docker exec p4-dpi-container bash -c "ip netns exec h1 ping -c 3 10.0.2.1"

# Test HTTP (h3 runs python http.server on port 80)
docker exec p4-dpi-container bash -c "ip netns exec h1 curl -m 5 http://10.0.2.1/"
```

## Configuration

### Main Configuration (`config/dpi_config.yaml`)
```yaml
switches:
  - name: s1
    device_id: 1
    grpc_port: 50051
    cpu_port: 255
    p4info_file: p4_programs/dpi_l2_l4.p4info.txt
    runtime_json_file: p4_programs/dpi_l2_l4.json
  - name: s2
    device_id: 2
    grpc_port: 50052
    cpu_port: 255
    p4info_file: p4_programs/dpi_l2_l4.p4info.txt
    runtime_json_file: p4_programs/dpi_l2_l4.json
  - name: s3
    device_id: 3
    grpc_port: 50053
    cpu_port: 255
    p4info_file: p4_programs/dpi_l2_l4.p4info.txt
    runtime_json_file: p4_programs/dpi_l2_l4.json

logging:
  level: INFO
  file: logs/dpi_system.log
  format: '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

monitoring:
  stats_interval: 10  # seconds

performance:
  database:
    file: logs/packets.db

export:
  initial_delay_seconds: 20  # delay before first per-run export

sniffing:
  enabled: true
  # interfaces auto-detected (all s*-eth* and h*-eth*)

web_interface:
  enabled: false  # disabled for headless operation
```

### P4 Program Tables (programmed by controller workers)
**s1 (Core Router)**:
- `arp_reply`: 10.0.{1,2,3,4}.254 → send_arp_reply with router MAC 00:aa:00:00:00:01
- `ipv4_forward`: exact match on dst IP → set_routing_params(port, src_mac, dst_mac, decrement TTL)
- `mac_forward`: dst MAC → set_egress_port(port) for inter-switch forwarding

**s2/s3 (Edge Switches)**:
- `mac_forward`: local host MACs → port; router MAC & broadcast → uplink port

## Usage

### Start the DPI System
```bash
docker exec p4-dpi-container bash -c "cd /p4-dpi && python3 scripts/start_dpi.py --mode start"
```

### Stop the System
```bash
docker exec p4-dpi-container bash -c "pkill -f start_dpi.py"
docker exec p4-dpi-container bash -c "pkill -f simple_switch_grpc"
docker exec p4-dpi-container bash -c "pkill -f p4_controller_worker"
```

### Query Packet Database
```bash
# Summary statistics
docker exec p4-dpi-container bash -c "cd /p4-dpi && python3 scripts/db_query.py"

# Check DB directly
docker exec p4-dpi-container bash -c "cd /p4-dpi && python3 scripts/check_db.py"
```

### Export Data
```bash
# Export all packets from DB to JSON/CSV
docker exec p4-dpi-container bash -c "cd /p4-dpi && python3 scripts/export_db.py --db logs/packets.db --out logs"

# Latest exports are in logs/ with timestamp: packets_export_db_YYYYMMDD_HHMMSS.{json,csv}
```

### Mininet CLI (for manual testing)
```bash
# Start with CLI instead of automated startup
docker exec -it p4-dpi-container bash -c "cd /p4-dpi && python3 scripts/mininet_topology.py"

# From Mininet CLI:
mininet> h1 ping -c 3 h3
mininet> h1 curl http://10.0.2.1/
mininet> xterm h1 h3  # open terminals
```

### Check P4 Table Entries
```bash
# Use simple_switch_CLI (Thrift API) or check controller logs
docker exec p4-dpi-container bash -c "grep 'mac_forward\\|ipv4_forward\\|arp_reply' logs/dpi_controller_worker.log | tail -20"
```

## P4 Program Details

### Pipeline (`p4_programs/dpi_l2_l4.p4`)

**Headers**: Ethernet, IPv4, IPv6, TCP, UDP, ICMP, ARP

**Parser**:
- Extracts L2 (Ethernet)
- Branches on EtherType: IPv4, IPv6, ARP
- Extracts L4 headers: TCP, UDP, ICMP (for v4), ICMPv6

**Ingress Control**:
1. **Packet Classification** (`packet_classifier`): Match on L2/L3/L4 protocols and ports → log_packet or drop
2. **Protocol Filtering** (`protocol_filter`): Match on L4 protocol → forward or drop
3. **Suspicious Detection** (`suspicious_detector`): Match on src/dst IP and ports → forward or drop
4. **ARP Handling** (`arp_reply`): Match on target IP → send_arp_reply(router_mac) and return to ingress port
5. **IPv4 Routing** (`ipv4_forward`): Match on dst IP → set_routing_params(port, src_mac, dst_mac) + TTL--
6. **MAC Forwarding** (`mac_forward`): Match on dst MAC → set_egress_port(port)

**Egress Control**: No-op (all logic in ingress)

**Checksum**: Updates IPv4 header checksum after TTL decrement

### Controller Workers (`scripts/p4_controller_worker.py`)

Each switch gets one dedicated Python process to hold P4Runtime session:
- Connects via gRPC to 127.0.0.1:5005{1,2,3}
- Pushes FwdPipeConfig (p4info.txt + compiled.json)
- Installs static table entries:
  - s1: ARP gateway replies, per-host IPv4 routes, MAC forwarding to uplinks
  - s2/s3: MAC forwarding for local hosts and uplink to s1
- Uses time-based election_id to avoid conflicts
- Holds session indefinitely (keeps leadership)

### Packet Logger (`scripts/packet_logger.py`)

- Scapy `sniff()` on all detected s*-eth* and h*-eth* interfaces
- Parses Ethernet → IPv4/IPv6 → TCP/UDP/ICMP
- Logs to SQLite `logs/packets.db` with timestamp, src/dst IPs/MACs/ports, protocol, size, flags
- Background tasks: periodic statistics, exports, cleanup
- Per-run export scheduled after initial delay (configurable)

## Logging and Monitoring

### Log Files
- `logs/dpi_system.log`: Main orchestrator log (start/stop, component status)
- `logs/dpi_controller_worker.log`: P4Runtime controller log (pipeline install, table programming)
- `logs/packet_logger.log`: Packet capture log (sniffer errors, DB writes)
- `logs/mininet.log`: Mininet topology log (switch start, host config)
- `logs/packets.db`: SQLite database (packets, flows, statistics tables)

### Database Schema
**packets**:
- id, timestamp, switch_id, src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port
- protocol, packet_size, tcp_flags, icmp_type, icmp_code
- is_fragment, is_malformed, is_suspicious
- layer2_protocol, layer3_protocol, layer4_protocol, ttl, tos, flow_id

**flows**:
- id, flow_id, src_ip, dst_ip, src_port, dst_port, protocol
- start_time, end_time, packet_count, total_bytes, is_suspicious

**statistics**:
- id, timestamp, total_packets, tcp_packets, udp_packets, icmp_packets
- suspicious_packets, top_protocols, top_ports, top_ips (JSON)

### Query Examples
```bash
# Total packets and protocol counts
docker exec p4-dpi-container bash -c "cd /p4-dpi && python3 scripts/db_query.py"

# Last 10 packets
docker exec p4-dpi-container bash -c "sqlite3 logs/packets.db 'SELECT src_ip, dst_ip, protocol, packet_size FROM packets ORDER BY id DESC LIMIT 10'"

# TCP traffic to port 80
docker exec p4-dpi-container bash -c "sqlite3 logs/packets.db 'SELECT COUNT(*) FROM packets WHERE dst_port=80 AND protocol=\"TCP\"'"
```

### Export Formats
- **JSON**: Array of packet objects with all fields
- **CSV**: Tabular format with headers
- Per-run exports: `packets_export_db_YYYYMMDD_HHMMSS.{json,csv}` (scheduled after startup)
- On-demand: Run `scripts/export_db.py` anytime

## Known Limitations

- **Single-threaded BMv2**: Each switch runs in one process; not suitable for high-throughput production
- **Static Routing**: IPv4 routes are statically programmed; no dynamic routing protocols
- **No L2 Learning**: MAC forwarding is static; no dynamic MAC learning
- **IPv6 Disabled**: Hosts configured to prefer IPv4 for testing; full IPv6 support is present in P4 but not exercised
- **No Multicast**: Broadcast handled via unicast to uplink; no PRE multicast groups configured
- **In-Container Only**: Topology runs inside Docker; not connected to external networks

## Security Considerations

### Network Security
- System requires `--privileged` Docker mode for Mininet network namespaces
- Use in isolated lab environments only
- Do not expose gRPC ports (50051-53) to untrusted networks

### Data Privacy
- Packet DB contains full packet headers (IPs, MACs, ports)
- Implement data retention and cleanup policies
- Export files may contain sensitive traffic metadata

### Access Control
- No authentication on P4Runtime (development setup)
- Protect SQLite DB file access
- Secure log directory permissions

## Troubleshooting

### Common Issues

#### Docker Build Fails
```bash
# Check Docker version (need 20.10+)
docker --version

# Ensure BuildKit is enabled
export DOCKER_BUILDKIT=1

# Clean and rebuild
docker-compose down
docker system prune -a
docker-compose build --no-cache
```

#### P4 Compilation Errors
```bash
# Check p4c installation
docker exec p4-dpi-container bash -c "p4c --version"

# Manually compile
docker exec p4-dpi-container bash -c "cd /p4-dpi && p4c --target bmv2 --arch v1model --p4runtime-files p4_programs/dpi_l2_l4.p4info.txt p4_programs/dpi_l2_l4.p4"

# Check for duplicate actions or syntax errors in p4_programs/dpi_l2_l4.p4
```

#### Switches Not Starting
```bash
# Check if interfaces exist
docker exec p4-dpi-container bash -c "ip link show | grep -E 's[123]-eth'"

# Clean stale Mininet state
docker exec p4-dpi-container bash -c "mn -c"

# Check simple_switch_grpc binary
docker exec p4-dpi-container bash -c "ls -l /p4-dpi/bmv2/targets/simple_switch_grpc/.libs/simple_switch_grpc"
```

#### P4Runtime Connection Fails
```bash
# Check gRPC ports are listening
docker exec p4-dpi-container bash -c "netstat -tln | grep -E '5005[123]'"

# Check controller worker logs
docker exec p4-dpi-container bash -c "tail -n 100 logs/dpi_controller_worker.log"

# Ensure switches started with --no-p4 (controller pushes pipeline)
docker exec p4-dpi-container bash -c "ps -ef | grep simple_switch_grpc | grep -- '--no-p4'"
```

#### No Packets Logged
```bash
# Check sniffer interfaces
docker exec p4-dpi-container bash -c "ls /sys/class/net/ | grep -E 's[123]-eth|h[123456]-eth'"

# Check packet_logger.log for errors
docker exec p4-dpi-container bash -c "tail -n 50 logs/packet_logger.log"

# Verify DB has tables
docker exec p4-dpi-container bash -c "sqlite3 logs/packets.db '.schema packets'"

# Test traffic manually
docker exec p4-dpi-container bash -c "ip netns exec h1 ping -c 3 10.0.2.1"
```

#### Only IPv6 Traffic (No IPv4)
```bash
# Verify IPv6 is disabled on hosts
docker exec p4-dpi-container bash -c "ip netns exec h1 sysctl net.ipv6.conf.all.disable_ipv6"

# Check ARP cache (should see router MAC)
docker exec p4-dpi-container bash -c "ip netns exec h1 ip neigh show"

# Check IPv4 forwarding entries on s1
docker exec p4-dpi-container bash -c "grep ipv4_forward logs/dpi_controller_worker.log"
```

### Debug Mode
Enable debug logging:
```yaml
# config/dpi_config.yaml
logging:
  level: DEBUG
```

Then restart and check verbose logs.

## Performance Tuning

### BMv2 Switch Optimization
- Use `--no-p4` startup and push pipeline via P4Runtime (already implemented)
- Disable log-file (use --log-console) to avoid spdlog issues (already implemented)
- Adjust `--device-id` and `--grpc-server-addr` per switch (already configured)

### Database Optimization
```yaml
# config/dpi_config.yaml or logging_config.yaml
retention:
  max_packets: 100000      # max packets in memory before cleanup
  max_age_days: 7          # auto-delete packets older than 7 days

performance:
  database:
    file: logs/packets.db
    max_size: 536870912    # 512MB limit
```

### Sniffer Optimization
- Auto-detect interfaces (avoid manual config)
- Run one sniffer thread per interface (already implemented)
- Filter at Scapy level if needed (e.g., `filter="ip"`)

### Memory Management
- Periodic cleanup task runs every hour
- In-memory packet list trimmed to `max_packets`
- Database rows older than `max_age_days` deleted automatically

## Extending the System

### Adding New Protocols (L7)
1. **Update P4 Program** (`p4_programs/dpi_l2_l4.p4`):
   ```p4
   header http_t {
       bit<8> method;  // GET, POST, etc.
       bit<16> status_code;
   }
   ```
2. **Add Parser State**:
   ```p4
   state parse_http {
       packet.extract(hdr.http);
       transition accept;
   }
   ```
3. **Add Control Logic**: New table for HTTP filtering/logging
4. **Update Logger**: Add HTTP fields to `packet_logger.py` parser

### Adding New Tables
1. Define table in P4 with keys, actions, size
2. Recompile P4 program
3. Update controller worker to install entries via P4Runtime:
   ```python
   te = TableEntry('MyIngress.new_table')(action='MyIngress.new_action')
   te.match['key_field'] = 'value'
   te.action['param'] = 'value'
   te.insert()
   ```

### Adding More Switches/Hosts
1. Edit `scripts/mininet_topology.py`:
   - Add switch: `s4 = self.net.addSwitch('s4', ...)`
   - Add host: `h7 = self.net.addHost('h7', ip='10.0.5.1/24', ...)`
   - Add links: `self.net.addLink('h7', 's4')`
2. Update `config/dpi_config.yaml`:
   ```yaml
   switches:
     - name: s4
       device_id: 4
       grpc_port: 50054
   ```
3. Update controller worker to program s4 tables

### Custom Traffic Patterns
1. Edit `scripts/mininet_topology.py` → `generate_traffic()`:
   ```python
   self.hosts['h1'].cmd('iperf3 -s &')
   self.hosts['h2'].cmd('iperf3 -c 10.0.2.1 -t 60 &')
   ```
2. Or use `scripts/traffic_generator.py` (currently minimal)

### Advanced Monitoring
- Add new fields to `packets` table schema
- Extend `PacketInfo` dataclass in `packet_logger.py`
- Add custom statistics collectors
- Implement alerting rules based on flow patterns

## Project Structure

```
P4 DPI/
├── docker-compose.yml          # Container orchestration
├── Dockerfile                  # Build P4 toolchain + Mininet
├── requirements.txt            # Python dependencies
├── setup.py                    # Package setup
├── README.md                   # This file
├── config/
│   ├── dpi_config.yaml         # Main system config (switches, logging)
│   ├── logging_config.yaml     # Packet logger config
│   └── traffic_config.yaml     # Traffic patterns (unused currently)
├── p4_programs/
│   ├── dpi_l2_l4.p4            # P4 source (L2/L3/L4 + ARP)
│   ├── dpi_l2_l4.json          # Compiled BMv2 JSON (generated)
│   └── dpi_l2_l4.p4info.txt    # P4Runtime metadata (generated)
├── scripts/
│   ├── start_dpi.py            # Main orchestrator
│   ├── mininet_topology.py     # Network topology (3 switches, 6 hosts)
│   ├── p4_controller.py        # Legacy controller (deprecated)
│   ├── p4_controller_worker.py # Per-switch P4Runtime worker
│   ├── packet_logger.py        # Scapy-based packet capture → SQLite
│   ├── traffic_generator.py    # Minimal traffic gen (mostly unused)
│   ├── export_db.py            # Export DB to JSON/CSV
│   ├── check_db.py             # Query packet count
│   └── db_query.py             # Query stats and last 10 packets
├── logs/                       # Generated logs and DB
│   ├── dpi_system.log
│   ├── dpi_controller_worker.log
│   ├── packet_logger.log
│   ├── mininet.log
│   ├── packets.db              # SQLite (packets, flows, statistics)
│   └── packets_export_db_*.{json,csv}
├── templates/
│   └── dashboard.html          # Web UI (disabled by default)
└── tests/
    └── test_dpi_system.py      # Unit tests (minimal)
```

## References

- **P4 Language**: [p4.org](https://p4.org/) - P4_16 specification and tutorials
- **BMv2**: [behavioral-model](https://github.com/p4lang/behavioral-model) - P4 software switch
- **P4Runtime**: [p4runtime-spec](https://p4.org/p4-spec/p4runtime/main/P4Runtime-Spec.html) - Control plane API
- **Mininet**: [mininet.org](http://mininet.org/) - Network emulator
- **Scapy**: [scapy.net](https://scapy.net/) - Packet manipulation library
- **p4runtime-sh**: [p4runtime-shell](https://github.com/p4lang/p4runtime-shell) - Python P4Runtime client

## Acknowledgments

- P4 Language Consortium for the P4 specification and toolchain
- Open Networking Foundation for P4Runtime
- Mininet project for network emulation
- Scapy contributors for packet parsing
- Docker community for containerization
