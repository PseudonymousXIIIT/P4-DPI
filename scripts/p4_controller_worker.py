#!/usr/bin/env python3
"""
P4 Controller Worker: manages a single switch connection using p4runtime_sh
Run one process per switch to avoid the singleton client limitation.
"""

import argparse
import logging
import os
import sys
import time
from p4runtime_sh.shell import setup as p4rt_setup, teardown as p4rt_teardown, FwdPipeConfig, TableEntry


def setup_logging(log_file: str = 'logs/dpi_controller_worker.log'):
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger('P4ControllerWorker')


def _program_mac_forward(logger, name: str):
    """Install static MAC forwarding entries per switch."""
    # Host MACs
    mac = {
        'h1': '00:00:00:00:00:01',
        'h2': '00:00:00:00:00:02',
        'h3': '00:00:00:00:00:03',
        'h4': '00:00:00:00:00:04',
        'h5': '00:00:00:00:00:05',
        'h6': '00:00:00:00:00:06',
    }
    BCAST = 'ff:ff:ff:ff:ff:ff'
    ROUTER_MAC = '00:aa:00:00:00:01'

    rules = []
    if name == 's1':
        # s1 ports: 1->h6, 2->s2, 3->s3
        # Route host MACs towards the correct inter-switch link
        for h in ('h1','h2','h5'):
            rules.append((mac[h], 2))
        for h in ('h3','h4'):
            rules.append((mac[h], 3))
        rules.append((mac['h6'], 1))
        # Optional: drop broadcast at s1 (arp handled by ARP table). No explicit rule added.
    elif name == 's2':
        # s2 ports: 1->h1, 2->h2, 3->h5, 4->s1
        rules.extend([
            (mac['h1'], 1),
            (mac['h2'], 2),
            (mac['h5'], 3),
            # Send traffic to router MAC and broadcasts up to s1
            (ROUTER_MAC, 4),
            (BCAST, 4),
        ])
    elif name == 's3':
        # s3 ports: 1->h3, 2->h4, 3->s1
        rules.extend([
            (mac['h3'], 1),
            (mac['h4'], 2),
            (ROUTER_MAC, 3),
            (BCAST, 3),
        ])

    for dst_mac, port in rules:
        try:
            te = TableEntry('MyIngress.mac_forward')(action='MyIngress.set_egress_port')
            te.match['hdr.ethernet.dstAddr'] = dst_mac
            te.action['port'] = str(port)
            te.insert()
            logger.info(f"[{name}] mac_forward: {dst_mac} -> {port}")
        except Exception as e:
            logger.error(f"[{name}] Failed to add mac_forward {dst_mac}->{port}: {e}")


def _program_s1_routing(logger):
    """Install ARP replies and IPv4 routing entries on s1."""
    ROUTER_MAC = '00:aa:00:00:00:01'
    # ARP gateway IPs per subnet
    gw_ips = ['10.0.1.254', '10.0.2.254', '10.0.3.254', '10.0.4.254']
    for ip in gw_ips:
        try:
            te = TableEntry('MyIngress.arp_reply')(action='MyIngress.send_arp_reply')
            te.match['hdr.arp.tpa'] = ip
            te.action['router_mac'] = ROUTER_MAC
            te.insert()
            logger.info(f"[s1] arp_reply: {ip} -> {ROUTER_MAC}")
        except Exception as e:
            logger.error(f"[s1] Failed to add arp_reply {ip}: {e}")

    # Host routing (dst IP -> egress port, src/dst MAC)
    host_map = [
        # ip, port, dst_mac
        ('10.0.1.1', 2, '00:00:00:00:00:01'),
        ('10.0.1.2', 2, '00:00:00:00:00:02'),
        ('10.0.3.1', 2, '00:00:00:00:00:05'),
        ('10.0.2.1', 3, '00:00:00:00:00:03'),
        ('10.0.2.2', 3, '00:00:00:00:00:04'),
        ('10.0.4.1', 1, '00:00:00:00:00:06'),
    ]
    for ip, port, dst_mac in host_map:
        try:
            te = TableEntry('MyIngress.ipv4_forward')(action='MyIngress.set_routing_params')
            te.match['hdr.ipv4.dstAddr'] = ip
            te.action['port'] = str(port)
            te.action['src_mac'] = ROUTER_MAC
            te.action['dst_mac'] = dst_mac
            te.insert()
            logger.info(f"[s1] ipv4_forward: {ip} -> port {port}, {ROUTER_MAC}->{dst_mac}")
        except Exception as e:
            logger.error(f"[s1] Failed to add ipv4_forward {ip}: {e}")


def connect_and_program(logger, name: str, device_id: int, grpc_port: int, p4info_path: str, json_path: str):
    grpc_addr = f"127.0.0.1:{grpc_port}"
    logger.info(f"[{name}] Connecting to {grpc_addr} device_id={device_id}")

    if not os.path.exists(p4info_path):
        logger.error(f"[{name}] Missing p4info: {p4info_path}")
        return False
    if not os.path.exists(json_path):
        logger.error(f"[{name}] Missing JSON: {json_path}")
        return False

    # Cleanup any previous session for this process
    try:
        p4rt_teardown()
        logger.info(f"[{name}] Cleaned previous P4Runtime session")
    except Exception:
        pass

    # Wait for simple_switch_grpc to be ready
    try:
        import grpc
        channel = grpc.insecure_channel(grpc_addr)
        grpc.channel_ready_future(channel).result(timeout=10)
        logger.info(f"[{name}] gRPC channel ready")
    except Exception as e:
        logger.error(f"[{name}] gRPC not ready: {e}")
        return False

    cfg = FwdPipeConfig(p4info=p4info_path, bin=json_path)
    try:
        p4rt_setup(
            device_id=device_id,
            grpc_addr=grpc_addr,
            election_id=(int(time.time()), device_id),
            config=cfg,
            verbose=True
        )
        logger.info(f"[{name}] Pipeline installed")
        # Program static entries based on switch role
        try:
            _program_mac_forward(logger, name)
            if name == 's1':
                _program_s1_routing(logger)
        except Exception as e:
            logger.error(f"[{name}] Error programming entries: {e}")
        return True
    except Exception as e:
        logger.exception(f"[{name}] Pipeline setup failed: {e}")
        return False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--name', required=True)
    parser.add_argument('--device-id', type=int, required=True)
    parser.add_argument('--grpc-port', type=int, required=True)
    parser.add_argument('--p4info', default='p4_programs/dpi_l2_l4.p4info.txt')
    parser.add_argument('--json', dest='json_path', default='p4_programs/dpi_l2_l4.json')
    args = parser.parse_args()

    logger = setup_logging()

    ok = connect_and_program(logger, args.name, args.device_id, args.grpc_port, args.p4info, args.json_path)
    if not ok:
        sys.exit(2)

    # Keep the process alive to hold leadership/session
    try:
        logger.info(f"[{args.name}] Controller worker running. Holding session...")
        while True:
            time.sleep(2)
    except KeyboardInterrupt:
        logger.info(f"[{args.name}] Shutting down")
    finally:
        try:
            p4rt_teardown()
        except Exception:
            pass


if __name__ == '__main__':
    main()
