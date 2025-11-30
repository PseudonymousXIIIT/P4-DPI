/* P4 DPI Program for L2-L4 Deep Packet Inspection
 * Supports Ethernet, IPv4, IPv6, TCP, UDP, ICMP protocols
 * Designed for extensibility to L7 in the future
 */

#include <core.p4>
#include <v1model.p4>

// Define constants for protocol numbers
const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_IPV6 = 0x86dd;
const bit<16> TYPE_ARP = 0x806;
const bit<8> PROTO_TCP = 6;
const bit<8> PROTO_UDP = 17;
const bit<8> PROTO_ICMP = 1;
const bit<8> PROTO_ICMPV6 = 58;

// Define constants for well-known ports
const bit<16> PORT_HTTP = 80;
const bit<16> PORT_HTTPS = 443;
const bit<16> PORT_SSH = 22;
const bit<16> PORT_FTP = 21;
const bit<16> PORT_DNS = 53;
const bit<16> PORT_DHCP = 67;
const bit<16> PORT_DHCP_CLIENT = 68;
const bit<16> PORT_SNMP = 161;
const bit<16> PORT_TELNET = 23;
const bit<16> PORT_SMTP = 25;
const bit<16> PORT_POP3 = 110;
const bit<16> PORT_IMAP = 143;

// Header definitions
header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header ipv6_t {
    bit<4>  version;
    bit<8>  trafficClass;
    bit<20> flowLabel;
    bit<16> payloadLen;
    bit<8>  nextHdr;
    bit<8>  hopLimit;
    bit<128> srcAddr;
    bit<128> dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

header icmp_t {
    bit<8>  type_;
    bit<8>  code;
    bit<16> checksum;
    bit<16> identifier;
    bit<16> sequenceNumber;
}

// ARP header (for ARP request/response handling)
header arp_t {
    bit<16> htype;
    bit<16> ptype;
    bit<8>  hlen;
    bit<8>  plen;
    bit<16> oper;
    bit<48> sha;   // Sender hardware (MAC)
    bit<32> spa;   // Sender protocol (IPv4)
    bit<48> tha;   // Target hardware (MAC)
    bit<32> tpa;   // Target protocol (IPv4)
}

// Headers struct
struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    ipv6_t     ipv6;
    tcp_t      tcp;
    udp_t      udp;
    icmp_t     icmp;
    arp_t      arp;
}

// Metadata for packet processing
struct metadata {
    bit<32> timestamp;
    bit<8>  layer2_protocol;
    bit<8>  layer3_protocol;
    bit<8>  layer4_protocol;
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> src_ip;
    bit<32> dst_ip;
    bit<128> src_ipv6;
    bit<128> dst_ipv6;
    bit<48> src_mac;
    bit<48> dst_mac;
    bit<16> packet_size;
    bit<8>  tcp_flags;
    bit<8>  icmp_type;
    bit<8>  icmp_code;
    bit<1>  is_fragment;
    bit<1>  is_malformed;
    bit<1>  is_suspicious;
}

// Parser
parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        meta.src_mac = hdr.ethernet.srcAddr;
        meta.dst_mac = hdr.ethernet.dstAddr;
        meta.layer2_protocol = 1; // Ethernet
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            TYPE_IPV6: parse_ipv6;
            TYPE_ARP: parse_arp;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        meta.src_ip = hdr.ipv4.srcAddr;
        meta.dst_ip = hdr.ipv4.dstAddr;
        meta.layer3_protocol = 4; // IPv4
        meta.is_fragment = (bit<1>)((hdr.ipv4.flags & 0x1) != 0);
        transition select(hdr.ipv4.protocol) {
            PROTO_TCP: parse_tcp;
            PROTO_UDP: parse_udp;
            PROTO_ICMP: parse_icmp;
            default: accept;
        }
    }

    state parse_ipv6 {
        packet.extract(hdr.ipv6);
        meta.src_ipv6 = hdr.ipv6.srcAddr;
        meta.dst_ipv6 = hdr.ipv6.dstAddr;
        meta.layer3_protocol = 6; // IPv6
        transition select(hdr.ipv6.nextHdr) {
            PROTO_TCP: parse_tcp;
            PROTO_UDP: parse_udp;
            PROTO_ICMPV6: parse_icmp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        meta.src_port = hdr.tcp.srcPort;
        meta.dst_port = hdr.tcp.dstPort;
        meta.layer4_protocol = 6; // TCP
        meta.tcp_flags = (bit<8>)hdr.tcp.flags;
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        meta.src_port = hdr.udp.srcPort;
        meta.dst_port = hdr.udp.dstPort;
        meta.layer4_protocol = 17; // UDP
        transition accept;
    }

    state parse_icmp {
        packet.extract(hdr.icmp);
        meta.layer4_protocol = 1; // ICMP
        meta.icmp_type = hdr.icmp.type_;
        meta.icmp_code = hdr.icmp.code;
        transition accept;
    }

    state parse_arp {
        packet.extract(hdr.arp);
        meta.layer3_protocol = 2; // ARP
        transition accept;
    }
}

// Control plane
control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    // Action to log packet information
    action log_packet() {
        // This will be handled by the control plane
        // The P4 program just marks packets for logging
    }

    // (drop action defined below)

    // Action to forward packet to a specific port (used by L2 MAC table)
    action set_egress_port(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    // Action to drop
    action drop_packet() {
        mark_to_drop(standard_metadata);
    }

    // Action to set L3 forwarding parameters (rewrite Ethernet, choose egress)
    action set_routing_params(bit<9> port, bit<48> src_mac, bit<48> dst_mac) {
        hdr.ethernet.srcAddr = src_mac;
        hdr.ethernet.dstAddr = dst_mac;
        if (hdr.ipv4.isValid()) {
            hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        }
        standard_metadata.egress_spec = port;
    }

    // Action to send ARP reply back to the requester, using provided router MAC
    action send_arp_reply(bit<48> router_mac) {
        // Ethernet
        hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = router_mac;
        // ARP fields
        hdr.arp.oper = 2; // reply
        hdr.arp.tha = hdr.arp.sha;
        hdr.arp.sha = router_mac;
        hdr.arp.tpa = hdr.arp.spa;
        hdr.arp.spa = hdr.arp.tpa;
        // Return to ingress port
        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }

    // Table for packet classification and logging
    table packet_classifier {
        key = {
            meta.layer2_protocol: exact;
            meta.layer3_protocol: exact;
            meta.layer4_protocol: exact;
            meta.src_port: exact;
            meta.dst_port: exact;
        }
        actions = {
            log_packet;
            drop_packet;
        }
        size = 1024;
        default_action = log_packet;
    }

    // Table for suspicious traffic detection
    table suspicious_detector {
        key = {
            meta.src_ip: exact;
            meta.dst_ip: exact;
            meta.src_port: exact;
            meta.dst_port: exact;
        }
        actions = {
            set_egress_port;
            drop_packet;
        }
        size = 512;
        default_action = drop_packet;
    }

    // Table for protocol-based filtering
    table protocol_filter {
        key = {
            meta.layer4_protocol: exact;
        }
        actions = {
            set_egress_port;
            drop_packet;
        }
        size = 256;
        default_action = drop_packet;
    }

    // L2 MAC forwarding table: dst MAC -> egress port
    table mac_forward {
        key = {
            hdr.ethernet.dstAddr: exact;
        }
        actions = {
            set_egress_port;
            drop_packet;
        }
        size = 2048;
        default_action = drop_packet;
    }

    // L3 IPv4 forwarding table: dst IP -> (egress port, src/dst MAC)
    table ipv4_forward {
        key = {
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            set_routing_params;
            drop_packet;
        }
        size = 2048;
        default_action = drop_packet;
    }

    // ARP reply table: target IP -> send reply with router MAC
    table arp_reply {
        key = {
            hdr.arp.tpa: exact;
        }
        actions = {
            send_arp_reply;
            drop_packet;
        }
        size = 256;
        default_action = drop_packet;
    }

    apply {
        // Set timestamp
        meta.timestamp = (bit<32>)standard_metadata.ingress_global_timestamp;
        meta.packet_size = (bit<16>)standard_metadata.packet_length;

        // Check for malformed packets
        if (meta.layer3_protocol == 4 && hdr.ipv4.isValid()) {
            if (hdr.ipv4.ihl < 5 || hdr.ipv4.totalLen < 20) {
                meta.is_malformed = 1;
            }
        }

        // Apply protocol filtering and detection/logging
        protocol_filter.apply();
        suspicious_detector.apply();
        packet_classifier.apply();

        // Handle ARP (reply to gateway ARP locally when configured)
        if (hdr.arp.isValid()) {
            arp_reply.apply();
            return;
        }

        // L3 routing for IPv4
        if (hdr.ipv4.isValid()) {
            ipv4_forward.apply();
            return;
        }

        // Fallback to L2 MAC forwarding
        mac_forward.apply();
    }
}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.ipv6);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
        packet.emit(hdr.icmp);
        packet.emit(hdr.arp);
    }
}

// Main control block
V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
