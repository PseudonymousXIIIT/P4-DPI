# Packet Header Fields Parsed in P4-DPI

## Overview
This document summarizes which header fields are currently extracted and stored by `packet_logger.py` for each network stack layer, plus gaps and potential enhancements.

## Layer 2 (Ethernet)
Parsed:
- Source MAC (`src_mac`)
- Destination MAC (`dst_mac`)
- Protocol label (`layer2_protocol = 'Ethernet'`)

Not Parsed:
- Ethertype value
- 802.1Q / QinQ VLAN tags
- MPLS labels
- Frame padding length

## Layer 3 (IPv4)
Parsed:
- Source IP (`src_ip`)
- Destination IP (`dst_ip`)
- TTL (`ttl`)
- TOS / DSCP+ECN byte (`tos`)
- Protocol (derived from presence of TCP/UDP/ICMP layer)

Not Parsed:
- Header length (IHL)
- Total length
- Identification
- Flags (DF, MF)
- Fragment offset (thus `is_fragment` always False now)
- Header checksum validation
- IP options

## Layer 3 (IPv6)
Parsed:
- Source IPv6 address (`src_ip`)
- Destination IPv6 address (`dst_ip`)
- Hop Limit (stored in `ttl` field)
- Protocol label (`layer3_protocol = 'IPv6'`)

Not Parsed:
- Traffic Class
- Flow Label
- Payload Length
- Next Header numeric value
- Extension Headers (Fragment, Hop-by-Hop, Routing, Destination Options)
- Any fragmentation info (so `is_fragment` stays False)

## Layer 4 (TCP)
Parsed:
- Source port (`src_port`)
- Destination port (`dst_port`)
- TCP flags (bitmask in `tcp_flags`)
- Protocol label (`protocol = 'TCP'`, `layer4_protocol = 'TCP'`)
- Full packet length (`packet_size`)

Not Parsed:
- Sequence number
- Acknowledgment number
- Window size
- Urgent pointer
- Header length (data offset)
- TCP options (MSS, Window Scale, SACK, Timestamps, etc.)
- Payload length explicitly

## Layer 4 (UDP)
Parsed:
- Source port
- Destination port
- Protocol label (`UDP`)
- Full packet length (`packet_size`)

Not Parsed:
- UDP length field
- UDP checksum
- Payload length explicitly

## ICMP (IPv4) / ICMPv6
Parsed (IPv4 ICMP):
- ICMP type (`icmp_type`)
- ICMP code (`icmp_code`)
- Protocol label (`ICMP`)
Parsed (IPv6 variants):
- Protocol labels: `ICMPv6`, `ICMPv6-RS`, `ICMPv6-RA`, `ICMPv6-NS`, `ICMPv6-NA`

Not Parsed:
- Echo identifier & sequence
- Checksums
- Neighbor Discovery options (SLLA/TLLA, prefixes, MTU)
- Router Advertisement flags & lifetimes

## Cross-Layer / Meta
Parsed:
- `packet_size`: Total frame size (L2 upward)
- `flow_id`: Canonical bidirectional tuple (ordered by IP) plus protocol
- `is_suspicious`: Set by simple anomaly detectors (port scanning, PPS spikes, unusual protocol/port combos)
- `layer2_protocol`, `layer3_protocol`, `layer4_protocol`: Text labels

Not Parsed / Always Default:
- `is_fragment`: Always False (no fragment offset parsing yet)
- `is_malformed`: Always False (no checksum / structural validation)

## Anomaly Detection (Current Heuristics)
- Port Scan: >10 unique destination ports from same source in 60s
- DDoS: >100 packets to same destination in 1s
- Unusual Protocol-Port Combos: UDP on ports 22, 80, 443

## Potential Enhancements
1. Fragmentation support (IPv4 flags/offset, IPv6 fragment header)
2. TCP option extraction (store as JSON or separate table)
3. VLAN / Ethertype capture
4. ICMP/ICMPv6 extended fields (Echo IDs, ND options)
5. IPv6 extension headers list
6. Application layer parsing (DNS, HTTP, TLS SNI) via selective deep inspection
7. Payload entropy / size metrics per flow
8. Proper malformed detection (length mismatches, invalid checksums)
9. Rate metrics per flow (packets/sec, bytes/sec over sliding windows)
10. Suspicious pattern tagging for DNS amplification, TCP SYN floods, etc.

## Database Mapping
Table `packets` columns correspond directly to `PacketInfo` dataclass fields used above.

## Summary
The current implementation focuses on core addressing and transport identifiers (MAC/IP/ports/protocol + basic flags). It omits advanced header semantics (fragmentation, options, extension headers, app-layer details). These can be incrementally added without breaking existing schema by introducing new nullable columns or auxiliary tables.

---
Generated for internal DPI documentation.
