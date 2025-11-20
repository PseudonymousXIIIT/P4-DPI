#!/usr/bin/env python3
"""Generate TLS/HTTPS test traffic for Layer 5 parsing validation."""
import time
from scapy.all import Ether, IP, TCP, Raw, sendp, get_if_list

# TLS ClientHello minimal structure for testing
def create_tls_client_hello():
    """Create a minimal TLS ClientHello packet."""
    # TLS Record Header: Content Type (0x16 = Handshake), Version (0x0303 = TLS 1.2), Length
    tls_record = bytes([0x16, 0x03, 0x03, 0x00, 0xA0])  # Record header, length 160 bytes
    
    # Handshake Header: Type (0x01 = ClientHello), Length
    handshake_hdr = bytes([0x01, 0x00, 0x00, 0x9C])  # ClientHello, length 156
    
    # ClientHello: Version (0x0303 = TLS 1.2), Random (32 bytes)
    client_version = bytes([0x03, 0x03])
    random_bytes = bytes([0x00] * 32)  # Simplified random
    
    # Session ID: Length + ID
    session_id_len = bytes([0x08])  # 8 bytes session ID
    session_id = bytes([0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44])
    
    # Cipher Suites: Length + suites
    cipher_len = bytes([0x00, 0x02])  # 2 bytes
    cipher_suites = bytes([0x00, 0x2F])  # TLS_RSA_WITH_AES_128_CBC_SHA
    
    # Compression Methods
    compression_len = bytes([0x01])
    compression = bytes([0x00])  # No compression
    
    # Extensions: Length + SNI extension
    ext_len = bytes([0x00, 0x10])  # 16 bytes of extensions
    
    # SNI Extension: Type (0x0000), Length, SNI List Length, Name Type (0x00 = hostname), Name Length, Name
    sni_type = bytes([0x00, 0x00])  # SNI extension type
    sni_len = bytes([0x00, 0x0C])  # 12 bytes
    sni_list_len = bytes([0x00, 0x0A])  # 10 bytes
    name_type = bytes([0x00])  # hostname
    name_len = bytes([0x00, 0x07])  # 7 bytes
    hostname = b'test.io'
    
    sni_ext = sni_type + sni_len + sni_list_len + name_type + name_len + hostname
    
    client_hello = (client_version + random_bytes + session_id_len + session_id +
                   cipher_len + cipher_suites + compression_len + compression +
                   ext_len + sni_ext)
    
    return tls_record + handshake_hdr + client_hello

def send_tls_test_packets(count=5):
    """Send test TLS ClientHello packets."""
    # Find switch interfaces
    ifaces = [iface for iface in get_if_list() if 's1-eth' in iface or 's2-eth' in iface]
    if not ifaces:
        print("No switch interfaces found")
        return
    
    target_iface = ifaces[0]
    print(f"Sending {count} TLS test packets on {target_iface}...")
    
    for i in range(count):
        tls_payload = create_tls_client_hello()
        
        pkt = (Ether(src='00:00:00:00:00:01', dst='00:aa:00:00:00:01') /
               IP(src='10.0.1.1', dst='10.0.2.1', ttl=64) /
               TCP(sport=50000+i, dport=443, flags='S') /
               Raw(load=tls_payload))
        
        sendp(pkt, iface=target_iface, verbose=0)
        print(f"  Sent TLS ClientHello #{i+1} with SNI=test.io, session_id=aabbccdd...")
        time.sleep(0.5)
    
    print(f"Done! Check DB for TLS session data.")

if __name__ == '__main__':
    send_tls_test_packets(5)
