#!/usr/bin/env python3
"""
Test the Render API deployment locally before pushing
"""

import requests
import json
import time

def test_api(base_url="http://localhost:10000"):
    """Test all API endpoints"""
    
    print(f"🧪 Testing API at {base_url}\n")
    
    # Test 1: Root endpoint
    print("1. Testing root endpoint...")
    try:
        response = requests.get(f"{base_url}/")
        print(f"   ✓ Status: {response.status_code}")
        print(f"   Response: {json.dumps(response.json(), indent=2)}\n")
    except Exception as e:
        print(f"   ✗ Error: {e}\n")
        return
    
    # Test 2: Health check
    print("2. Testing health endpoint...")
    try:
        response = requests.get(f"{base_url}/api/health")
        data = response.json()
        print(f"   ✓ Status: {response.status_code}")
        print(f"   Database: {data.get('status')}")
        print(f"   Packet count: {data.get('packet_count')}\n")
    except Exception as e:
        print(f"   ✗ Error: {e}\n")
        return
    
    # Test 3: Upload sample packets
    print("3. Testing packet upload...")
    sample_packets = [
        {
            "timestamp": "2025-12-01 12:00:00",
            "src_ip": "10.0.1.2",
            "dst_ip": "10.0.2.3",
            "src_port": 50123,
            "dst_port": 80,
            "protocol": "TCP",
            "packet_size": 1024,
            "ttl": 64,
            "is_suspicious": 0,
            "is_malformed": 0
        },
        {
            "timestamp": "2025-12-01 12:00:01",
            "src_ip": "10.0.1.2",
            "dst_ip": "8.8.8.8",
            "src_port": 51234,
            "dst_port": 53,
            "protocol": "UDP",
            "packet_size": 512,
            "ttl": 64,
            "is_suspicious": 0,
            "is_malformed": 0
        },
        {
            "timestamp": "2025-12-01 12:00:02",
            "src_ip": "192.168.1.100",
            "dst_ip": "10.0.1.1",
            "src_port": 0,
            "dst_port": 0,
            "protocol": "ICMP",
            "packet_size": 84,
            "ttl": 64,
            "is_suspicious": 0,
            "is_malformed": 0
        }
    ]
    
    try:
        response = requests.post(
            f"{base_url}/api/upload",
            json={"packets": sample_packets},
            timeout=10
        )
        data = response.json()
        print(f"   ✓ Status: {response.status_code}")
        print(f"   Inserted: {data.get('inserted')}/{data.get('total')}\n")
    except Exception as e:
        print(f"   ✗ Error: {e}\n")
    
    # Test 4: Get recent packets
    print("4. Testing recent packets endpoint...")
    try:
        response = requests.get(f"{base_url}/api/packets/recent?limit=10")
        data = response.json()
        print(f"   ✓ Status: {response.status_code}")
        print(f"   Packets returned: {data.get('count')}")
        if data.get('count', 0) > 0:
            print(f"   Sample packet: {json.dumps(data['data'][0], indent=2)}\n")
        else:
            print("   No packets in database\n")
    except Exception as e:
        print(f"   ✗ Error: {e}\n")
    
    # Test 5: Get statistics
    print("5. Testing statistics endpoint...")
    try:
        response = requests.get(f"{base_url}/api/stats")
        data = response.json()
        stats = data.get('data', {})
        print(f"   ✓ Status: {response.status_code}")
        print(f"   Total packets: {stats.get('total_packets')}")
        print(f"   Suspicious: {stats.get('suspicious_packets')}")
        print(f"   Protocols: {len(stats.get('protocols', []))}\n")
    except Exception as e:
        print(f"   ✗ Error: {e}\n")
    
    # Test 6: SSE Stream (just check if endpoint responds)
    print("6. Testing SSE stream endpoint...")
    try:
        response = requests.get(f"{base_url}/stream", stream=True, timeout=3)
        print(f"   ✓ Status: {response.status_code}")
        print(f"   Content-Type: {response.headers.get('Content-Type')}")
        print("   Streaming endpoint is working\n")
    except requests.exceptions.ReadTimeout:
        print("   ✓ Stream endpoint connected (timeout expected)\n")
    except Exception as e:
        print(f"   ✗ Error: {e}\n")
    
    print("✅ All tests completed!\n")

if __name__ == "__main__":
    import sys
    
    base_url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:10000"
    test_api(base_url)
