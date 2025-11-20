# Starting DPI with Scapy Traffic Generation

## Quick Start Commands

### 1. Clean up and start fresh
```powershell
docker exec p4-dpi-container bash -lc "pkill -9 -f start_dpi.py; pkill -9 -f simple_switch_grpc; mn -c >/dev/null 2>&1; rm -f logs/packets.db logs/dpi.log; echo 'Cleanup done'"
```

### 2. Start DPI system (detached mode)
```powershell
docker exec -d p4-dpi-container bash -lc "cd /p4-dpi && export DPI_TRAFFIC_TARGET_PACKETS=600 && python3 scripts/start_dpi.py --mode start"
```

### 3. Monitor progress (optional, wait ~60 seconds)
```powershell
docker exec p4-dpi-container sh -c "sleep 60 && python3 scripts/check_db.py | head -n 2"
```

---

## Additional Commands

### Check current packet count anytime
```powershell
docker exec p4-dpi-container python3 scripts/check_db.py
```

### Stop DPI system manually
```powershell
docker exec p4-dpi-container bash -lc "pkill -9 -f start_dpi.py; pkill -9 -f simple_switch_grpc"
```

### Verify no stale processes
```powershell
docker exec p4-dpi-container bash -c "ps aux | grep -E 'start_dpi|simple_switch' | grep -v grep"
```
(Should return empty if clean)

---

## Configuration

- **Packet Rate:** 12-16 packets/second (hard-coded)
- **Default Packet Limit:** 600 packets per run (~40-50 seconds runtime)
- **Traffic Type:** Randomized ICMP/TCP/UDP packets with varying IPs, ports, TTL, TOS
- **Method:** Scapy-based injection on switch interfaces
- **Layer 5 Parsing:** TLS ClientHello (session ID, SNI, version) automatically extracted from HTTPS traffic

## Layer 5 (Session) Features

The system now parses Layer 5 session information:
- **TLS Session tracking:** Extracts session ID, TLS version, SNI (Server Name Indication)
- **Database fields:** `session_id`, `tls_version`, `tls_sni`, `tls_cipher`, `http2_stream_id`
- **Session table:** Separate `session_data` table for detailed session tracking

### Check Layer 5 Data
```powershell
docker exec p4-dpi-container python3 scripts/check_layer5.py
```

### Generate Test TLS Traffic
```powershell
docker exec p4-dpi-container python3 scripts/test_tls_layer5.py
```

## Notes

- The system generates ~1200 packets instead of exactly 600 due to batch processing
- Traffic stops automatically when packet limit is reached
- Database (logs/packets.db) accumulates packets across runs unless cleaned
- Always run cleanup command before starting to avoid multiple concurrent instances
