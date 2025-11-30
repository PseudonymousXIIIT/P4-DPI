// Mock packet data generator for P4 DPI Dashboard

const protocols = ['TCP/HTTP', 'TCP/HTTPS', 'TCP/SSH', 'UDP/DNS', 'ICMP', 'UDP'];
const actions = ['forwarded', 'dropped'];
const sourceIPs = ['10.0.1.1', '10.0.1.2', '10.0.1.5', '192.168.1.10', '172.16.0.5'];
const destIPs = ['10.0.1.3', '10.0.1.4', '8.8.8.8', '1.1.1.1', '192.168.1.20'];

let packetIdCounter = 1;

export const generateMockPacket = () => {
  const protocol = protocols[Math.floor(Math.random() * protocols.length)];
  const sourcePort = protocol.includes('TCP') || protocol.includes('UDP') ? Math.floor(Math.random() * 60000) + 1024 : 'N/A';
  const destPort = protocol.includes('HTTP') ? 80 : protocol.includes('HTTPS') ? 443 : protocol.includes('SSH') ? 22 : protocol.includes('DNS') ? 53 : 'N/A';
  
  return {
    timestamp: new Date().toISOString(),
    packet_id: packetIdCounter++,
    source_ip: sourceIPs[Math.floor(Math.random() * sourceIPs.length)],
    dest_ip: destIPs[Math.floor(Math.random() * destIPs.length)],
    source_port: sourcePort,
    dest_port: destPort,
    protocol: protocol,
    packet_size: Math.floor(Math.random() * 1400) + 50,
    action: Math.random() > 0.15 ? 'forwarded' : 'dropped'
  };
};

export const generateInitialMockData = (count = 50) => {
  const data = [];
  for (let i = 0; i < count; i++) {
    data.push(generateMockPacket());
  }
  return data;
};

