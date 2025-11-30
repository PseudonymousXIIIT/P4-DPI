import { useState, useEffect, useRef } from 'react';
import { io } from 'socket.io-client';

// WebSocket hook for Flask backend connection
const BACKEND_URL = 'http://localhost:5000';
const TIME_OFFSET_SECONDS = 360; // 6 minutes behind
const DATA_WINDOW_SECONDS = 12; // Show only 10-12 seconds of data

export const useWebSocket = () => {
  const [packets, setPackets] = useState([]);
  const [isConnected, setIsConnected] = useState(false);
  const [connectionStatus, setConnectionStatus] = useState('connecting');
  const socketRef = useRef(null);
  const requestIntervalRef = useRef(null);

  useEffect(() => {
    console.log('Initializing Socket.IO connection to:', BACKEND_URL);

    // Create Socket.IO connection
    const socket = io(BACKEND_URL, {
      transports: ['websocket', 'polling'],
      reconnection: true,
      reconnectionDelay: 1000,
      reconnectionAttempts: 5
    });

    socketRef.current = socket;

    // Connection event handlers
    socket.on('connect', () => {
      console.log('Socket.IO connected');
      setIsConnected(true);
      setConnectionStatus('connected');
      
      // Start streaming when connected
      socket.emit('start_stream');
    });

    socket.on('disconnect', () => {
      console.log('Socket.IO disconnected');
      setIsConnected(false);
      setConnectionStatus('disconnected');
    });

    socket.on('connection_response', (data) => {
      console.log('Connection response:', data);
    });

    socket.on('stream_status', (data) => {
      console.log('Stream status:', data);
    });

    // Handle continuous packet stream
    socket.on('packets_stream', (data) => {
      console.log(`Received ${data.count} packets at ${data.timestamp}`);
      console.log(`Target time (6 min behind): ${data.target_time}`);
      
      if (data.packets && data.packets.length > 0) {
        // Filter to show only last 10-12 seconds of data
        const now = new Date(data.target_time);
        const cutoffTime = new Date(now.getTime() - DATA_WINDOW_SECONDS * 1000);
        
        const filteredPackets = data.packets.filter(packet => {
          const packetTime = new Date(packet.timestamp);
          return packetTime >= cutoffTime;
        });

        console.log(`Filtered to ${filteredPackets.length} packets within ${DATA_WINDOW_SECONDS}s window`);
        
        // Update packets (keep only the latest window)
        setPackets(filteredPackets.slice(0, 50));
      } else {
        console.log('No packets in current time window');
        // Keep existing packets but log that no new data is available
        setPackets(prev => prev.length > 0 ? prev : []);
      }
    });

    // Handle packets update (response to manual requests)
    socket.on('packets_update', (data) => {
      console.log(`Packets update: ${data.count} packets`);
      
      if (data.packets && data.packets.length > 0) {
        setPackets(data.packets.slice(0, 50));
      }
    });

    // Handle errors
    socket.on('error', (error) => {
      console.error('Socket.IO error:', error);
      setConnectionStatus('error');
    });

    socket.on('connect_error', (error) => {
      console.error('Connection error:', error);
      setIsConnected(false);
      setConnectionStatus('connection_error');
    });

    // Cleanup on unmount
    return () => {
      console.log('Cleaning up Socket.IO connection');
      
      if (socketRef.current) {
        socketRef.current.emit('stop_stream');
        socketRef.current.disconnect();
      }
      
      if (requestIntervalRef.current) {
        clearInterval(requestIntervalRef.current);
      }
    };
  }, []);

  // Manual request function (can be used to fetch specific data)
  const requestPackets = (offset = TIME_OFFSET_SECONDS) => {
    if (socketRef.current && socketRef.current.connected) {
      console.log(`Manually requesting packets with ${offset}s offset`);
      socketRef.current.emit('request_packets', { offset });
    }
  };

  return { 
    packets, 
    isConnected, 
    connectionStatus,
    requestPackets 
  };
};

