import { useEffect, useState, useRef } from "react";

const BACKEND_URL = "http://localhost:5000";
const DATA_WINDOW_SECONDS = 12;

export const useStream = () => {
  const [packets, setPackets] = useState([]);
  const [isConnected, setIsConnected] = useState(false);
  const [connectionStatus, setConnectionStatus] = useState("connecting");
  
  const eventSourceRef = useRef(null);

  useEffect(() => {
    console.log("Connecting to SSE:", BACKEND_URL + "/stream");
    const es = new EventSource(BACKEND_URL + "/stream");
    eventSourceRef.current = es;

    // When SSE connection opens
    es.onopen = () => {
      console.log("SSE connected");
      setIsConnected(true);
      setConnectionStatus("connected");
    };

    // When SSE encounters a network error / disconnect
    es.onerror = (err) => {
      console.error("SSE error:", err);
      setIsConnected(false);               // <<------+------+ 
      setConnectionStatus("disconnected"); //        | Tracks dropped connection
                                           //        |
      // SSE auto-retries, so "pending reconnect"   |
      setTimeout(() => {                          // |
        setConnectionStatus("reconnecting");       // |
      }, 500);
    };

    // On receiving streamed packet data
    es.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);

        // const now = new Date(data.timestamp);
        // const cutoff = new Date(now.getTime() - DATA_WINDOW_SECONDS * 1000);

        // const filtered = data.packets.filter((p) => {
        //   const t = new Date(p.timestamp);
        //   return t >= cutoff;
        // });

        // setPackets(filtered.slice(0, 50));
        function utcToISTISO(utcTs) {
          const d = new Date(utcTs);
          const ist = new Date(d.getTime() + 5.5 * 60 * 60 * 1000);

          return ist.toISOString();
        }

        const packetsIST = data.packets.map(p => ({
          ...p,
          timestamp: utcToISTISO(p.timestamp)
        }));
        setPackets(packetsIST);
      } catch (err) {
        console.error("Failed parsing SSE message:", err);
      }
    };

    // Cleanup
    return () => {
      console.log("Closing SSE stream");
      es.close();
    };
  }, []);

  return {
    packets,
    isConnected,
    connectionStatus
  };
};
