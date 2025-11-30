import React from 'react';
import { useWebSocket } from './hooks/useWebSocket';
import { useStream } from './hooks/useStream';
import MetricsCards from './components/MetricsCards';
import PacketFlowChart from './components/PacketFlowChart';
import ProtocolChart from './components/ProtocolChart';
import PacketSizeChart from './components/PacketSizeChart';
import PacketTable from './components/PacketTable';
import { Activity, Wifi, WifiOff } from 'lucide-react';

const Dashboard = () => {
  const { packets, isConnected, connectionStatus } = useStream();

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950" data-testid="dashboard-container">
      {/* Header */}
      <header className="border-b border-slate-800 bg-slate-900/50 backdrop-blur-sm sticky top-0 z-50" data-testid="dashboard-header">
        <div className="container mx-auto px-4 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-gradient-to-br from-cyan-500 to-blue-500 rounded-lg">
                <Activity className="w-6 h-6 text-white" />
              </div>
              <div>
                <h1 className="text-2xl font-bold text-white">P4 Deep Packet Inspection</h1>
                <p className="text-sm text-slate-400">Real-time Network Traffic Analysis (6 min delay)</p>
              </div>
            </div>
            <div className="flex items-center gap-2 px-4 py-2 bg-slate-800/50 rounded-lg border border-slate-700" data-testid="connection-status">
              {isConnected ? (
                <Wifi className="w-4 h-4 text-emerald-400" />
              ) : (
                <WifiOff className="w-4 h-4 text-amber-400" />
              )}
              <span className="text-sm text-slate-300 capitalize">{connectionStatus}</span>
              <div className={`w-2 h-2 rounded-full ${
                isConnected ? 'bg-emerald-400' : 'bg-amber-400'
              } animate-pulse`}></div>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="container mx-auto px-4 py-6" data-testid="dashboard-main">
        {/* Metrics Cards */}
        <MetricsCards packets={packets} />

        {/* Packet Flow Chart */}
        <div className="mb-6">
          <PacketFlowChart packets={packets} />
        </div>

        {/* Protocol and Size Charts */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
          <ProtocolChart packets={packets} />
          <PacketSizeChart packets={packets} />
        </div>

        {/* Live Packet Table */}
        <PacketTable packets={packets} />
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800 bg-slate-900/50 backdrop-blur-sm mt-12">
        <div className="container mx-auto px-4 py-6">
          <p className="text-center text-slate-500 text-sm">
            P4 DPI Dashboard
          </p>
        </div>
      </footer>
    </div>
  );
};

export default Dashboard;