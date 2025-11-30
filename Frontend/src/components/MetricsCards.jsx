import React from 'react';
import { Card, CardContent } from './ui/card';
import { Activity, Shield, Zap, Database } from 'lucide-react';

const MetricsCards = ({ packets }) => {
  const totalPackets = packets && packets.length > 0 ? packets.length : 0;
  const forwardedPackets = packets && packets.length > 0 
    ? packets.filter(p => p.action === 'forwarded').length 
    : 0;
  const droppedPackets = packets && packets.length > 0 
    ? packets.filter(p => p.action === 'dropped').length 
    : 0;
  const avgPacketSize = packets && packets.length > 0 
    ? Math.round(packets.reduce((sum, p) => sum + (p.packet_size || 0), 0) / packets.length)
    : 0;

  const metrics = [
    {
      title: 'Total Packets',
      value: totalPackets,
      icon: Activity,
      color: 'from-cyan-500 to-blue-500',
      bgColor: 'bg-cyan-500/10'
    },
    {
      title: 'Forwarded',
      value: forwardedPackets,
      icon: Zap,
      color: 'from-emerald-500 to-teal-500',
      bgColor: 'bg-emerald-500/10'
    },
    {
      title: 'Dropped',
      value: droppedPackets,
      icon: Shield,
      color: 'from-rose-500 to-pink-500',
      bgColor: 'bg-rose-500/10'
    },
    {
      title: 'Avg Size',
      value: `${avgPacketSize} B`,
      icon: Database,
      color: 'from-violet-500 to-purple-500',
      bgColor: 'bg-violet-500/10'
    }
  ];

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
      {metrics.map((metric, index) => (
        <Card key={index} className="border-slate-800 bg-slate-900/50 backdrop-blur-sm hover:bg-slate-900/70 transition-all duration-300">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-slate-400 mb-1">{metric.title}</p>
                <p className="text-3xl font-bold text-white">{metric.value}</p>
              </div>
              <div className={`${metric.bgColor} p-3 rounded-xl`}>
                <metric.icon className={`w-6 h-6 bg-gradient-to-br ${metric.color} bg-clip-text text-transparent`} style={{ filter: 'drop-shadow(0 0 8px currentColor)' }} />
              </div>
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  );
};

export default MetricsCards;