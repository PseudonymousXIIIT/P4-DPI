import React, { useMemo } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from './ui/card';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts';

const PacketSizeChart = ({ packets }) => {
  const sizeData = useMemo(() => {
    const ranges = [
      { name: '0-100', min: 0, max: 100, count: 0 },
      { name: '101-500', min: 101, max: 500, count: 0 },
      { name: '501-1000', min: 501, max: 1000, count: 0 },
      { name: '1001-1500', min: 1001, max: 1500, count: 0 }
    ];

    packets.forEach(packet => {
      const size = packet.packet_size;
      const range = ranges.find(r => size >= r.min && size <= r.max);
      if (range) {
        range.count++;
      }
    });

    return ranges.map(({ name, count }) => ({ name, count }));
  }, [packets]);

  const CustomTooltip = ({ active, payload }) => {
    if (active && payload && payload.length) {
      return (
        <div className="bg-slate-900 border border-slate-700 p-3 rounded-lg shadow-xl">
          <p className="text-slate-100 font-semibold">{payload[0].payload.name} bytes</p>
          <p className="text-cyan-400 text-sm">Packets: {payload[0].value}</p>
        </div>
      );
    }
    return null;
  };

  return (
    <Card className="border-slate-800 bg-slate-900/50 backdrop-blur-sm">
      <CardHeader>
        <CardTitle className="text-slate-100">Packet Size Distribution</CardTitle>
      </CardHeader>
      <CardContent>
        <ResponsiveContainer width="100%" height={300}>
          <BarChart data={sizeData}>
            <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
            <XAxis 
              dataKey="name" 
              stroke="#94a3b8"
              style={{ fontSize: '12px' }}
            />
            <YAxis 
              stroke="#94a3b8"
              style={{ fontSize: '12px' }}
            />
            <Tooltip content={<CustomTooltip />} />
            <Bar 
              dataKey="count" 
              fill="#06b6d4"
              radius={[8, 8, 0, 0]}
            />
          </BarChart>
        </ResponsiveContainer>
      </CardContent>
    </Card>
  );
};

export default PacketSizeChart;