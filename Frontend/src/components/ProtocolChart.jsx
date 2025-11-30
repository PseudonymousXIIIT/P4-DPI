import React, { useMemo } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from './ui/card';
import { PieChart, Pie, Cell, ResponsiveContainer, Legend, Tooltip } from 'recharts';

const COLORS = ['#06b6d4', '#10b981', '#f59e0b', '#8b5cf6', '#ec4899', '#14b8a6'];

const ProtocolChart = ({ packets }) => {
  const protocolData = useMemo(() => {
    const protocolCount = {};
    
    packets.forEach(packet => {
      const protocol = packet.protocol;
      protocolCount[protocol] = (protocolCount[protocol] || 0) + 1;
    });

    return Object.entries(protocolCount).map(([name, value]) => ({
      name,
      value
    }));
  }, [packets]);

  const CustomTooltip = ({ active, payload }) => {
    if (active && payload && payload.length) {
      const total = packets.length;
      const percentage = ((payload[0].value / total) * 100).toFixed(1);
      return (
        <div className="bg-slate-900 border border-slate-700 p-3 rounded-lg shadow-xl">
          <p className="text-slate-100 font-semibold">{payload[0].name}</p>
          <p className="text-slate-300 text-sm">Count: {payload[0].value}</p>
          <p className="text-slate-400 text-sm">{percentage}%</p>
        </div>
      );
    }
    return null;
  };

  return (
    <Card className="border-slate-800 bg-slate-900/50 backdrop-blur-sm">
      <CardHeader>
        <CardTitle className="text-slate-100">Protocol Distribution</CardTitle>
      </CardHeader>
      <CardContent>
        <ResponsiveContainer width="100%" height={300}>
          <PieChart>
            <Pie
              data={protocolData}
              cx="50%"
              cy="50%"
              labelLine={false}
              label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
              outerRadius={100}
              fill="#8884d8"
              dataKey="value"
            >
              {protocolData.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
              ))}
            </Pie>
            <Tooltip content={<CustomTooltip />} />
          </PieChart>
        </ResponsiveContainer>
      </CardContent>
    </Card>
  );
};

export default ProtocolChart;