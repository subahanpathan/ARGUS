import React from 'react';
import { LogEntry } from '../hooks/useArgusSimulation';
import { Shield, AlertTriangle, Info, CheckCircle } from 'lucide-react';

interface TimelineProps {
  logs: LogEntry[];
}

const Timeline: React.FC<TimelineProps> = ({ logs }) => {
  const getIcon = (level: string) => {
    switch (level) {
      case 'critical': return <Shield className="w-5 h-5 text-red-500" />;
      case 'warn': return <AlertTriangle className="w-5 h-5 text-yellow-500" />;
      case 'success': return <CheckCircle className="w-5 h-5 text-green-500" />;
      default: return <Info className="w-5 h-5 text-blue-400" />;
    }
  };

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 h-full flex flex-col">
      <h3 className="text-lg font-semibold text-slate-100 mb-4 flex items-center gap-2">
        <ActivityIcon />
        Live Event Timeline
      </h3>
      <div className="flex-1 overflow-y-auto space-y-4 pr-2 custom-scrollbar">
        {logs.length === 0 ? (
          <div className="text-slate-500 text-sm text-center mt-10">Awaiting events...</div>
        ) : (
          logs.map((log) => (
            <div key={log.id} className="flex gap-3 text-sm animate-in fade-in slide-in-from-bottom-2">
              <div className="mt-0.5">{getIcon(log.level)}</div>
              <div>
                <div className="text-slate-400 text-xs">
                  {log.timestamp.toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit', fractionalSecondDigits: 3 })}
                </div>
                <div className={`mt-1 ${log.level === 'critical' ? 'text-red-400 font-medium' : log.level === 'success' ? 'text-green-400' : 'text-slate-300'}`}>
                  {log.message}
                </div>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};

const ActivityIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="text-blue-500">
    <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline>
  </svg>
);

export default Timeline;