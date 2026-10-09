import React from 'react';
import { ScenarioDef, SimulationPhase } from '../lib/scenarios';
import { Share2, Server, Database, ShieldAlert, Cpu } from 'lucide-react';

interface AttackGraphProps {
  scenario: ScenarioDef;
  phase: SimulationPhase;
}

const AttackGraph: React.FC<AttackGraphProps> = ({ scenario, phase }) => {
  const isVisible = ['INVESTIGATING', 'ADAPTING', 'RECOVERED'].includes(phase);

  if (!isVisible) {
    return (
      <div className="flex flex-col items-center justify-center h-full text-slate-500">
        <Share2 className="w-12 h-12 mb-4 opacity-20" />
        <p>Attack graph will be generated after containment.</p>
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col">
      <h3 className="text-lg font-semibold text-slate-100 mb-6">Forensic Attack Path Analysis</h3>

      <div className="flex-1 relative bg-slate-950 rounded-lg border border-slate-800 p-6 overflow-hidden">
        {/* Synthetic Nodes */}
        <div className="absolute top-1/2 left-10 -translate-y-1/2 flex flex-col items-center">
          <div className="w-16 h-16 rounded-full bg-red-900/50 border border-red-500 flex items-center justify-center z-10">
            <Server className="text-red-400 w-8 h-8" />
          </div>
          <span className="text-xs text-slate-400 mt-2">Entry Vector</span>
          <span className="text-[10px] text-red-400 mt-1 px-2 py-0.5 bg-red-950 rounded">{scenario.entryVector.split('->')[0]}</span>
        </div>

        {/* Path line */}
        <div className="absolute top-1/2 left-26 right-10 h-0.5 bg-gradient-to-r from-red-500 via-yellow-500 to-slate-700 -translate-y-1/2"></div>

        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 flex flex-col items-center">
          <div className="w-16 h-16 rounded-full bg-yellow-900/50 border border-yellow-500 flex items-center justify-center z-10 animate-pulse">
            <Cpu className="text-yellow-400 w-8 h-8" />
          </div>
          <span className="text-xs text-slate-400 mt-2">Endpoint-01</span>
          <span className="text-[10px] text-yellow-400 mt-1">Memory Injection</span>
        </div>

        <div className="absolute top-1/4 right-20 flex flex-col items-center">
          <div className="w-16 h-16 rounded-full bg-slate-800 border border-slate-600 flex items-center justify-center z-10">
            <Database className="text-slate-300 w-8 h-8" />
          </div>
          <span className="text-xs text-slate-400 mt-2">Target Files</span>
        </div>

        <div className="absolute bottom-1/4 right-20 flex flex-col items-center">
          <div className="w-16 h-16 rounded-full bg-slate-800 border border-slate-600 flex items-center justify-center z-10">
            <ShieldAlert className="text-slate-300 w-8 h-8" />
          </div>
          <span className="text-xs text-slate-400 mt-2">C2 Server</span>
        </div>

        {/* Connection lines to targets */}
        <svg className="absolute inset-0 w-full h-full pointer-events-none">
          <path d="M 50% 50% L 80% 25%" stroke="#64748b" strokeWidth="2" strokeDasharray="5,5" fill="none" />
          <path d="M 50% 50% L 80% 75%" stroke="#64748b" strokeWidth="2" strokeDasharray="5,5" fill="none" />
        </svg>

        {/* MITRE Panel */}
        <div className="absolute bottom-4 left-4 right-4 bg-slate-900 border border-slate-700 p-3 rounded text-sm">
          <div className="font-semibold text-slate-200 mb-2">Identified MITRE ATT&CK Techniques:</div>
          <div className="flex flex-wrap gap-2">
            {scenario.steps.map(s => (
              <span key={s.id} className="px-2 py-1 bg-slate-800 text-blue-300 rounded text-xs border border-slate-700">
                {s.technique}
              </span>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

export default AttackGraph;