import React from 'react';
import { useArgusSimulation } from '../hooks/useArgusSimulation';
import Timeline from './Timeline';
import FileInventory from './FileInventory';
import AttackGraph from './AttackGraph';
import IncidentReport from './IncidentReport';
import { Shield, PlayCircle, RotateCcw, AlertTriangle, Clock, Activity, ShieldCheck, CheckCircle2 } from 'lucide-react';

const ArgusSimulation: React.FC = () => {
  const {
    phase,
    scenario,
    files,
    logs,
    metrics,
    SCENARIOS,
    selectScenario,
    startSimulation,
    reset,
    reportToCyberCell,
    startAdaptation
  } = useArgusSimulation();

  const getPhaseBadgeColor = () => {
    switch(phase) {
      case 'IDLE': return 'bg-slate-800 text-slate-300 border-slate-600';
      case 'ATTACK': return 'bg-red-950 text-red-400 border-red-800 animate-pulse';
      case 'DETECTED': return 'bg-orange-950 text-orange-400 border-orange-800';
      case 'CONTAINED': return 'bg-yellow-950 text-yellow-400 border-yellow-800';
      case 'LEAK_ASSESSMENT': return 'bg-purple-950 text-purple-400 border-purple-800';
      case 'REPORTING': return 'bg-blue-950 text-blue-400 border-blue-800';
      case 'INVESTIGATING': return 'bg-indigo-950 text-indigo-400 border-indigo-800';
      case 'ADAPTING': return 'bg-emerald-950 text-emerald-400 border-emerald-800';
      case 'RECOVERED': return 'bg-green-950 text-green-400 border-green-800';
      default: return 'bg-slate-800 text-slate-300';
    }
  };

  const getGlobalBgColor = () => {
    switch(phase) {
      case 'ATTACK':
      case 'DETECTED': return 'bg-red-950/20';
      case 'RECOVERED': return 'bg-emerald-950/20';
      default: return 'bg-slate-950';
    }
  };

  return (
    <div className={`min-h-screen text-slate-50 font-sans transition-colors duration-1000 ${getGlobalBgColor()}`}>
      {/* HEADER */}
      <header className="border-b border-slate-800 bg-slate-950/50 backdrop-blur sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Shield className={`w-8 h-8 ${phase === 'RECOVERED' ? 'text-emerald-500' : 'text-blue-500'}`} />
            <div>
              <h1 className="font-bold text-xl tracking-tight">ARGUS Engine</h1>
              <p className="text-xs text-slate-400 uppercase tracking-wider">Security Intelligence Sandbox</p>
            </div>
          </div>

          <div className="flex items-center gap-6">
            <div className="flex items-center gap-2">
              <span className="text-sm text-slate-400">Scenario:</span>
              <select
                className="bg-slate-900 border border-slate-700 rounded px-3 py-1.5 text-sm text-slate-200 focus:outline-none focus:border-blue-500 disabled:opacity-50"
                value={scenario.id}
                onChange={(e) => selectScenario(e.target.value)}
                disabled={phase !== 'IDLE'}
              >
                {SCENARIOS.map(s => <option key={s.id} value={s.id}>{s.name}</option>)}
              </select>
            </div>

            <div className="h-6 w-px bg-slate-800"></div>

            <div className="flex items-center gap-3">
              <span className={`px-3 py-1 rounded-full text-xs font-semibold border uppercase tracking-wider flex items-center gap-2 ${getPhaseBadgeColor()}`}>
                {phase === 'ATTACK' || phase === 'DETECTED' ? <AlertTriangle className="w-3 h-3"/> : ''}
                {phase === 'RECOVERED' ? <ShieldCheck className="w-3 h-3"/> : ''}
                {phase.replace('_', ' ')}
              </span>

              {phase === 'IDLE' ? (
                <button onClick={startSimulation} className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-1.5 rounded text-sm font-medium flex items-center gap-2 transition-colors">
                  <PlayCircle className="w-4 h-4" /> Start Simulation
                </button>
              ) : (
                <button onClick={reset} className="bg-slate-800 hover:bg-slate-700 text-slate-200 px-4 py-1.5 rounded text-sm font-medium flex items-center gap-2 transition-colors">
                  <RotateCcw className="w-4 h-4" /> Reset Sandbox
                </button>
              )}
            </div>
          </div>
        </div>
      </header>

      {/* MAIN LAYOUT */}
      <main className="max-w-7xl mx-auto px-4 py-8 grid grid-cols-12 gap-6 h-[calc(100vh-4rem)]">

        {/* LEFT COLUMN: Files & Metrics */}
        <div className="col-span-4 flex flex-col gap-6 h-full">
          {/* Metrics Panel */}
          <div className="bg-slate-900 border border-slate-800 rounded-lg p-5">
            <h3 className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-4 flex items-center gap-2">
              <Activity className="w-4 h-4" /> Response Telemetry
            </h3>

            <div className="space-y-4">
              <div>
                <div className="flex justify-between text-sm mb-1">
                  <span className="text-slate-300">Time to Detect (TTD)</span>
                  <span className="font-mono text-blue-400">
                    {metrics.detectTimeMs ? `${(metrics.detectTimeMs / 1000).toFixed(3)}s` : '---'}
                  </span>
                </div>
                <div className="h-1.5 w-full bg-slate-800 rounded overflow-hidden">
                  <div className={`h-full bg-blue-500 transition-all duration-1000 ${metrics.detectTimeMs ? 'w-full' : 'w-0'}`}></div>
                </div>
              </div>

              <div>
                <div className="flex justify-between text-sm mb-1">
                  <span className="text-slate-300">Time to Contain (TTC)</span>
                  <span className="font-mono text-yellow-400">
                    {metrics.containTimeMs ? `${(metrics.containTimeMs / 1000).toFixed(3)}s` : '---'}
                  </span>
                </div>
                <div className="h-1.5 w-full bg-slate-800 rounded overflow-hidden">
                  <div className={`h-full bg-yellow-500 transition-all duration-1000 ${metrics.containTimeMs ? 'w-full' : 'w-0'}`}></div>
                </div>
              </div>

              <div className="pt-3 border-t border-slate-800 flex justify-between items-center">
                <span className="text-sm font-medium text-slate-300 flex items-center gap-2">
                  <Clock className="w-4 h-4 text-slate-500" /> Total Exposure Window
                </span>
                <span className="font-mono text-lg font-bold text-slate-100">
                  {metrics.totalResponseTimeMs ? `${(metrics.totalResponseTimeMs / 1000).toFixed(3)}s` : '---'}
                </span>
              </div>
            </div>
          </div>

          {/* File Inventory Panel */}
          <div className="flex-1 min-h-0">
             <FileInventory files={files} />
          </div>
        </div>

        {/* MIDDLE COLUMN: Dynamic Main View */}
        <div className="col-span-5 h-full flex flex-col min-h-0">
          <div className="bg-slate-900 border border-slate-800 rounded-lg flex-1 overflow-hidden relative">
            {phase === 'IDLE' && (
              <div className="absolute inset-0 flex flex-col items-center justify-center text-slate-500 p-8 text-center">
                <ShieldCheck className="w-16 h-16 mb-4 opacity-20" />
                <h2 className="text-xl font-semibold mb-2 text-slate-400">Sandbox Ready</h2>
                <p>Select a scenario and click Start Simulation to begin the attack lifecycle visualization.</p>
              </div>
            )}

            {(phase === 'ATTACK' || phase === 'DETECTED' || phase === 'CONTAINED' || phase === 'LEAK_ASSESSMENT') && (
              <div className="absolute inset-0 flex flex-col items-center justify-center animate-in fade-in">
                <Activity className={`w-24 h-24 mb-6 ${phase === 'CONTAINED' || phase === 'LEAK_ASSESSMENT' ? 'text-yellow-500' : 'text-red-500 animate-pulse'}`} />
                <h2 className="text-2xl font-bold mb-2">
                  {phase === 'CONTAINED' ? 'Threat Contained' : phase === 'LEAK_ASSESSMENT' ? 'Assessing Data Impact...' : 'Active Threat Detected'}
                </h2>
                <p className="text-slate-400 font-mono text-sm">Monitoring simulated endpoint memory and file system events.</p>
              </div>
            )}

            {phase === 'REPORTING' && (
              <IncidentReport scenario={scenario} files={files} onAuthorize={reportToCyberCell} />
            )}

            {(phase === 'INVESTIGATING' || phase === 'ADAPTING' || phase === 'RECOVERED') && (
              <div className="p-6 h-full flex flex-col animate-in fade-in">
                <AttackGraph scenario={scenario} phase={phase} />

                {phase === 'INVESTIGATING' && (
                  <div className="mt-6 flex justify-center">
                    <button onClick={startAdaptation} className="bg-emerald-600 hover:bg-emerald-700 text-white px-6 py-2 rounded font-medium flex items-center gap-2 animate-pulse">
                      <Shield className="w-4 h-4" /> Synthesize Defensive Rule
                    </button>
                  </div>
                )}

                {phase === 'RECOVERED' && (
                  <div className="mt-6 p-4 bg-emerald-950/50 border border-emerald-900 rounded flex items-start gap-3">
                    <CheckCircle2 className="w-5 h-5 text-emerald-500 mt-0.5" />
                    <div>
                      <h4 className="font-medium text-emerald-400">Simulation Complete</h4>
                      <p className="text-sm text-emerald-200 mt-1">Attack path successfully mapped. New semantic rule deployed. File state restored to pristine condition via shadow copy.</p>
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

        {/* RIGHT COLUMN: Timeline */}
        <div className="col-span-3 h-full min-h-0">
          <Timeline logs={logs} />
        </div>

      </main>
    </div>
  );
};

export default ArgusSimulation;