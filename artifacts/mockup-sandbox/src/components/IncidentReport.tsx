import React, { useState } from 'react';
import { ScenarioDef, SimulatedFile } from '../lib/scenarios';
import { ShieldAlert, FileWarning, Send, CheckCircle2 } from 'lucide-react';

interface IncidentReportProps {
  scenario: ScenarioDef;
  files: SimulatedFile[];
  onAuthorize: () => void;
}

const IncidentReport: React.FC<IncidentReportProps> = ({ scenario, files, onAuthorize }) => {
  const [authorized, setAuthorized] = useState(false);

  const leakedFiles = files.filter(f => f.status === 'leaked');
  const corruptedFiles = files.filter(f => f.status === 'corrupted');

  const handleAuthorize = () => {
    setAuthorized(true);
    onAuthorize();
  };

  if (authorized) {
    return (
      <div className="h-full flex flex-col items-center justify-center p-8 text-center animate-in zoom-in-95">
        <CheckCircle2 className="w-16 h-16 text-emerald-500 mb-4" />
        <h2 className="text-2xl font-bold text-slate-100 mb-2">Report Transmitted</h2>
        <p className="text-slate-400 max-w-md">
          Incident report successfully submitted to Cyber Cell endpoint. Awaiting response and defensive signatures...
        </p>
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col p-6 animate-in fade-in">
      <div className="flex items-center gap-3 mb-6 pb-4 border-b border-red-900/50">
        <ShieldAlert className="w-8 h-8 text-red-500" />
        <div>
          <h2 className="text-xl font-bold text-red-100">Critical Incident Report Draft</h2>
          <p className="text-sm text-red-400">Consent required for telemetry transmission</p>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto space-y-6 pr-4 custom-scrollbar text-sm">
        <div className="grid grid-cols-2 gap-4">
          <div className="bg-slate-900 p-4 rounded border border-slate-700">
            <span className="text-slate-400 block mb-1">Incident Type</span>
            <span className="text-slate-100 font-semibold">{scenario.name}</span>
          </div>
          <div className="bg-slate-900 p-4 rounded border border-slate-700">
            <span className="text-slate-400 block mb-1">Threat Family</span>
            <span className="text-slate-100 font-semibold">{scenario.family}</span>
          </div>
          <div className="bg-slate-900 p-4 rounded border border-slate-700">
            <span className="text-slate-400 block mb-1">Confidence</span>
            <span className="text-slate-100 font-semibold">{scenario.confidence}%</span>
          </div>
          <div className="bg-slate-900 p-4 rounded border border-slate-700">
            <span className="text-slate-400 block mb-1">Endpoint ID</span>
            <span className="text-slate-100 font-semibold">Endpoint-01 (Simulated)</span>
          </div>
        </div>

        <div className="bg-red-950/30 p-4 rounded border border-red-900/50">
          <h3 className="text-red-300 font-semibold mb-3 flex items-center gap-2">
            <FileWarning className="w-4 h-4" /> Data Impact Assessment
          </h3>
          {leakedFiles.length > 0 || corruptedFiles.length > 0 ? (
            <ul className="space-y-2">
              {leakedFiles.map(f => (
                <li key={f.id} className="text-slate-300 flex justify-between">
                  <span>{f.name}</span> <span className="text-purple-400 text-xs uppercase px-2 bg-purple-950 rounded">Exfiltrated</span>
                </li>
              ))}
              {corruptedFiles.map(f => (
                <li key={f.id} className="text-slate-300 flex justify-between">
                  <span>{f.name}</span> <span className="text-orange-400 text-xs uppercase px-2 bg-orange-950 rounded">Encrypted</span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-slate-400 italic">No sensitive data access detected during the exposure window.</p>
          )}
        </div>

        <div className="bg-slate-900 p-4 rounded border border-slate-700 text-slate-300">
          <p className="mb-2"><strong>Notice:</strong> Submitting this report will transmit endpoint telemetry, process trees, and file hashes to the Cyber Cell for forensic analysis. No actual file contents will be uploaded.</p>
        </div>
      </div>

      <div className="mt-6 pt-6 border-t border-slate-800 flex justify-end gap-4">
        <button className="px-6 py-2 rounded font-medium text-slate-300 hover:bg-slate-800 transition-colors">
          Reject & Close
        </button>
        <button
          onClick={handleAuthorize}
          className="px-6 py-2 rounded font-medium bg-blue-600 hover:bg-blue-700 text-white flex items-center gap-2 transition-colors"
        >
          <Send className="w-4 h-4" />
          Authorize & Submit Report
        </button>
      </div>
    </div>
  );
};

export default IncidentReport;