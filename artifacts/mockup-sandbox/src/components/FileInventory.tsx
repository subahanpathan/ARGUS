import React from 'react';
import { SimulatedFile } from '../lib/scenarios';
import { FileCode, Image, FileText, Settings, ShieldCheck, AlertOctagon, RefreshCcw } from 'lucide-react';

interface FileInventoryProps {
  files: SimulatedFile[];
}

const FileInventory: React.FC<FileInventoryProps> = ({ files }) => {
  const getFileIcon = (type: string) => {
    switch(type) {
      case 'system': return <Settings className="w-5 h-5" />;
      case 'image': return <Image className="w-5 h-5" />;
      case 'sensitive': return <AlertOctagon className="w-5 h-5" />;
      case 'executable': return <FileCode className="w-5 h-5" />;
      default: return <FileText className="w-5 h-5" />;
    }
  };

  const getStatusDisplay = (status: string) => {
    switch(status) {
      case 'safe': return <span className="flex items-center gap-1 text-green-400"><ShieldCheck className="w-4 h-4"/> Safe</span>;
      case 'malware': return <span className="flex items-center gap-1 text-red-500 animate-pulse"><AlertOctagon className="w-4 h-4"/> Malicious</span>;
      case 'deleted': return <span className="flex items-center gap-1 text-slate-500 line-through">Quarantined</span>;
      case 'corrupted': return <span className="flex items-center gap-1 text-orange-400">Encrypted</span>;
      case 'leaked': return <span className="flex items-center gap-1 text-purple-400">Exfiltrated</span>;
      case 'recovered': return <span className="flex items-center gap-1 text-emerald-400"><RefreshCcw className="w-4 h-4"/> Restored</span>;
      default: return <span>Unknown</span>;
    }
  };

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden h-full flex flex-col">
      <div className="p-4 border-b border-slate-800 bg-slate-950">
        <h3 className="text-lg font-semibold text-slate-100">Protected Workspace Inventory</h3>
        <p className="text-xs text-slate-400">Synthetic files used for impact analysis</p>
      </div>

      <div className="flex-1 overflow-y-auto p-4 custom-scrollbar">
        <table className="w-full text-sm text-left">
          <thead className="text-xs text-slate-400 uppercase bg-slate-900 border-b border-slate-700">
            <tr>
              <th className="px-4 py-3">File Name</th>
              <th className="px-4 py-3">Type</th>
              <th className="px-4 py-3 text-right">Status</th>
            </tr>
          </thead>
          <tbody>
            {files.map(file => (
              <tr key={file.id} className="border-b border-slate-800/50 hover:bg-slate-800/30 transition-colors">
                <td className="px-4 py-3 font-medium text-slate-200 flex items-center gap-3">
                  <div className={`p-2 rounded ${file.status === 'malware' ? 'bg-red-950 text-red-400' : 'bg-slate-800 text-slate-300'}`}>
                    {getFileIcon(file.type)}
                  </div>
                  {file.name}
                </td>
                <td className="px-4 py-3 text-slate-400 capitalize">{file.type}</td>
                <td className="px-4 py-3 text-right font-medium">
                  <div className="flex justify-end">{getStatusDisplay(file.status)}</div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default FileInventory;