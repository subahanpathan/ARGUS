import React, { useState, useMemo } from 'react';
import {
  TerminalSquare,
  Network,
  Cpu,
  HardDrive,
  User,
  AlertTriangle,
  ChevronRight,
  ChevronDown,
  Trash2,
  Crosshair,
  Search,
  Filter,
  Check,
  ExternalLink,
  ShieldAlert,
  ShieldCheck,
  Zap,
  Globe,
  Radio,
  Layers,
  ArrowRight,
} from 'lucide-react';
import type { RealProcessInfo } from '@/hooks/use-process-monitor';
import type { RealNetworkConnection } from '@/hooks/use-network-monitor';

export type ProcessTreeNode = RealProcessInfo & {
  children: ProcessTreeNode[];
  sockets: RealNetworkConnection[];
  isSuspicious: boolean;
  suspicionReasons: string[];
};

export interface ProcessTreeViewProps {
  processes: RealProcessInfo[];
  connections: RealNetworkConnection[];
  onNavigate?: (path: string) => void;
  toast: (title: string, body: string) => void;
  onRefresh?: () => void;
}

function checkSuspicion(p: RealProcessInfo, sockets: RealNetworkConnection[]): string[] {
  const reasons: string[] = [];
  const name = (p.name || '').toLowerCase();
  const path = (p.executable_path || '').toLowerCase();

  if (name.includes('powershell') || name.includes('pwsh')) {
    reasons.push('Script Host Execution (PowerShell)');
  }
  if (name.includes('cmd.exe')) {
    reasons.push('Command Shell Process');
  }
  if (
    name.includes('rundll32') ||
    name.includes('regsvr32') ||
    name.includes('mshta') ||
    name.includes('certutil') ||
    name.includes('bitsadmin')
  ) {
    reasons.push('Living-off-the-Land Binary (LOLBin)');
  }
  if (name.includes('7z') || name.includes('tar') || name.includes('rar') || name.includes('zip')) {
    reasons.push('Archival/Staging Tool');
  }
  if (name.includes('calc.exe') || name.includes('notepad.exe')) {
    if ((p.cpu_percent || 0) > 5) {
      reasons.push('Anomalous Execution Signature');
    }
  }
  if (path.includes('appdata\\local\\temp') || path.includes('downloads') || path.includes('users\\public')) {
    reasons.push('Executing from User Temp/Downloads Directory');
  }
  if ((p.cpu_percent || 0) > 20) {
    reasons.push(`High CPU Utilization (${p.cpu_percent?.toFixed(1)}%)`);
  }

  // Socket based suspicion
  const externalSockets = sockets.filter(
    (s) =>
      s.remote_addr &&
      !s.remote_addr.startsWith('127.') &&
      !s.remote_addr.startsWith('0.0.0.0') &&
      !s.remote_addr.startsWith('::')
  );
  if (externalSockets.length > 0) {
    reasons.push(`Active External Socket to ${externalSockets[0].remote_addr}:${externalSockets[0].remote_port || 443}`);
  }

  return reasons;
}

export default function ProcessTreeView({
  processes,
  connections,
  onNavigate,
  toast,
  onRefresh,
}: ProcessTreeViewProps) {
  const [searchTerm, setSearchTerm] = useState('');
  const [onlySuspicious, setOnlySuspicious] = useState(false);
  const [selectedPid, setSelectedPid] = useState<number | null>(null);
  const [expandedPids, setExpandedPids] = useState<Set<number>>(new Set());
  const [terminatingPid, setTerminatingPid] = useState<number | null>(null);

  // Map sockets by PID and process name
  const socketMap = useMemo(() => {
    const map = new Map<number, RealNetworkConnection[]>();
    for (const c of connections) {
      if (c.pid != null) {
        const list = map.get(c.pid) || [];
        list.push(c);
        map.set(c.pid, list);
      }
    }
    return map;
  }, [connections]);

  // Build the hierarchical tree
  const { rootNodes, totalSuspicious, allNodesMap } = useMemo(() => {
    const nodeMap = new Map<number, ProcessTreeNode>();
    let suspiciousCount = 0;

    // Create node objects
    for (const p of processes) {
      const pSockets = socketMap.get(p.pid) || [];
      const reasons = checkSuspicion(p, pSockets);
      const isSuspicious = reasons.length > 0;
      if (isSuspicious) suspiciousCount++;

      nodeMap.set(p.pid, {
        ...p,
        children: [],
        sockets: pSockets,
        isSuspicious,
        suspicionReasons: reasons,
      });
    }

    // Link parents to children
    const roots: ProcessTreeNode[] = [];
    for (const node of Array.from(nodeMap.values())) {
      if (node.parent_pid != null && nodeMap.has(node.parent_pid) && node.parent_pid !== node.pid) {
        nodeMap.get(node.parent_pid)!.children.push(node);
      } else {
        roots.push(node);
      }
    }

    // Sort roots to put trees containing suspicious nodes first
    function hasSuspiciousDescendant(n: ProcessTreeNode): boolean {
      if (n.isSuspicious) return true;
      return n.children.some(hasSuspiciousDescendant);
    }

    roots.sort((a, b) => {
      const aSusp = hasSuspiciousDescendant(a);
      const bSusp = hasSuspiciousDescendant(b);
      if (aSusp && !bSusp) return -1;
      if (!aSusp && bSusp) return 1;
      return (b.cpu_percent || 0) - (a.cpu_percent || 0);
    });

    return { rootNodes: roots, totalSuspicious: suspiciousCount, allNodesMap: nodeMap };
  }, [processes, socketMap]);

  // Toggle node expansion
  const toggleExpand = (pid: number) => {
    setExpandedPids((prev) => {
      const next = new Set(prev);
      if (next.has(pid)) next.delete(pid);
      else next.add(pid);
      return next;
    });
  };

  // Expand all trees that contain suspicious nodes by default
  React.useEffect(() => {
    const toExpand = new Set<number>();
    for (const node of Array.from(allNodesMap.values())) {
      if (node.isSuspicious && node.parent_pid) {
        toExpand.add(node.parent_pid);
      }
    }
    setExpandedPids(toExpand);
  }, [allNodesMap]);

  // Handle process termination
  const handleTerminate = async (node: ProcessTreeNode) => {
    setTerminatingPid(node.pid);
    try {
      const res = await fetch(`/api/processes/${node.pid}/terminate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: node.name, killTree: true }),
      });
      const data = await res.json();
      if (res.ok && data.success) {
        toast('Process Tree Terminated', `Successfully terminated ${node.name} (PID ${node.pid}) and child branches.`);
        if (selectedPid === node.pid) setSelectedPid(null);
        if (onRefresh) onRefresh();
      } else {
        toast('Termination Failed', data.error || 'Access denied or process already exited.');
      }
    } catch (err: any) {
      toast('Termination Error', err.message || 'Could not communicate with process engine.');
    } finally {
      setTerminatingPid(null);
    }
  };

  const selectedNode = selectedPid != null ? allNodesMap.get(selectedPid) : null;

  // Filter root nodes based on search or suspicious-only filter
  const filteredRoots = useMemo(() => {
    if (!searchTerm && !onlySuspicious) return rootNodes;

    const term = searchTerm.toLowerCase();

    function matchNode(n: ProcessTreeNode): boolean {
      const matchSearch =
        !term ||
        n.name.toLowerCase().includes(term) ||
        String(n.pid).includes(term) ||
        (n.username || '').toLowerCase().includes(term) ||
        (n.executable_path || '').toLowerCase().includes(term);

      const matchSuspicious = !onlySuspicious || n.isSuspicious;

      if (matchSearch && matchSuspicious) return true;
      return n.children.some(matchNode);
    }

    return rootNodes.filter(matchNode);
  }, [rootNodes, searchTerm, onlySuspicious]);

  // Recursive tree node renderer
  const renderNode = (node: ProcessTreeNode, depth = 0) => {
    const hasChildren = node.children.length > 0;
    const isExpanded = expandedPids.has(node.pid);
    const isSelected = selectedPid === node.pid;
    const memMb = Math.round((node.memory_bytes || 0) / (1024 * 1024));

    return (
      <div key={node.pid} style={{ marginLeft: depth > 0 ? 20 : 0 }}>
        <div
          onClick={() => setSelectedPid(node.pid)}
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            padding: '7px 10px',
            borderRadius: 6,
            background: isSelected
              ? 'hsl(var(--primary)/0.15)'
              : node.isSuspicious
              ? 'hsl(0 84% 60%/0.08)'
              : 'transparent',
            border: isSelected
              ? '1px solid hsl(var(--primary)/0.4)'
              : node.isSuspicious
              ? '1px solid hsl(0 84% 60%/0.25)'
              : '1px solid transparent',
            marginBottom: 3,
            cursor: 'pointer',
            transition: 'all 0.15s ease',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, overflow: 'hidden' }}>
            {hasChildren ? (
              <button
                type="button"
                onClick={(e) => {
                  e.stopPropagation();
                  toggleExpand(node.pid);
                }}
                style={{
                  background: 'transparent',
                  border: 'none',
                  padding: 2,
                  cursor: 'pointer',
                  color: 'hsl(var(--muted-foreground))',
                  display: 'flex',
                  alignItems: 'center',
                }}
              >
                {isExpanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
              </button>
            ) : (
              <span style={{ width: 14, display: 'inline-block' }} />
            )}

            <TerminalSquare
              size={14}
              style={{
                color: node.isSuspicious ? 'hsl(0 84% 60%)' : 'hsl(var(--muted-foreground))',
                flexShrink: 0,
              }}
            />

            <span
              style={{
                fontWeight: node.isSuspicious ? 700 : 500,
                fontSize: 12,
                color: node.isSuspicious ? 'hsl(0 84% 60%)' : 'hsl(var(--foreground))',
              }}
            >
              {node.name}
            </span>

            <span
              className="mono"
              style={{
                fontSize: 10,
                padding: '1px 5px',
                borderRadius: 4,
                background: 'hsl(var(--muted)/0.5)',
                color: 'hsl(var(--muted-foreground))',
              }}
            >
              PID {node.pid}
            </span>

            {node.isSuspicious && (
              <span
                style={{
                  fontSize: 9,
                  fontWeight: 700,
                  padding: '1px 6px',
                  borderRadius: 10,
                  background: 'hsl(0 84% 60%/0.18)',
                  color: 'hsl(0 84% 60%)',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: 3,
                }}
              >
                <AlertTriangle size={9} />
                {node.suspicionReasons[0]}
              </span>
            )}

            {node.sockets.length > 0 && (
              <span
                style={{
                  fontSize: 9,
                  fontWeight: 600,
                  padding: '1px 6px',
                  borderRadius: 10,
                  background: 'hsl(var(--primary)/0.15)',
                  color: 'hsl(var(--primary))',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: 3,
                }}
              >
                <Network size={9} />
                {node.sockets.length} socket{node.sockets.length > 1 ? 's' : ''}
              </span>
            )}
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 10, fontSize: 10 }} className="mono muted">
            {memMb > 0 && <span>{memMb} MB</span>}
            {node.cpu_percent != null && node.cpu_percent > 0.1 && (
              <span style={{ color: node.cpu_percent > 10 ? 'hsl(0 84% 60%)' : 'inherit' }}>
                {node.cpu_percent.toFixed(1)}% CPU
              </span>
            )}
          </div>
        </div>

        {hasChildren && isExpanded && (
          <div style={{ borderLeft: '1px dashed hsl(var(--border))', marginLeft: 7, paddingLeft: 6 }}>
            {node.children.map((child) => renderNode(child, depth + 1))}
          </div>
        )}
      </div>
    );
  };

  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'minmax(400px, 1fr) 380px', gap: 16, alignItems: 'start' }}>
      {/* Left Column: Live Tree View */}
      <section className="card card-pad" style={{ minHeight: 520 }}>
        {/* Controls Bar */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14, flexWrap: 'wrap', gap: 10 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ fontSize: 13, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Live Execution Hierarchy
            </span>
            <span
              style={{
                fontSize: 10,
                padding: '2px 8px',
                borderRadius: 12,
                background: totalSuspicious > 0 ? 'hsl(0 84% 60%/0.15)' : 'hsl(142 71% 18%)',
                color: totalSuspicious > 0 ? 'hsl(0 84% 60%)' : 'hsl(142 71% 75%)',
                fontWeight: 700,
              }}
            >
              {totalSuspicious} Flagged / {processes.length} Processes
            </span>
          </div>

          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <div style={{ position: 'relative' }}>
              <Search size={12} style={{ position: 'absolute', left: 8, top: '50%', transform: 'translateY(-50%)', color: 'hsl(var(--muted-foreground))' }} />
              <input
                type="text"
                placeholder="Search PID, name, user..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                style={{
                  background: 'hsl(var(--muted)/0.5)',
                  border: '1px solid hsl(var(--border))',
                  borderRadius: 5,
                  padding: '4px 8px 4px 26px',
                  fontSize: 11,
                  color: 'hsl(var(--foreground))',
                  width: 170,
                }}
              />
            </div>

            <button
              type="button"
              onClick={() => setOnlySuspicious(!onlySuspicious)}
              style={{
                fontSize: 10,
                padding: '4px 8px',
                borderRadius: 5,
                background: onlySuspicious ? 'hsl(0 84% 60%/0.18)' : 'hsl(var(--muted)/0.5)',
                color: onlySuspicious ? 'hsl(0 84% 60%)' : 'hsl(var(--foreground))',
                border: '1px solid hsl(var(--border))',
                cursor: 'pointer',
                fontWeight: 600,
                display: 'inline-flex',
                alignItems: 'center',
                gap: 4,
              }}
            >
              <Filter size={10} /> {onlySuspicious ? 'Showing Flagged' : 'Flagged Only'}
            </button>
          </div>
        </div>

        {/* Tree Container */}
        <div style={{ maxHeight: 600, overflowY: 'auto', paddingRight: 6 }}>
          {filteredRoots.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '40px 0', color: 'hsl(var(--muted-foreground))', fontSize: 12 }}>
              No processes match the filter criteria.
            </div>
          ) : (
            filteredRoots.map((root) => renderNode(root))
          )}
        </div>
      </section>

      {/* Right Column: Node Forensic Inspector */}
      <section className="card card-pad" style={{ position: 'sticky', top: 20 }}>
        <div className="panel-title" style={{ marginBottom: 12 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <Crosshair size={14} style={{ color: 'hsl(var(--primary))' }} />
            <h3 style={{ fontSize: 13, fontWeight: 700, margin: 0 }}>Process Blast Radius Node</h3>
          </div>
          {selectedNode && (
            <span className="mono" style={{ fontSize: 10, color: 'hsl(var(--muted-foreground))' }}>
              PID {selectedNode.pid}
            </span>
          )}
        </div>

        {selectedNode ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            {/* Process Header Badge */}
            <div
              style={{
                background: selectedNode.isSuspicious ? 'hsl(0 84% 60%/0.08)' : 'hsl(var(--muted)/0.3)',
                border: selectedNode.isSuspicious ? '1px solid hsl(0 84% 60%/0.3)' : '1px solid hsl(var(--border))',
                borderRadius: 6,
                padding: 12,
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: 15, fontWeight: 800, color: selectedNode.isSuspicious ? 'hsl(0 84% 60%)' : 'hsl(var(--foreground))' }}>
                  {selectedNode.name}
                </span>
                <span
                  style={{
                    fontSize: 10,
                    fontWeight: 700,
                    padding: '2px 7px',
                    borderRadius: 4,
                    background: selectedNode.isSuspicious ? 'hsl(0 84% 60%)' : 'hsl(142 71% 22%)',
                    color: '#fff',
                  }}
                >
                  {selectedNode.isSuspicious ? 'COMPROMISE INDICATOR' : 'MONITORED BASELINE'}
                </span>
              </div>
              <div className="mono muted" style={{ fontSize: 10, marginTop: 4 }}>
                Parent: {selectedNode.parent_name || 'System Root'} (PID {selectedNode.parent_pid || '—'})
              </div>
            </div>

            {/* Suspicion Reasons if flagged */}
            {selectedNode.isSuspicious && (
              <div style={{ background: 'hsl(0 84% 60%/0.08)', border: '1px solid hsl(0 84% 60%/0.25)', borderRadius: 6, padding: 10 }}>
                <div style={{ fontSize: 10, fontWeight: 700, color: 'hsl(0 84% 60%)', textTransform: 'uppercase', marginBottom: 4 }}>
                  Triage Indicators & Heuristics
                </div>
                <ul style={{ margin: 0, paddingLeft: 16, fontSize: 11, color: 'hsl(var(--foreground))' }}>
                  {selectedNode.suspicionReasons.map((r, i) => (
                    <li key={i} style={{ marginBottom: 2 }}>{r}</li>
                  ))}
                </ul>
              </div>
            )}

            {/* Metadata Grid */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, fontSize: 11 }}>
              <div className="kpi-box" style={{ background: 'hsl(var(--muted)/0.3)', padding: 8, borderRadius: 5 }}>
                <div style={{ fontSize: 9, color: 'hsl(var(--muted-foreground))', textTransform: 'uppercase' }}>CPU Load</div>
                <div style={{ fontSize: 13, fontWeight: 700, marginTop: 2 }}>
                  {selectedNode.cpu_percent != null ? `${selectedNode.cpu_percent.toFixed(1)}%` : '0.1%'}
                </div>
              </div>

              <div className="kpi-box" style={{ background: 'hsl(var(--muted)/0.3)', padding: 8, borderRadius: 5 }}>
                <div style={{ fontSize: 9, color: 'hsl(var(--muted-foreground))', textTransform: 'uppercase' }}>Working Memory</div>
                <div style={{ fontSize: 13, fontWeight: 700, marginTop: 2 }}>
                  {Math.round((selectedNode.memory_bytes || 0) / (1024 * 1024))} MB
                </div>
              </div>

              <div className="kpi-box" style={{ background: 'hsl(var(--muted)/0.3)', padding: 8, borderRadius: 5 }}>
                <div style={{ fontSize: 9, color: 'hsl(var(--muted-foreground))', textTransform: 'uppercase' }}>User Security Context</div>
                <div style={{ fontSize: 11, fontWeight: 700, marginTop: 2, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {selectedNode.username || 'Current User'}
                </div>
              </div>

              <div className="kpi-box" style={{ background: 'hsl(var(--muted)/0.3)', padding: 8, borderRadius: 5 }}>
                <div style={{ fontSize: 9, color: 'hsl(var(--muted-foreground))', textTransform: 'uppercase' }}>Process Status</div>
                <div style={{ fontSize: 11, fontWeight: 700, marginTop: 2, color: 'hsl(142 71% 65%)' }}>
                  {selectedNode.status || 'Running'}
                </div>
              </div>
            </div>

            {/* Path */}
            <div>
              <div style={{ fontSize: 10, fontWeight: 600, color: 'hsl(var(--muted-foreground))', textTransform: 'uppercase', marginBottom: 4 }}>
                Executable Binary Path
              </div>
              <div
                className="mono"
                style={{
                  background: 'hsl(var(--muted)/0.4)',
                  padding: '6px 8px',
                  borderRadius: 4,
                  fontSize: 10,
                  wordBreak: 'break-all',
                }}
              >
                {selectedNode.executable_path || 'C:\\Windows\\System32\\' + selectedNode.name}
              </div>
            </div>

            {/* Connected Sockets if present */}
            {selectedNode.sockets.length > 0 && (
              <div>
                <div style={{ fontSize: 10, fontWeight: 600, color: 'hsl(var(--muted-foreground))', textTransform: 'uppercase', marginBottom: 4 }}>
                  Associated Network Egress Sockets ({selectedNode.sockets.length})
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  {selectedNode.sockets.map((s, idx) => (
                    <div
                      key={idx}
                      className="mono"
                      style={{
                        display: 'flex',
                        justifyContent: 'space-between',
                        background: 'hsl(var(--muted)/0.3)',
                        padding: '4px 8px',
                        borderRadius: 4,
                        fontSize: 10,
                      }}
                    >
                      <span>{s.local_addr || '0.0.0.0'}:{s.local_port || '—'}</span>
                      <span style={{ color: 'hsl(var(--primary))' }}>
                        → {s.remote_addr}:{s.remote_port}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Actions */}
            <div style={{ display: 'flex', gap: 8, marginTop: 6, borderTop: '1px solid hsl(var(--border))', paddingTop: 12 }}>
              <button
                type="button"
                onClick={() => handleTerminate(selectedNode)}
                disabled={terminatingPid === selectedNode.pid || selectedNode.pid <= 4}
                style={{
                  flex: 1,
                  display: 'inline-flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  gap: 6,
                  background: 'hsl(0 84% 60%)',
                  color: '#fff',
                  border: 'none',
                  borderRadius: 5,
                  padding: '7px 10px',
                  fontSize: 11,
                  fontWeight: 700,
                  cursor: terminatingPid === selectedNode.pid ? 'not-allowed' : 'pointer',
                }}
              >
                <Trash2 size={12} />
                {terminatingPid === selectedNode.pid ? 'Terminating...' : 'Terminate Tree (/F /T)'}
              </button>

              {onNavigate && (
                <button
                  type="button"
                  onClick={() => onNavigate('/processes')}
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    gap: 4,
                    background: 'hsl(var(--secondary))',
                    color: 'hsl(var(--secondary-foreground))',
                    border: '1px solid hsl(var(--border))',
                    borderRadius: 5,
                    padding: '7px 10px',
                    fontSize: 11,
                    fontWeight: 600,
                    cursor: 'pointer',
                  }}
                >
                  <ExternalLink size={12} /> Details
                </button>
              )}
            </div>
          </div>
        ) : (
          <div style={{ textAlign: 'center', padding: '60px 20px', color: 'hsl(var(--muted-foreground))' }}>
            <TerminalSquare size={32} style={{ margin: '0 auto 10px', opacity: 0.4 }} />
            <div style={{ fontSize: 12, fontWeight: 600 }}>Select a process node to inspect</div>
            <div style={{ fontSize: 11, marginTop: 4 }}>
              Click any process in the hierarchy tree to review its blast radius, open network sockets, and command line.
            </div>
          </div>
        )}
      </section>
    </div>
  );
}
