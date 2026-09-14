import { useMemo, useState } from 'react';
import {
  ChevronDown,
  ChevronRight,
  Cpu,
  Database,
  FileSearch,
  LockKeyhole,
  Network,
  ShieldCheck,
} from 'lucide-react';
import { cn } from '@/lib/utils';

export type ProcessVerdict = 'trusted' | 'monitored' | 'suspicious' | 'malicious' | 'restricted';

export type ProcessGraphNode = {
  id: string;
  pid: number;
  name: string;
  parentPid: number | null;
  detail?: string;
  cpu: string;
  memory: string;
  network: string;
  files: string;
  verdict: ProcessVerdict;
  /** When true the parent→this edge animates a directional data flow. */
  flow?: boolean;
  /** When true the card renders in a "contained / quarantined" state. */
  contained?: boolean;
};

type ProcessGraphProps = {
  nodes: ProcessGraphNode[];
  selected: number;
  onSelect: (pid: number) => void;
};

const VERDICT_COPY: Record<ProcessVerdict, string> = {
  trusted: 'Baseline process — no signals raised.',
  monitored: 'Routine activity — retained under observation.',
  suspicious: 'Elevated behavior detected — under active review.',
  malicious: 'Critical signals — escalated for immediate containment.',
  restricted: 'Handle protected by the OS — metadata only.',
};

function monogram(name: string): string {
  const clean = name.replace(/\.exe$/i, '');
  const initials = clean
    .split(/[^a-z0-9]/i)
    .filter(Boolean)
    .slice(0, 2)
    .map((p) => p[0])
    .join('')
    .toUpperCase();
  return (initials || clean[0] || '?').toUpperCase().slice(0, 2);
}

function verdictLabel(verdict: ProcessVerdict): string | null {
  if (verdict === 'suspicious') return 'suspicious';
  if (verdict === 'malicious') return 'malicious';
  if (verdict === 'restricted') return 'restricted';
  if (verdict === 'monitored') return 'monitored';
  return null;
}

function severityToVerdict(risk: string): ProcessVerdict {
  switch (risk) {
    case 'critical': return 'malicious';
    case 'high': return 'suspicious';
    case 'medium': return 'monitored';
    default: return 'trusted';
  }
}

function ProcessCard({
  node,
  expanded,
  onSelect,
}: {
  node: ProcessGraphNode;
  expanded: boolean;
  onSelect: () => void;
}) {
  const label = verdictLabel(node.verdict);
  return (
    <div
      role="button"
      tabIndex={0}
      aria-expanded={expanded}
      onClick={onSelect}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          onSelect();
        }
      }}
      data-testid={`node-process-${node.pid}`}
      className={cn(
        'proc-card',
        `verdict-${node.verdict}`,
        expanded && 'is-open',
        node.contained && 'is-contained',
      )}
    >
      <span className="proc-monogram" aria-hidden>
        {node.verdict === 'restricted' ? <LockKeyhole size={14} /> : monogram(node.name)}
      </span>
      <div className="proc-copy">
        <div className="proc-name-row">
          <b className="proc-name">{node.name}</b>
          {label && <span className={cn('proc-chip', `chip-${node.verdict}`)}>{label}</span>}
          {node.contained && (
            <span className="proc-chip chip-contained">
              <ShieldCheck size={9} />
              contained
            </span>
          )}
        </div>
        <div className="proc-meta mono">
          PID {node.pid}
          {node.parentPid != null && <span className="proc-meta-arrow">← parent {node.parentPid}</span>}
        </div>
        {node.detail && <div className="proc-path muted">{node.detail}</div>}
        <div className="proc-kpis">
          <span>
            <Cpu size={10} />
            {node.cpu}
          </span>
          <span>
            <Database size={10} />
            {node.memory}
          </span>
          <span>
            <Network size={10} />
            {node.network} conn
          </span>
          <span>
            <FileSearch size={10} />
            {node.files} files
          </span>
        </div>
        <div className="proc-detail">
          <div className="proc-detail-inner">
            <div className="proc-verdict-line muted">{VERDICT_COPY[node.verdict]}</div>
            {node.contained && (
              <div className="proc-verdict-line proc-verdict-contained">
                Network isolation applied · traffic terminated · artifact quarantined.
              </div>
            )}
          </div>
        </div>
      </div>
      <span className="proc-toggle" aria-hidden>
        {expanded ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
      </span>
    </div>
  );
}

function Branch({
  node,
  nodes,
  onSelect,
  openPid,
  isRoot,
}: {
  node: ProcessGraphNode;
  nodes: ProcessGraphNode[];
  onSelect: (pid: number) => void;
  openPid: number | null;
  isRoot: boolean;
}) {
  const children = useMemo(() => nodes.filter((n) => n.parentPid === node.pid), [nodes, node.pid]);
  const expanded = openPid === node.pid;
  const flowsToSuspicious = children.some((c) => c.verdict === 'suspicious' || c.verdict === 'malicious');

  return (
    <div className="proc-node">
      <div className="proc-card-wrap">
        <ProcessCard node={node} expanded={expanded} onSelect={() => onSelect(node.pid)} />
        {isRoot && <span className="proc-root-chip">session root</span>}
      </div>
      {children.length > 0 && (
        <div
          className={cn(
            'proc-edge',
            node.flow && !node.contained && 'flow',
            flowsToSuspicious && !node.contained && 'flow-elevated',
          )}
          aria-hidden
        >
          <span className="proc-edge-line" />
          <span className="proc-edge-h" />
          <span className="proc-edge-arrow" />
          {node.flow && !node.contained && (
            <span className="proc-flow">
              <i />
              <i />
              <i />
            </span>
          )}
        </div>
      )}
      {children.length > 0 && (
        <div className="proc-children">
          {children.map((child) => (
            <Branch
              key={child.id}
              node={child}
              nodes={nodes}
              onSelect={onSelect}
              openPid={openPid}
              isRoot={false}
            />
          ))}
        </div>
      )}
    </div>
  );
}

/**
 * Premium directed process graph.
 *
 *  - process cards carrying real information (PID, resource use, verdict)
 *  - directional parent→child connectors with arrowheads
 *  - animated data-flow along important relationships only (and only one
 *    time-invariant loop, powered by CSS), elevated for suspicious chains
 *  - clear suspicious/malicious/contained visual states
 *  - smooth expand/collapse of node detail (grid-rows transition — no layout
 *    thrash, compositor-friendly)
 *  - containment transition that dims and pill-marks the affected chain
 *  - avoids continuous layout animation: only transform/opacity move
 */
export function ProcessGraph({ nodes, selected, onSelect }: ProcessGraphProps) {
  const [openPid, setOpenPid] = useState<number | null>(selected);

  const roots = useMemo(() => nodes.filter((n) => n.parentPid == null), [nodes]);

  if (roots.length === 0) {
    return <div className="empty">No processes observed in this snapshot.</div>;
  }

  const handleSelect = (pid: number) => {
    onSelect(pid);
    setOpenPid((cur) => (cur === pid ? null : pid));
  };

  const summary = useMemo(() => {
    let suspicious = 0;
    let malicious = 0;
    let contained = 0;
    for (const n of nodes) {
      if (n.verdict === 'suspicious') suspicious++;
      if (n.verdict === 'malicious') malicious++;
      if (n.contained) contained++;
    }
    return { suspicious, malicious, contained };
  }, [nodes]);

  const markFlowOnChain = useMemo(() => {
    const ids = new Set<string>();
    for (const n of nodes) {
      if (n.verdict === 'suspicious' || n.verdict === 'malicious') {
        let current: ProcessGraphNode | undefined = n;
        while (current && current.parentPid != null) {
          current = nodes.find((x) => x.pid === current!.parentPid);
          if (current) ids.add(current.id);
        }
      }
    }
    return ids;
  }, [nodes]);

  return (
    <div>
      <div className="proc-legend" data-testid="process-graph-legend">
        <span className="proc-legend-title">Execution graph</span>
        {(['trusted', 'monitored', 'suspicious', 'malicious', 'contained'] as const).map((k) => (
          <span className="legend-item" key={k}>
            <i className={cn('dot', `dot-${k}`)} />
            {k}
          </span>
        ))}
        <span className="legend-item legend-flow">flow · relationship activity</span>
        {summary.suspicious + summary.malicious > 0 && (
          <span className="mono muted" style={{ marginLeft: 'auto' }}>
            {summary.suspicious + summary.malicious} elevated · {summary.contained || 0} contained
          </span>
        )}
      </div>
      <div className="proc-graph" data-testid="process-tree">
        {roots.map((root) => (
          <Branch
            key={root.id}
            node={{ ...root, flow: root.contained ? false : markFlowOnChain.has(root.id) || root.flow }}
            nodes={nodes}
            onSelect={handleSelect}
            openPid={openPid}
            isRoot
          />
        ))}
      </div>
      {nodes.length === 1 && (
        <div className="muted" style={{ fontSize: 10, marginTop: 8 }}>
          Single process — no parent relationship observed.
        </div>
      )}
    </div>
  );
}

/**
 * Builds a ProcessGraph's node list from raw seed records (demo data).
 */
export type GraphSeedNode = {
  pid: number;
  executable: string;
  parent: number | null;
  cpu: string;
  memory: string;
  files: number;
  network: number;
  risk: string;
};

export function buildGraphFromSeed(
  rows: GraphSeedNode[],
  containedPids: number[] = [],
): ProcessGraphNode[] {
  return rows.map((r) => ({
    id: String(r.pid),
    pid: r.pid,
    name: r.executable,
    parentPid: r.parent,
    cpu: r.cpu,
    memory: r.memory,
    network: String(r.network),
    files: String(r.files),
    verdict: severityToVerdict(r.risk),
    contained: containedPids.includes(r.pid),
  }));
}

/**
 * Builds a ProcessGraph's node list from live Windows telemetry.
 */
export type GraphTelemetryNode = {
  pid: number;
  parent_pid: number | null;
  name: string;
  cpu_percent: number | null;
  memory_bytes: number | null;
  network_connections?: number;
  open_files?: number;
  access_error?: string | null;
  executable_path?: string | null;
};

export function buildGraphFromTelemetry(
  rows: GraphTelemetryNode[],
  containedPids: number[] = [],
  flaggedPids: number[] = [],
): ProcessGraphNode[] {
  return rows.map((r) => {
    const flagged = flaggedPids.includes(r.pid);
    const verdict: ProcessVerdict = r.access_error
      ? 'restricted'
      : flagged
        ? 'suspicious'
        : 'trusted';
    return {
      id: String(r.pid),
      pid: r.pid,
      name: r.name,
      parentPid: r.parent_pid,
      detail: r.executable_path || undefined,
      cpu: r.cpu_percent != null ? `${r.cpu_percent.toFixed(1)}%` : '—',
      memory: r.memory_bytes != null ? `${(r.memory_bytes / 1048576).toFixed(0)} MB` : '—',
      network: String(r.network_connections ?? 0),
      files: String(r.open_files ?? 0),
      verdict,
      flow: flagged,
      contained: containedPids.includes(r.pid),
    };
  });
}