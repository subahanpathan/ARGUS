import React, { useState, useMemo } from 'react';
import {
  Server,
  TerminalSquare,
  UserCheck,
  FileKey2,
  Network,
  Users,
  AlertTriangle,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Lock,
  Radio,
  ExternalLink,
  Crosshair,
  Layers,
  ChevronRight,
} from 'lucide-react';
import type { Severity } from '@/pages/exposure-page';

export type BlastRadiusAsset = {
  ring: number;
  ringLabel: string;
  type: string;
  name: string;
  owner: string;
  scope: string;
  status: string;
  severity: Severity;
  icon: any;
  actionRoute?: string;
};

export interface BlastRadiusMapProps {
  assets: Array<{
    type: string;
    name: string;
    owner: string;
    ip: string;
    status: string;
    severity: Severity;
    icon: any;
  }>;
  contained: boolean;
  onContain?: () => void;
  onNavigate?: (path: string) => void;
  toast: (title: string, body: string) => void;
  riskScore: number;
  isReal: boolean;
}

export default function BlastRadiusMap({
  assets,
  contained,
  onContain,
  onNavigate,
  toast,
  riskScore,
  isReal,
}: BlastRadiusMapProps) {
  const [filterSeverity, setFilterSeverity] = useState<string>('all');
  const [selectedRing, setSelectedRing] = useState<number | null>(null);

  // Categorize assets into concentric rings of blast radius
  const enrichedAssets: BlastRadiusAsset[] = useMemo(() => {
    return assets.map((a, idx) => {
      let ring = 0;
      let ringLabel = 'Epicenter (Process)';

      if (a.type.includes('Host') || a.type.includes('Endpoint')) {
        ring = 0;
        ringLabel = 'Epicenter: Execution Anchor';
      } else if (a.type.includes('Identity') || a.type.includes('Credentials')) {
        ring = 1;
        ringLabel = 'Ring 1: Security Tokens & Account Context';
      } else if (a.type.includes('Data') || a.type.includes('Repositories') || a.type.includes('Files')) {
        ring = 2;
        ringLabel = 'Ring 2: Filesystem & Staged Artifacts';
      } else if (a.type.includes('Network') || a.type.includes('Perimeter') || a.type.includes('Sockets')) {
        ring = 3;
        ringLabel = 'Ring 3: Transport Layer & Egress Channels';
      } else {
        ring = 4;
        ringLabel = 'Ring 4: Adjacent Subnet & Enterprise Scope';
      }

      return {
        ...a,
        ring,
        ringLabel,
        scope: a.ip,
        actionRoute: ring === 0 ? '/processes' : ring === 2 ? '/quarantine' : ring === 3 ? '/network' : undefined,
      };
    });
  }, [assets]);

  // Filtered assets
  const filteredAssets = useMemo(() => {
    return enrichedAssets.filter((a) => {
      const matchSeverity = filterSeverity === 'all' || a.severity === filterSeverity;
      const matchRing = selectedRing === null || a.ring === selectedRing;
      return matchSeverity && matchRing;
    });
  }, [enrichedAssets, filterSeverity, selectedRing]);

  // Concentric Rings Definitions
  const rings = [
    { ring: 0, label: 'Ring 0: Host Process Epicenter', color: 'hsl(0 84% 60%)', note: 'Unsigned Script / Binary Spawn' },
    { ring: 1, label: 'Ring 1: Identity & Credentials', color: 'hsl(38 92% 50%)', note: 'Interactive User Security Tokens' },
    { ring: 2, label: 'Ring 2: Staged Filesystem Buffers', color: 'hsl(199 89% 48%)', note: 'Candidate & Quarantined Artifacts' },
    { ring: 3, label: 'Ring 3: Network Transport Perimeter', color: 'hsl(280 65% 60%)', note: 'Active Sockets & External IPs' },
    { ring: 4, label: 'Ring 4: Adjacent Enterprise Peers', color: 'hsl(142 71% 45%)', note: 'Subnet VLAN Broadcast Boundary' },
  ];

  const criticalCount = enrichedAssets.filter((a) => a.severity === 'critical').length;
  const highCount = enrichedAssets.filter((a) => a.severity === 'high').length;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      {/* Blast Radius Summary Top Banner */}
      <div
        className="card card-pad"
        style={{
          background: 'hsl(var(--card))',
          borderLeft: `4px solid ${contained ? 'hsl(142 71% 45%)' : riskScore > 75 ? 'hsl(0 84% 60%)' : 'hsl(38 92% 50%)'}`,
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 12 }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
              <span style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'hsl(var(--primary))' }}>
                ENTERPRISE BLAST RADIUS MAPPING
              </span>
              <span
                style={{
                  fontSize: 10,
                  padding: '2px 8px',
                  borderRadius: 12,
                  background: contained ? 'hsl(142 71% 18%)' : 'hsl(0 84% 60%/0.15)',
                  color: contained ? 'hsl(142 71% 75%)' : 'hsl(0 84% 60%)',
                  fontWeight: 700,
                }}
              >
                {contained ? 'CONTAINED TO WORKSTATION WS-0427' : 'POTENTIAL LATERAL EXPOSURE ACTIVE'}
              </span>
            </div>
            <h2 style={{ fontSize: 18, fontWeight: 800, margin: 0 }}>
              {isReal ? 'Live Host WS-0427 Blast Perimeter' : 'Simulated Corporate Network Blast Perimeter'}
            </h2>
            <p style={{ fontSize: 12, color: 'hsl(var(--muted-foreground))', margin: '4px 0 0', maxWidth: 740, lineHeight: 1.5 }}>
              Calculates the concentric blast radius from initial process execution outwards to user credentials, local filesystem staging directories, network sockets, and adjacent VLAN subnets.
            </p>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            {onContain && (
              <button
                type="button"
                className="btn"
                onClick={() => {
                  onContain();
                  toast(contained ? 'Isolation Removed' : 'Blast Radius Severed', contained ? 'Network routing restored.' : 'Outbound network isolation applied to WS-0427.');
                }}
                style={{
                  background: contained ? 'hsl(142 71% 22%)' : 'hsl(0 84% 60%)',
                  color: '#fff',
                  border: 'none',
                  padding: '8px 16px',
                  fontSize: 12,
                  fontWeight: 700,
                  borderRadius: 6,
                  cursor: 'pointer',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: 6,
                }}
              >
                <Lock size={13} />
                {contained ? 'Workstation Isolated' : 'Sever Blast Radius (Isolate Host)'}
              </button>
            )}
          </div>
        </div>

        {/* Concentric Rings Visual Filter Bar */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 8, marginTop: 18 }}>
          {rings.map((r) => {
            const isSelected = selectedRing === r.ring;
            const ringAssetCount = enrichedAssets.filter((a) => a.ring === r.ring).length;

            return (
              <div
                key={r.ring}
                onClick={() => setSelectedRing(isSelected ? null : r.ring)}
                style={{
                  background: isSelected ? 'hsl(var(--primary)/0.15)' : 'hsl(var(--muted)/0.3)',
                  border: isSelected ? `2px solid ${r.color}` : '1px solid hsl(var(--border))',
                  borderRadius: 6,
                  padding: '8px 10px',
                  cursor: 'pointer',
                  transition: 'all 0.15s ease',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 2 }}>
                  <span style={{ fontSize: 10, fontWeight: 700, color: r.color }}>RING {r.ring}</span>
                  <span style={{ fontSize: 10, fontWeight: 700, padding: '1px 5px', borderRadius: 4, background: 'hsl(var(--muted)/0.6)' }}>
                    {ringAssetCount}
                  </span>
                </div>
                <div style={{ fontSize: 11, fontWeight: 700, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {r.label.split(':')[1]}
                </div>
                <div style={{ fontSize: 9, color: 'hsl(var(--muted-foreground))', marginTop: 2 }}>
                  {r.note}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Filter Chips & Asset Grid */}
      <div>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
          <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
            <span style={{ fontSize: 11, fontWeight: 600, color: 'hsl(var(--muted-foreground))', textTransform: 'uppercase' }}>
              Severity Filter:
            </span>
            {['all', 'critical', 'high', 'medium', 'low'].map((sev) => (
              <button
                key={sev}
                type="button"
                onClick={() => setFilterSeverity(sev)}
                style={{
                  fontSize: 10,
                  fontWeight: 600,
                  textTransform: 'uppercase',
                  padding: '3px 8px',
                  borderRadius: 4,
                  border: filterSeverity === sev ? '1px solid hsl(var(--primary))' : '1px solid hsl(var(--border))',
                  background: filterSeverity === sev ? 'hsl(var(--primary)/0.15)' : 'hsl(var(--muted)/0.4)',
                  color: filterSeverity === sev ? 'hsl(var(--primary))' : 'hsl(var(--muted-foreground))',
                  cursor: 'pointer',
                }}
              >
                {sev}
              </button>
            ))}
          </div>

          <div style={{ fontSize: 11, color: 'hsl(var(--muted-foreground))' }}>
            Showing <b>{filteredAssets.length}</b> of {enrichedAssets.length} blast assets
          </div>
        </div>

        {/* Asset Cards */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(360px, 1fr))', gap: 14 }}>
          {filteredAssets.map((asset) => {
            const Icon = asset.icon;
            const isCrit = asset.severity === 'critical';
            const isHigh = asset.severity === 'high';

            return (
              <div
                key={asset.name}
                style={{
                  background: 'hsl(var(--card))',
                  border: isCrit ? '1px solid hsl(0 84% 60%/0.4)' : '1px solid hsl(var(--border))',
                  borderRadius: 8,
                  padding: 14,
                  display: 'flex',
                  flexDirection: 'column',
                  gap: 10,
                  boxShadow: isCrit ? '0 2px 12px rgba(239, 68, 68, 0.08)' : 'none',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                  <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
                    <div
                      style={{
                        padding: 8,
                        borderRadius: 6,
                        background: isCrit ? 'hsl(0 84% 60%/0.15)' : 'hsl(var(--muted)/0.6)',
                        color: isCrit ? 'hsl(0 84% 60%)' : 'hsl(var(--primary))',
                      }}
                    >
                      <Icon size={16} />
                    </div>
                    <div>
                      <div style={{ fontSize: 9, fontWeight: 700, color: 'hsl(var(--muted-foreground))', textTransform: 'uppercase' }}>
                        {asset.ringLabel}
                      </div>
                      <div style={{ fontSize: 13, fontWeight: 700, color: 'hsl(var(--foreground))', marginTop: 1 }}>
                        {asset.name}
                      </div>
                    </div>
                  </div>

                  <span
                    style={{
                      fontSize: 9,
                      fontWeight: 700,
                      padding: '2px 7px',
                      borderRadius: 4,
                      background: isCrit
                        ? 'hsl(0 84% 60%)'
                        : isHigh
                        ? 'hsl(38 92% 50%)'
                        : 'hsl(142 71% 22%)',
                      color: '#fff',
                      textTransform: 'uppercase',
                    }}
                  >
                    {asset.severity}
                  </span>
                </div>

                <div
                  style={{
                    background: 'hsl(var(--muted)/0.3)',
                    padding: '8px 10px',
                    borderRadius: 5,
                    fontSize: 11,
                    display: 'flex',
                    flexDirection: 'column',
                    gap: 3,
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span className="muted">Scope / Address:</span>
                    <span className="mono" style={{ fontWeight: 600 }}>{asset.scope}</span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span className="muted">Entity Context:</span>
                    <span>{asset.owner}</span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span className="muted">Remediation State:</span>
                    <span style={{ fontWeight: 600, color: asset.status.includes('Isolated') ? 'hsl(142 71% 65%)' : 'hsl(var(--foreground))' }}>
                      {asset.status}
                    </span>
                  </div>
                </div>

                {asset.actionRoute && onNavigate && (
                  <div style={{ display: 'flex', justifyContent: 'flex-end', borderTop: '1px solid hsl(var(--border))', paddingTop: 8 }}>
                    <button
                      type="button"
                      onClick={() => onNavigate(asset.actionRoute!)}
                      style={{
                        background: 'transparent',
                        border: 'none',
                        color: 'hsl(var(--primary))',
                        fontSize: 11,
                        fontWeight: 600,
                        cursor: 'pointer',
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: 4,
                        padding: 0,
                      }}
                    >
                      Investigate in {asset.actionRoute.replace('/', '')} <ChevronRight size={12} />
                    </button>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
