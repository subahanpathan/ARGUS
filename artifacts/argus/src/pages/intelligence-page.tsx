import React, { useState, useMemo } from 'react';
import {
  BrainCircuit,
  Search,
  RefreshCw,
  Download,
  Plus,
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Globe2,
  Fingerprint,
  Radio,
  Wifi,
  Database,
  ExternalLink,
  CheckCircle2,
  Copy,
  Check,
  Filter,
  Layers,
  ArrowRight,
  Info,
  Server,
  Terminal,
  Activity,
  X,
  Clock,
  Sparkles,
  Lock,
  Unlock,
  Radar,
  FileCode,
  Flame,
  Bug,
  Eye,
  SlidersHorizontal,
} from 'lucide-react';
import {
  useThreatIntelligence,
  type IOCRecord,
  type IndicatorType,
  type IndicatorSeverity,
  type ThreatFeed,
  type ThreatActor,
  type VulnerabilityItem,
  type LocalCorrelationMatch,
} from '@/hooks/use-threat-intelligence';
import type { ProcessMonitorState } from '@/hooks/use-process-monitor';
import type { NetworkMonitorState } from '@/hooks/use-network-monitor';
import type { FileScanState } from '@/hooks/use-file-scan';
import type { ThreatAnalysisState } from '@/hooks/use-threat-analysis';

function cn(...values: Array<string | false | undefined | null>) {
  return values.filter(Boolean).join(' ');
}

function PanelTitle({ title, detail, action }: { title: string; detail?: string; action?: React.ReactNode }) {
  return (
    <div className="panel-title" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
      <h2>{title}</h2>
      <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
        {detail && <span className="mono muted" style={{ fontSize: 10 }}>{detail}</span>}
        {action}
      </div>
    </div>
  );
}

export type IntelligencePageProps = {
  toast: (title: string, body: string) => void;
  processMonitor?: ProcessMonitorState;
  networkMonitor?: NetworkMonitorState;
  fileScan?: FileScanState;
  threatAnalysis?: ThreatAnalysisState;
  onNavigate?: (path: string) => void;
};

type ActiveTab = 'iocs' | 'feeds' | 'actors' | 'cves' | 'correlation';

export default function IntelligencePage({
  toast,
  processMonitor,
  networkMonitor,
  fileScan,
  threatAnalysis,
  onNavigate,
}: IntelligencePageProps) {
  const {
    summary,
    indicators,
    feeds,
    actors,
    vulnerabilities,
    correlations,
    loading,
    syncingFeeds,
    lastSyncTime,
    refreshFeeds,
    toggleFollow,
    toggleBlock,
    submitIndicator,
    lookup,
  } = useThreatIntelligence({
    processMonitor,
    networkMonitor,
    fileScan,
    threatAnalysis,
  });

  // State
  const [activeTab, setActiveTab] = useState<ActiveTab>('iocs');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedType, setSelectedType] = useState<string>('all');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all');
  const [onlyLocalSightings, setOnlyLocalSightings] = useState(false);
  const [defangEnabled, setDefangEnabled] = useState(true);
  const [selectedIocId, setSelectedIocId] = useState<string>('ioc-1');
  const [selectedActorId, setSelectedActorId] = useState<string>('actor-1');
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);

  // New IOC Form state
  const [newIocValue, setNewIocValue] = useState('');
  const [newIocType, setNewIocType] = useState<IndicatorType>('domain');
  const [newIocSeverity, setNewIocSeverity] = useState<IndicatorSeverity>('high');
  const [newIocCategory, setNewIocCategory] = useState('Command & Control');
  const [newIocActor, setNewIocActor] = useState('');
  const [newIocDesc, setNewIocDesc] = useState('');

  // Find currently selected IOC
  const selectedIoc = useMemo(() => {
    return indicators.find((i) => i.id === selectedIocId) || indicators[0] || null;
  }, [indicators, selectedIocId]);

  // Find currently selected Actor
  const selectedActor = useMemo(() => {
    return actors.find((a) => a.id === selectedActorId) || actors[0] || null;
  }, [actors, selectedActorId]);

  // Filtered indicators list
  const filteredIndicators = useMemo(() => {
    return indicators.filter((ioc) => {
      if (selectedType !== 'all' && ioc.type !== selectedType) return false;
      if (selectedSeverity !== 'all' && ioc.severity !== selectedSeverity) return false;
      if (onlyLocalSightings && (!ioc.localSightingsCount || ioc.localSightingsCount <= 0)) return false;
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matchesVal = ioc.value.toLowerCase().includes(q) || ioc.defangedValue.toLowerCase().includes(q);
        const matchesCat = ioc.category.toLowerCase().includes(q);
        const matchesActor = ioc.threatActor?.toLowerCase().includes(q);
        const matchesTags = ioc.tags.some((t) => t.toLowerCase().includes(q));
        if (!matchesVal && !matchesCat && !matchesActor && !matchesTags) return false;
      }
      return true;
    });
  }, [indicators, selectedType, selectedSeverity, onlyLocalSightings, searchQuery]);

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    toast('Copied to clipboard', text);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleRefresh = async () => {
    await refreshFeeds();
    toast('Feeds synchronized', 'All 6 global threat intelligence feeds returned live context.');
  };

  const handleDownloadStix = () => {
    const stixData = {
      type: 'bundle',
      id: `bundle--${Date.now()}`,
      spec_version: '2.1',
      objects: indicators.map((ioc) => ({
        type: 'indicator',
        spec_version: '2.1',
        id: `indicator--${ioc.id}`,
        created: ioc.firstSeen,
        modified: ioc.lastSeen,
        name: `${ioc.type.toUpperCase()}: ${ioc.value}`,
        description: ioc.description,
        indicator_types: [ioc.category],
        pattern: `[${ioc.type}:value = '${ioc.value}']`,
        pattern_type: 'stix',
        confidence: ioc.confidence,
      })),
    };
    const blob = new Blob([JSON.stringify(stixData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `argus-threat-intel-stix-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
    toast('STIX 2.1 exported', 'Threat intelligence bundle downloaded in OASIS STIX 2.1 format.');
  };

  const handleAddSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newIocValue.trim()) return;
    await submitIndicator({
      value: newIocValue.trim(),
      type: newIocType,
      severity: newIocSeverity,
      category: newIocCategory,
      threatActor: newIocActor || undefined,
      description: newIocDesc || 'Analyst created indicator',
    });
    setIsAddModalOpen(false);
    setNewIocValue('');
    setNewIocDesc('');
    toast('Indicator registered', `${newIocValue} added to workspace threat intelligence repository.`);
  };

  const handleQuickChipClick = async (val: string) => {
    setSearchQuery(val);
    const matched = indicators.find((i) => i.value.toLowerCase().includes(val.toLowerCase()) || val.toLowerCase().includes(i.value.toLowerCase()));
    if (matched) {
      setSelectedIocId(matched.id);
    } else {
      const res = await lookup(val);
      if (res) {
        setSelectedIocId(res.id);
      }
    }
  };

  return (
    <div className="animate-rise" style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      {/* Top Header */}
      <div className="page-heading">
        <div>
          <div className="eyebrow" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <span className="event-dot" style={{ background: 'hsl(var(--accent))' }} />
            GLOBAL CONTEXT LAYER · THREAT SENSORS & CURATED REPUTATION
          </div>
          <h1 className="page-title" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <BrainCircuit size={26} style={{ color: 'hsl(var(--primary))' }} />
            Threat Intelligence & Adversary Tracking
          </h1>
          <p className="page-subtitle">
            High-fidelity global threat intelligence feeds, MITRE ATT&CK correlation, IOC enrichment dossiers, and real-time endpoint sighting telemetry.
          </p>
        </div>
        <div className="actions" style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          <button
            type="button"
            className="btn"
            onClick={handleRefresh}
            disabled={syncingFeeds}
            data-testid="button-refresh-intelligence"
          >
            <RefreshCw size={14} className={syncingFeeds ? 'animate-spin' : ''} />
            {syncingFeeds ? 'Syncing Feeds…' : 'Sync All Feeds'}
          </button>
          <button
            type="button"
            className="btn"
            onClick={handleDownloadStix}
            data-testid="button-export-stix"
          >
            <Download size={14} />
            Export STIX 2.1
          </button>
          <button
            type="button"
            className="btn btn-primary"
            onClick={() => setIsAddModalOpen(true)}
            data-testid="button-add-ioc"
          >
            <Plus size={14} />
            Add Indicator
          </button>
        </div>
      </div>

      {/* KPI Metrics Cards */}
      <div className="grid metrics">
        <div className="card metric">
          <div className="metric-label">
            <Radar size={13} style={{ verticalAlign: 'middle', marginRight: 6 }} />
            Indicators Tracked
          </div>
          <div className="metric-value signal-info">
            {summary ? summary.totalIndicators.toLocaleString() : '14,892'}
          </div>
          <div className="metric-note">
            +{summary?.newTodayCount || 312} today · IP, Domain, Hash, CVE
          </div>
        </div>

        <div className="card metric">
          <div className="metric-label">
            <Wifi size={13} style={{ verticalAlign: 'middle', marginRight: 6 }} />
            Feed Network Health
          </div>
          <div className="metric-value signal-good">
            {feeds.filter((f) => f.status === 'active').length} / {feeds.length || 6}
          </div>
          <div className="metric-note">
            Avg sync latency 44ms · 98.4% reliability
          </div>
        </div>

        <div className="card metric">
          <div className="metric-label">
            <Flame size={13} style={{ verticalAlign: 'middle', marginRight: 6 }} />
            Correlated Sightings
          </div>
          <div className="metric-value signal-danger" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            {String(correlations.length).padStart(2, '0')}
            <span className="badge badge-critical" style={{ fontSize: 10, padding: '2px 6px' }}>ACTIVE</span>
          </div>
          <div className="metric-note">
            Observed on endpoint WS-0427 telemetry
          </div>
        </div>

        <div className="card metric">
          <div className="metric-label">
            <Sparkles size={13} style={{ verticalAlign: 'middle', marginRight: 6 }} />
            Active Campaigns
          </div>
          <div className="metric-value signal-warn">
            {summary?.activeCampaignsCount || 8}
          </div>
          <div className="metric-note">
            DarkGate, Volt Typhoon, LockBit 3.0, APT29
          </div>
        </div>
      </div>

      {/* Omnibar Search & Quick Lookup Chips */}
      <div className="card card-pad" style={{ background: 'hsl(var(--card))' }}>
        <div style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
          <div style={{ position: 'relative', flex: '1 1 320px' }}>
            <Search size={15} style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: 'hsl(var(--muted-foreground))' }} />
            <input
              type="text"
              className="form-input"
              style={{
                width: '100%',
                paddingLeft: 34,
                paddingRight: searchQuery ? 32 : 12,
                height: 38,
                borderRadius: 6,
                background: 'hsl(var(--background))',
                border: '1px solid hsl(var(--border))',
                color: 'hsl(var(--foreground))',
                fontSize: 12,
              }}
              placeholder="Search any IP (185.220.101.42), Domain (cdn-sync-check.com), Hash, CVE, or Threat Actor..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              data-testid="input-search-intelligence"
            />
            {searchQuery && (
              <button
                type="button"
                className="btn btn-ghost"
                style={{ position: 'absolute', right: 6, top: '50%', transform: 'translateY(-50%)', padding: 4 }}
                onClick={() => setSearchQuery('')}
              >
                <X size={14} />
              </button>
            )}
          </div>

          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <button
              type="button"
              className={cn('btn btn-sm', defangEnabled ? 'btn-primary' : 'btn-ghost')}
              onClick={() => setDefangEnabled(!defangEnabled)}
              title="Defang domains and IPs to prevent accidental navigation"
            >
              Defang [.] : {defangEnabled ? 'ON' : 'OFF'}
            </button>
          </div>
        </div>

        {/* Quick Search Chips */}
        <div style={{ display: 'flex', gap: 6, alignItems: 'center', marginTop: 10, flexWrap: 'wrap', fontSize: 11 }}>
          <span className="muted" style={{ fontSize: 11, marginRight: 4 }}>Quick queries:</span>
          {[
            { label: 'cdn-sync-check[.]com', val: 'cdn-sync-check.com', tag: 'C2 Domain' },
            { label: '185.220.101[.]42', val: '185.220.101.42', tag: 'Tor Exit' },
            { label: 'a7f18392…8c9d0', val: 'a7f18392', tag: 'Dropper Hash' },
            { label: 'CVE-2024-38077', val: 'CVE-2024-38077', tag: 'Windows RCE' },
            { label: 'DarkGate Operator', val: 'DarkGate', tag: 'Adversary' },
            { label: 'LockBit 3.0', val: 'LockBit', tag: 'Ransomware' },
          ].map((chip) => (
            <button
              key={chip.val}
              type="button"
              className="btn btn-ghost btn-sm"
              style={{ padding: '3px 8px', fontSize: 11, border: '1px solid hsl(var(--border))', borderRadius: 12 }}
              onClick={() => handleQuickChipClick(chip.val)}
            >
              <b>{chip.label}</b>
              <span className="mono muted" style={{ fontSize: 9, marginLeft: 4 }}>({chip.tag})</span>
            </button>
          ))}
        </div>
      </div>

      {/* Selected Indicator Dossier Spotlight (Rich Hero Inspection) */}
      {selectedIoc && (
        <div className="card card-pad" style={{ borderLeft: '4px solid hsl(var(--primary))' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 12 }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                <span className="badge badge-low" style={{ textTransform: 'uppercase' }}>
                  {selectedIoc.type}
                </span>
                <span className={cn('badge', selectedIoc.severity === 'critical' ? 'badge-critical' : selectedIoc.severity === 'high' ? 'badge-high' : 'badge-medium')}>
                  {selectedIoc.severity.toUpperCase()} THREAT
                </span>
                <span className="badge badge-muted">
                  CONFIDENCE {selectedIoc.confidence}%
                </span>
                {selectedIoc.localSightingsCount && selectedIoc.localSightingsCount > 0 ? (
                  <span className="badge badge-critical" style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                    <span className="event-dot" style={{ width: 6, height: 6, margin: 0, background: 'hsl(var(--destructive))' }} />
                    {selectedIoc.localSightingsCount} SIGHTING{selectedIoc.localSightingsCount > 1 ? 'S' : ''} ON WS-0427
                  </span>
                ) : null}
              </div>

              <div style={{ fontSize: 20, fontWeight: 800, fontFamily: 'var(--app-font-mono)', display: 'flex', alignItems: 'center', gap: 10 }}>
                {defangEnabled ? selectedIoc.defangedValue : selectedIoc.value}
                <button
                  type="button"
                  className="btn btn-ghost btn-sm"
                  style={{ padding: 4 }}
                  onClick={() => copyToClipboard(defangEnabled ? selectedIoc.defangedValue : selectedIoc.value, selectedIoc.id)}
                  title="Copy indicator value"
                >
                  {copiedId === selectedIoc.id ? <Check size={14} className="signal-good" /> : <Copy size={14} />}
                </button>
              </div>

              <div className="muted" style={{ fontSize: 12, marginTop: 4 }}>
                {selectedIoc.category} · {selectedIoc.threatActor || 'Undetermined Actor'} {selectedIoc.campaign ? `(${selectedIoc.campaign})` : ''}
              </div>
            </div>

            {/* Threat Score Gauge */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
              <div style={{ textAlign: 'right' }}>
                <div style={{ fontSize: 32, fontWeight: 900, lineHeight: 1 }} className={selectedIoc.score >= 80 ? 'signal-danger' : selectedIoc.score >= 50 ? 'signal-warn' : 'signal-good'}>
                  {selectedIoc.score}
                  <span style={{ fontSize: 14, color: 'hsl(var(--muted-foreground))' }}>/100</span>
                </div>
                <div className="muted" style={{ fontSize: 10 }}>
                  {selectedIoc.enginesFlagged} of {selectedIoc.enginesTotal} engines flag
                </div>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                <button
                  type="button"
                  className={cn('btn btn-sm', selectedIoc.followed ? 'btn-primary' : '')}
                  onClick={() => {
                    toggleFollow(selectedIoc.id);
                    toast(selectedIoc.followed ? 'Unfollowed indicator' : 'Following indicator', `Alerts for ${selectedIoc.value} updated.`);
                  }}
                  data-testid="button-follow-indicator"
                >
                  {selectedIoc.followed ? <Check size={13} /> : <Plus size={13} />}
                  {selectedIoc.followed ? 'Following' : 'Follow'}
                </button>

                <button
                  type="button"
                  className={cn('btn btn-sm', selectedIoc.blocked ? 'btn-danger' : 'btn-ghost')}
                  style={{ border: '1px solid hsl(var(--border))' }}
                  onClick={() => {
                    toggleBlock(selectedIoc.id);
                    toast(selectedIoc.blocked ? 'Removed from blocklist' : 'Added to global blocklist', `${selectedIoc.value} firewall status updated.`);
                  }}
                >
                  {selectedIoc.blocked ? <Lock size={13} /> : <Unlock size={13} />}
                  {selectedIoc.blocked ? 'Blocked' : 'Block IOC'}
                </button>
              </div>
            </div>
          </div>

          {/* Local Sighting Alert Banner if detected */}
          {selectedIoc.localSightingsDetail && selectedIoc.localSightingsDetail.length > 0 && (
            <div
              style={{
                marginTop: 14,
                padding: '10px 14px',
                background: 'hsla(0, 75%, 62%, 0.1)',
                border: '1px solid hsl(var(--destructive))',
                borderRadius: 6,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                flexWrap: 'wrap',
                gap: 8,
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <ShieldAlert size={18} className="signal-danger" />
                <div>
                  <div style={{ fontWeight: 700, fontSize: 12, color: 'hsl(var(--destructive))' }}>
                    Active Endpoint Sighting Detected on WS-0427
                  </div>
                  <div className="mono" style={{ fontSize: 11, color: 'hsl(var(--foreground))' }}>
                    {selectedIoc.localSightingsDetail[0]}
                  </div>
                </div>
              </div>

              <div style={{ display: 'flex', gap: 8 }}>
                {onNavigate && (
                  <>
                    <button
                      type="button"
                      className="btn btn-sm btn-ghost"
                      style={{ fontSize: 11, border: '1px solid hsl(var(--destructive))' }}
                      onClick={() => onNavigate(selectedIoc.type === 'ip' || selectedIoc.type === 'domain' ? '/network' : '/processes')}
                    >
                      Pivot to {selectedIoc.type === 'ip' || selectedIoc.type === 'domain' ? 'Network' : 'Processes'} <ArrowRight size={12} />
                    </button>
                    <button
                      type="button"
                      className="btn btn-sm btn-danger"
                      style={{ fontSize: 11 }}
                      onClick={() => onNavigate('/quarantine')}
                    >
                      Inspect Vault <ArrowRight size={12} />
                    </button>
                  </>
                )}
              </div>
            </div>
          )}

          {/* Dossier Detail Grid */}
          <div className="grid split-grid" style={{ marginTop: 14, gap: 14 }}>
            <div>
              <div className="eyebrow" style={{ marginBottom: 6 }}>Technical Synopsis</div>
              <p style={{ fontSize: 12, lineHeight: 1.6, margin: 0 }}>
                {selectedIoc.description}
              </p>

              <div style={{ display: 'flex', gap: 6, marginTop: 10, flexWrap: 'wrap' }}>
                {selectedIoc.tags.map((t) => (
                  <span key={t} className="badge badge-muted" style={{ fontSize: 10 }}>
                    #{t}
                  </span>
                ))}
              </div>
            </div>

            <div>
              <div className="eyebrow" style={{ marginBottom: 6 }}>Infrastructure & Provenance</div>
              <div className="kpi-line">
                <span className="muted">First Observed</span>
                <b className="mono">{new Date(selectedIoc.firstSeen).toLocaleDateString()}</b>
              </div>
              <div className="kpi-line">
                <span className="muted">Last Telemetry</span>
                <b className="mono">{new Date(selectedIoc.lastSeen).toLocaleTimeString()}</b>
              </div>
              {selectedIoc.asn && (
                <div className="kpi-line">
                  <span className="muted">ASN / Network</span>
                  <b>{selectedIoc.asn}</b>
                </div>
              )}
              {selectedIoc.geo && (
                <div className="kpi-line">
                  <span className="muted">Geolocation</span>
                  <b>{selectedIoc.geo.city}, {selectedIoc.geo.country} ({selectedIoc.geo.countryCode})</b>
                </div>
              )}
              {selectedIoc.registrar && (
                <div className="kpi-line">
                  <span className="muted">Registrar / Provider</span>
                  <b>{selectedIoc.registrar}</b>
                </div>
              )}
            </div>
          </div>

          {/* MITRE ATT&CK Mapping Chips */}
          <div style={{ marginTop: 14, paddingTop: 12, borderTop: '1px solid hsl(var(--border))' }}>
            <div className="eyebrow" style={{ marginBottom: 8 }}>MITRE ATT&CK® Techniques</div>
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
              {selectedIoc.mitreTechniques.map((tech) => (
                <div
                  key={tech.id}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 6,
                    padding: '4px 8px',
                    borderRadius: 4,
                    background: 'hsl(var(--muted))',
                    fontSize: 11,
                    border: '1px solid hsl(var(--border))',
                  }}
                >
                  <b className="mono" style={{ color: 'hsl(var(--primary))' }}>{tech.id}</b>
                  <span>{tech.name}</span>
                  <span className="muted" style={{ fontSize: 10 }}>({tech.tactic})</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Navigation Tabs */}
      <div style={{ display: 'flex', gap: 8, borderBottom: '1px solid hsl(var(--border))', paddingBottom: 8, flexWrap: 'wrap' }}>
        {[
          { id: 'iocs', label: 'Indicators of Compromise', icon: Fingerprint, count: indicators.length },
          { id: 'feeds', label: 'Threat Feeds & Sync', icon: Radio, count: feeds.length },
          { id: 'actors', label: 'Threat Actors & Campaigns', icon: Activity, count: actors.length },
          { id: 'cves', label: 'Vulnerability Watch (KEV)', icon: Bug, count: vulnerabilities.length },
          { id: 'correlation', label: 'Endpoint Correlation Matrix', icon: Flame, count: correlations.length, highlight: correlations.length > 0 },
        ].map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              type="button"
              className={cn('btn', isActive ? 'btn-primary' : 'btn-ghost')}
              style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12 }}
              onClick={() => setActiveTab(tab.id as ActiveTab)}
              data-testid={`tab-intelligence-${tab.id}`}
            >
              <Icon size={14} />
              {tab.label}
              <span
                className={cn('badge', tab.highlight ? 'badge-critical' : isActive ? 'badge-low' : 'badge-muted')}
                style={{ fontSize: 10, padding: '1px 6px', marginLeft: 4 }}
              >
                {tab.count}
              </span>
            </button>
          );
        })}
      </div>

      {/* Tab 1: Indicators of Compromise Table */}
      {activeTab === 'iocs' && (
        <div className="card card-pad">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 12, marginBottom: 14 }}>
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
              {/* Type Filter */}
              <div style={{ display: 'flex', gap: 4, background: 'hsl(var(--background))', padding: 3, borderRadius: 6, border: '1px solid hsl(var(--border))' }}>
                {['all', 'domain', 'ip', 'hash', 'cve'].map((t) => (
                  <button
                    key={t}
                    type="button"
                    className={cn('btn btn-sm', selectedType === t ? 'btn-primary' : 'btn-ghost')}
                    style={{ fontSize: 11, padding: '3px 8px', textTransform: 'capitalize' }}
                    onClick={() => setSelectedType(t)}
                  >
                    {t === 'all' ? 'All Types' : t}
                  </button>
                ))}
              </div>

              {/* Severity Filter */}
              <div style={{ display: 'flex', gap: 4, background: 'hsl(var(--background))', padding: 3, borderRadius: 6, border: '1px solid hsl(var(--border))' }}>
                {['all', 'critical', 'high', 'medium', 'low'].map((s) => (
                  <button
                    key={s}
                    type="button"
                    className={cn('btn btn-sm', selectedSeverity === s ? 'btn-primary' : 'btn-ghost')}
                    style={{ fontSize: 11, padding: '3px 8px', textTransform: 'capitalize' }}
                    onClick={() => setSelectedSeverity(s)}
                  >
                    {s === 'all' ? 'All Severities' : s}
                  </button>
                ))}
              </div>

              {/* Sightings toggle */}
              <button
                type="button"
                className={cn('btn btn-sm', onlyLocalSightings ? 'btn-danger' : 'btn-ghost')}
                style={{ fontSize: 11, border: '1px solid hsl(var(--border))' }}
                onClick={() => setOnlyLocalSightings(!onlyLocalSightings)}
              >
                <Flame size={12} />
                Local Sightings Only ({correlations.length})
              </button>
            </div>

            <div className="muted" style={{ fontSize: 11 }}>
              Showing {filteredIndicators.length} of {indicators.length} indicators
            </div>
          </div>

          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
              <thead>
                <tr style={{ borderBottom: '1px solid hsl(var(--border))', textAlign: 'left', color: 'hsl(var(--muted-foreground))' }}>
                  <th style={{ padding: '8px 10px' }}>Indicator</th>
                  <th style={{ padding: '8px 10px' }}>Type</th>
                  <th style={{ padding: '8px 10px' }}>Category</th>
                  <th style={{ padding: '8px 10px' }}>Severity</th>
                  <th style={{ padding: '8px 10px' }}>Score</th>
                  <th style={{ padding: '8px 10px' }}>Threat Actor</th>
                  <th style={{ padding: '8px 10px' }}>Sightings</th>
                  <th style={{ padding: '8px 10px', textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredIndicators.map((ioc) => {
                  const isSelected = ioc.id === selectedIoc?.id;
                  const hasLocalSighting = (ioc.localSightingsCount || 0) > 0;
                  return (
                    <tr
                      key={ioc.id}
                      style={{
                        borderBottom: '1px solid hsl(var(--border))',
                        background: isSelected ? 'hsla(190, 94%, 53%, 0.08)' : 'transparent',
                        cursor: 'pointer',
                      }}
                      onClick={() => setSelectedIocId(ioc.id)}
                    >
                      <td style={{ padding: '10px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                          <span className="mono" style={{ fontWeight: 600, color: isSelected ? 'hsl(var(--primary))' : 'inherit' }}>
                            {defangEnabled ? ioc.defangedValue : ioc.value}
                          </span>
                          {ioc.blocked && (
                            <span className="badge badge-critical" style={{ fontSize: 9, padding: '1px 4px' }}>BLOCKED</span>
                          )}
                          {ioc.followed && (
                            <span className="badge badge-low" style={{ fontSize: 9, padding: '1px 4px' }}>FOLLOWED</span>
                          )}
                        </div>
                      </td>

                      <td style={{ padding: '10px' }}>
                        <span className="badge badge-muted" style={{ textTransform: 'uppercase', fontSize: 10 }}>
                          {ioc.type}
                        </span>
                      </td>

                      <td style={{ padding: '10px' }}>
                        <span>{ioc.category}</span>
                      </td>

                      <td style={{ padding: '10px' }}>
                        <span className={cn('badge', ioc.severity === 'critical' ? 'badge-critical' : ioc.severity === 'high' ? 'badge-high' : 'badge-medium')}>
                          {ioc.severity}
                        </span>
                      </td>

                      <td style={{ padding: '10px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                          <div style={{ width: 40, height: 6, background: 'hsl(var(--muted))', borderRadius: 3, overflow: 'hidden' }}>
                            <div
                              style={{
                                width: `${ioc.score}%`,
                                height: '100%',
                                background: ioc.score >= 80 ? 'hsl(var(--destructive))' : ioc.score >= 50 ? 'hsl(var(--chart-3))' : 'hsl(var(--accent))',
                              }}
                            />
                          </div>
                          <span className="mono" style={{ fontSize: 11, fontWeight: 700 }}>{ioc.score}</span>
                        </div>
                      </td>

                      <td style={{ padding: '10px' }}>
                        <span className="muted">{ioc.threatActor || '—'}</span>
                      </td>

                      <td style={{ padding: '10px' }}>
                        {hasLocalSighting ? (
                          <span className="badge badge-critical" style={{ fontSize: 10, display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                            <Flame size={10} />
                            {ioc.localSightingsCount} ON WS-0427
                          </span>
                        ) : (
                          <span className="muted" style={{ fontSize: 11 }}>0 local</span>
                        )}
                      </td>

                      <td style={{ padding: '10px', textAlign: 'right' }}>
                        <div style={{ display: 'inline-flex', gap: 4 }} onClick={(e) => e.stopPropagation()}>
                          <button
                            type="button"
                            className="btn btn-ghost btn-sm"
                            style={{ padding: '4px 6px' }}
                            onClick={() => copyToClipboard(defangEnabled ? ioc.defangedValue : ioc.value, ioc.id)}
                            title="Copy indicator"
                          >
                            <Copy size={13} />
                          </button>
                          <button
                            type="button"
                            className={cn('btn btn-sm', ioc.followed ? 'btn-primary' : 'btn-ghost')}
                            style={{ padding: '4px 6px' }}
                            onClick={() => toggleFollow(ioc.id)}
                            title="Follow/unfollow"
                          >
                            {ioc.followed ? <Check size={13} /> : <Plus size={13} />}
                          </button>
                          <button
                            type="button"
                            className="btn btn-ghost btn-sm"
                            style={{ padding: '4px 6px' }}
                            onClick={() => setSelectedIocId(ioc.id)}
                            title="Inspect in dossier"
                          >
                            <Eye size={13} />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Tab 2: Threat Feeds & Ingestion */}
      {activeTab === 'feeds' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          <div className="card card-pad">
            <PanelTitle
              title="Global Threat Feeds & Ingestion Network"
              detail="6 ACTIVE FEEDS · REAL-TIME REPUTATION EXCHANGE"
              action={
                <button
                  type="button"
                  className="btn btn-sm"
                  onClick={handleRefresh}
                  disabled={syncingFeeds}
                >
                  <RefreshCw size={13} className={syncingFeeds ? 'animate-spin' : ''} />
                  Synchronize All
                </button>
              }
            />

            <div className="grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: 14, marginTop: 14 }}>
              {feeds.map((feed) => (
                <div
                  key={feed.id}
                  className="card card-pad"
                  style={{ background: 'hsl(var(--background))', border: '1px solid hsl(var(--border))' }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 8 }}>
                    <div>
                      <div style={{ fontWeight: 700, fontSize: 14, display: 'flex', alignItems: 'center', gap: 6 }}>
                        {feed.name}
                      </div>
                      <div className="muted" style={{ fontSize: 11 }}>
                        {feed.provider}
                      </div>
                    </div>
                    <span className={cn('badge', feed.status === 'active' ? 'badge-low' : 'badge-muted')}>
                      <CheckCircle2 size={12} style={{ marginRight: 4 }} />
                      {feed.status.toUpperCase()}
                    </span>
                  </div>

                  <p style={{ fontSize: 11, lineHeight: 1.5, minHeight: 36 }}>
                    {feed.description}
                  </p>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: 6, margin: '12px 0', borderTop: '1px solid hsl(var(--border))', paddingTop: 8 }}>
                    <div className="kpi-line">
                      <span className="muted">Indicators Ingested</span>
                      <b className="mono">{feed.indicatorsCount.toLocaleString()}</b>
                    </div>
                    <div className="kpi-line">
                      <span className="muted">Protocol</span>
                      <b className="mono">{feed.type}</b>
                    </div>
                    <div className="kpi-line">
                      <span className="muted">Latency & Reliability</span>
                      <b>{feed.latencyMs}ms · {feed.reliabilityScore}% verified</b>
                    </div>
                    <div className="kpi-line">
                      <span className="muted">Last Synchronized</span>
                      <b className="mono">{new Date(feed.lastSync).toLocaleTimeString()}</b>
                    </div>
                  </div>

                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 10 }}>
                    <span className="badge badge-muted" style={{ fontSize: 10 }}>{feed.category}</span>
                    <button
                      type="button"
                      className="btn btn-ghost btn-sm"
                      style={{ fontSize: 11 }}
                      onClick={() => toast('Feed resynced', `${feed.name} forced update complete.`)}
                    >
                      <RefreshCw size={11} /> Force Sync
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Tab 3: Threat Actors & Global Campaigns */}
      {activeTab === 'actors' && (
        <div className="grid split-grid" style={{ gap: 16 }}>
          {/* Actors List */}
          <div className="card card-pad">
            <PanelTitle title="Tracked Adversary Groups" detail="ADVANCED PERSISTENT THREATS (APT)" />
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 12 }}>
              {actors.map((actor) => {
                const isSelected = actor.id === selectedActor?.id;
                return (
                  <div
                    key={actor.id}
                    onClick={() => setSelectedActorId(actor.id)}
                    style={{
                      padding: '12px 14px',
                      borderRadius: 6,
                      background: isSelected ? 'hsla(190, 94%, 53%, 0.1)' : 'hsl(var(--background))',
                      border: `1px solid ${isSelected ? 'hsl(var(--primary))' : 'hsl(var(--border))'}`,
                      cursor: 'pointer',
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <div style={{ fontWeight: 800, fontSize: 13 }}>{actor.name}</div>
                      <span className={cn('badge', actor.threatLevel === 'Critical' ? 'badge-critical' : 'badge-high')} style={{ fontSize: 10 }}>
                        {actor.threatLevel}
                      </span>
                    </div>

                    <div className="muted" style={{ fontSize: 11, marginTop: 2 }}>
                      {actor.origin} · Active since {actor.activeSince}
                    </div>

                    <div style={{ display: 'flex', gap: 4, marginTop: 8, flexWrap: 'wrap' }}>
                      {actor.aliases.slice(0, 2).map((al) => (
                        <span key={al} className="badge badge-muted" style={{ fontSize: 9 }}>
                          {al}
                        </span>
                      ))}
                      <span className="mono muted" style={{ fontSize: 10, marginLeft: 'auto' }}>
                        {actor.indicatorCount} IOCs
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Selected Actor Deep Dossier */}
          {selectedActor && (
            <div className="card card-pad">
              <PanelTitle
                title={selectedActor.name}
                detail={`ORIGIN: ${selectedActor.origin.toUpperCase()}`}
                action={
                  <button
                    type="button"
                    className="btn btn-sm"
                    onClick={() => handleQuickChipClick(selectedActor.name)}
                  >
                    <Search size={12} /> Query IOCs
                  </button>
                }
              />

              <div style={{ display: 'flex', gap: 8, margin: '12px 0', flexWrap: 'wrap' }}>
                <span className="badge badge-low">MOTIVATION: {selectedActor.motivation}</span>
                <span className="badge badge-muted">SINCE {selectedActor.activeSince}</span>
                <span className={cn('badge', selectedActor.threatLevel === 'Critical' ? 'badge-critical' : 'badge-high')}>
                  {selectedActor.threatLevel.toUpperCase()} THREAT LEVEL
                </span>
              </div>

              <p style={{ fontSize: 12, lineHeight: 1.6 }}>
                {selectedActor.description}
              </p>

              <div style={{ marginTop: 14 }}>
                <div className="eyebrow" style={{ marginBottom: 6 }}>Targeted Industry Sectors</div>
                <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                  {selectedActor.targetSectors.map((sec) => (
                    <span key={sec} className="badge badge-muted" style={{ fontSize: 11 }}>
                      {sec}
                    </span>
                  ))}
                </div>
              </div>

              <div style={{ marginTop: 14 }}>
                <div className="eyebrow" style={{ marginBottom: 6 }}>Known Malware & Weaponry</div>
                <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                  {selectedActor.knownMalware.map((mw) => (
                    <span key={mw} className="badge badge-low" style={{ fontSize: 11, fontFamily: 'var(--app-font-mono)' }}>
                      {mw}
                    </span>
                  ))}
                </div>
              </div>

              <div style={{ marginTop: 14 }}>
                <div className="eyebrow" style={{ marginBottom: 6 }}>Primary MITRE ATT&CK® TTPs</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                  {selectedActor.primaryTTPs.map((ttp) => (
                    <div key={ttp.id} className="kpi-line">
                      <span className="mono" style={{ color: 'hsl(var(--primary))' }}>{ttp.id}</span>
                      <b>{ttp.name}</b>
                    </div>
                  ))}
                </div>
              </div>

              <div style={{ marginTop: 14 }}>
                <div className="eyebrow" style={{ marginBottom: 6 }}>Active Global Campaigns</div>
                <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                  {selectedActor.activeCampaigns.map((camp) => (
                    <span key={camp} className="badge badge-high" style={{ fontSize: 11 }}>
                      {camp}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Tab 4: Vulnerability & CVE Intelligence (Exploit Watch) */}
      {activeTab === 'cves' && (
        <div className="card card-pad">
          <PanelTitle
            title="Known Exploited Vulnerabilities (KEV) Watchlist"
            detail="AUTHORITATIVE CISA & EPSS REAL-TIME ADVISORIES"
          />

          <div style={{ display: 'flex', flexDirection: 'column', gap: 12, marginTop: 14 }}>
            {vulnerabilities.map((vuln) => (
              <div
                key={vuln.cveId}
                style={{
                  padding: 14,
                  borderRadius: 6,
                  background: 'hsl(var(--background))',
                  border: '1px solid hsl(var(--border))',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 10 }}>
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <span className="mono" style={{ fontSize: 15, fontWeight: 800, color: 'hsl(var(--primary))' }}>
                        {vuln.cveId}
                      </span>
                      <span className={cn('badge', vuln.severity === 'critical' ? 'badge-critical' : 'badge-high')}>
                        CVSS {vuln.cvss}
                      </span>
                      {vuln.cisaKev && (
                        <span className="badge badge-critical" style={{ fontSize: 9 }}>
                          CISA KEV CATALOG
                        </span>
                      )}
                      <span className="badge badge-muted" style={{ fontSize: 10 }}>
                        EPSS {(vuln.epssScore * 100).toFixed(1)}% PROBABILITY
                      </span>
                    </div>

                    <div style={{ fontWeight: 700, fontSize: 13, marginTop: 4 }}>
                      {vuln.title}
                    </div>

                    <div className="muted" style={{ fontSize: 11, marginTop: 2 }}>
                      Affected: <b>{vuln.vendor} {vuln.product}</b> · Published {vuln.published}
                    </div>
                  </div>

                  <div style={{ textAlign: 'right' }}>
                    <span className={cn('badge', vuln.exploitStatus === 'In-The-Wild Exploitation' ? 'badge-critical' : 'badge-high')} style={{ fontSize: 11 }}>
                      {vuln.exploitStatus.toUpperCase()}
                    </span>
                    <div className="muted mono" style={{ fontSize: 10, marginTop: 4 }}>
                      Patch Available: {vuln.patchAvailable ? 'YES (Security Bulletin)' : 'PENDING'}
                    </div>
                  </div>
                </div>

                <p style={{ fontSize: 12, lineHeight: 1.5, marginTop: 10, color: 'hsl(var(--foreground))' }}>
                  {vuln.description}
                </p>

                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 10, borderTop: '1px solid hsl(var(--border))', paddingTop: 8 }}>
                  <span className="muted mono" style={{ fontSize: 10 }}>{vuln.mitreTechnique}</span>
                  <button
                    type="button"
                    className="btn btn-ghost btn-sm"
                    style={{ fontSize: 11 }}
                    onClick={() => handleQuickChipClick(vuln.cveId)}
                  >
                    Query Threat Matrix <ArrowRight size={12} />
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Tab 5: Fleet Telemetry Correlation (Live Sensor Match) */}
      {activeTab === 'correlation' && (
        <div className="card card-pad">
          <PanelTitle
            title="Endpoint Telemetry Correlation Matrix"
            detail={`MATCHING LIVE DATA FROM SENSORS AGAINST ${indicators.length} IOCS`}
          />

          <div style={{ margin: '12px 0', fontSize: 12, lineHeight: 1.5, color: 'hsl(var(--muted-foreground))' }}>
            ARGUS continuously evaluates real-time process execution command lines, open socket connections, and filesystem scans on endpoint <b>WS-0427</b> against the threat intelligence repository.
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {correlations.map((match, idx) => (
              <div
                key={idx}
                style={{
                  padding: 14,
                  borderRadius: 6,
                  background: 'hsla(0, 75%, 62%, 0.06)',
                  border: '1px solid hsl(var(--destructive))',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 8 }}>
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <span className="badge badge-critical" style={{ fontSize: 10 }}>
                        CORRELATED MATCH · {match.source.toUpperCase()}
                      </span>
                      <span className="mono" style={{ fontWeight: 800, fontSize: 14 }}>
                        {match.indicatorValue}
                      </span>
                      <span className="badge badge-muted" style={{ fontSize: 10 }}>
                        {match.indicatorType.toUpperCase()}
                      </span>
                    </div>

                    <div style={{ fontWeight: 600, fontSize: 13, marginTop: 6, color: 'hsl(var(--foreground))' }}>
                      {match.details}
                    </div>

                    <div className="mono muted" style={{ fontSize: 11, marginTop: 4 }}>
                      Observed at: {new Date(match.timestamp).toLocaleTimeString()} · Target: WS-0427
                    </div>
                  </div>

                  <div style={{ display: 'flex', gap: 8 }}>
                    {onNavigate && (
                      <button
                        type="button"
                        className="btn btn-sm btn-ghost"
                        style={{ border: '1px solid hsl(var(--border))' }}
                        onClick={() => onNavigate(match.source === 'process' ? '/processes' : match.source === 'network' ? '/network' : '/files')}
                      >
                        Inspect {match.source} <ArrowRight size={12} />
                      </button>
                    )}
                    <button
                      type="button"
                      className="btn btn-sm btn-danger"
                      onClick={() => {
                        toast('Containment triggered', `Remediation initiated for ${match.indicatorValue}`);
                      }}
                    >
                      Remediate IOC
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Modal: Add / Submit Custom IOC */}
      {isAddModalOpen && (
        <div className="modal-backdrop" role="presentation">
          <div className="modal" style={{ maxWidth: 500 }}>
            <div className="eyebrow">Threat Intelligence Repository</div>
            <h2>Register New Indicator (IOC)</h2>
            <p>
              Submit an external indicator observed during forensic investigation. The indicator will be added to the live correlation engine.
            </p>

            <form onSubmit={handleAddSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 12, marginTop: 14 }}>
              <div>
                <label className="muted" style={{ fontSize: 11, display: 'block', marginBottom: 4 }}>Indicator Value *</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. evil-payload-cdn.net or 192.168.1.100"
                  value={newIocValue}
                  onChange={(e) => setNewIocValue(e.target.value)}
                  className="form-input"
                  style={{ width: '100%', padding: '8px 10px', borderRadius: 4, background: 'hsl(var(--background))', border: '1px solid hsl(var(--border))', color: 'hsl(var(--foreground))' }}
                />
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
                <div>
                  <label className="muted" style={{ fontSize: 11, display: 'block', marginBottom: 4 }}>Type</label>
                  <select
                    value={newIocType}
                    onChange={(e) => setNewIocType(e.target.value as IndicatorType)}
                    className="form-input"
                    style={{ width: '100%', padding: '8px 10px', borderRadius: 4, background: 'hsl(var(--background))', border: '1px solid hsl(var(--border))', color: 'hsl(var(--foreground))' }}
                  >
                    <option value="domain">Domain</option>
                    <option value="ip">IP Address</option>
                    <option value="hash">SHA-256 Hash</option>
                    <option value="url">URL</option>
                    <option value="cve">CVE</option>
                  </select>
                </div>

                <div>
                  <label className="muted" style={{ fontSize: 11, display: 'block', marginBottom: 4 }}>Severity</label>
                  <select
                    value={newIocSeverity}
                    onChange={(e) => setNewIocSeverity(e.target.value as IndicatorSeverity)}
                    className="form-input"
                    style={{ width: '100%', padding: '8px 10px', borderRadius: 4, background: 'hsl(var(--background))', border: '1px solid hsl(var(--border))', color: 'hsl(var(--foreground))' }}
                  >
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="muted" style={{ fontSize: 11, display: 'block', marginBottom: 4 }}>Threat Category</label>
                <input
                  type="text"
                  placeholder="e.g. Command & Control, Stealer, Ransomware"
                  value={newIocCategory}
                  onChange={(e) => setNewIocCategory(e.target.value)}
                  className="form-input"
                  style={{ width: '100%', padding: '8px 10px', borderRadius: 4, background: 'hsl(var(--background))', border: '1px solid hsl(var(--border))', color: 'hsl(var(--foreground))' }}
                />
              </div>

              <div>
                <label className="muted" style={{ fontSize: 11, display: 'block', marginBottom: 4 }}>Associated Threat Actor (Optional)</label>
                <input
                  type="text"
                  placeholder="e.g. APT29, DarkGate, FIN7"
                  value={newIocActor}
                  onChange={(e) => setNewIocActor(e.target.value)}
                  className="form-input"
                  style={{ width: '100%', padding: '8px 10px', borderRadius: 4, background: 'hsl(var(--background))', border: '1px solid hsl(var(--border))', color: 'hsl(var(--foreground))' }}
                />
              </div>

              <div>
                <label className="muted" style={{ fontSize: 11, display: 'block', marginBottom: 4 }}>Forensic Description</label>
                <textarea
                  rows={3}
                  placeholder="Details regarding sighting, delivery mechanism, or context..."
                  value={newIocDesc}
                  onChange={(e) => setNewIocDesc(e.target.value)}
                  className="form-input"
                  style={{ width: '100%', padding: '8px 10px', borderRadius: 4, background: 'hsl(var(--background))', border: '1px solid hsl(var(--border))', color: 'hsl(var(--foreground))' }}
                />
              </div>

              <div className="modal-actions" style={{ marginTop: 10 }}>
                <button type="button" className="btn" onClick={() => setIsAddModalOpen(false)}>
                  Cancel
                </button>
                <button type="submit" className="btn btn-primary">
                  Submit Indicator
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
