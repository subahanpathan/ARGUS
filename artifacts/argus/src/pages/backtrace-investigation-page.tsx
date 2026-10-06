/**
 * backtrace-investigation-page.tsx — ARGUS Full-Screen 3D Forensic Backtrace & Network Intelligence Page.
 *
 * Provides a cinematic, SOC-grade 3D investigation environment allowing analysts to follow observed attack traces:
 * REMOTE SOURCE → NETWORK INFRASTRUCTURE → ARGUS ENDPOINT → PROCESS → DETECTION → FILE ACTIVITY → OUTBOUND CONNECTION → DESTINATION.
 *
 * Driven strictly by REAL ARGUS telemetry.
 */

import { useState } from "react";
import {
  Activity,
  AlertTriangle,
  ArrowLeft,
  ArrowRight,
  BrainCircuit,
  CheckCircle2,
  Clock,
  Compass,
  Cpu,
  Database,
  ExternalLink,
  Eye,
  FileText,
  GitBranch,
  Globe,
  HardDrive,
  Info,
  Layers,
  Lock,
  Maximize2,
  Minimize2,
  Network,
  Pause,
  Play,
  Radio,
  RefreshCw,
  RotateCcw,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  Zap,
} from "lucide-react";
import { useBacktrace, type BacktraceNode3D } from "@/hooks/use-backtrace";
import { Backtrace3DVisualizer } from "@/components/backtrace-3d-visualizer";
import { X, Trophy } from "lucide-react";

function cn(...values: Array<string | false | undefined | null>) {
  return values.filter(Boolean).join(" ");
}

export default function BacktraceInvestigationPage({
  incidentId,
  onNavigate,
}: {
  incidentId?: string;
  onNavigate?: (path: string) => void;
}) {
  const {
    data,
    activeStep,
    setActiveStep,
    isPlaying,
    setIsPlaying,
    replayComplete,
    dismissReplayComplete,
    playbackSpeed,
    setPlaybackSpeed,
    selectedNode,
    setSelectedNode,
    cameraMode,
    setCameraMode,
    stepBack,
    stepForward,
    replay,
    refresh,
  } = useBacktrace(incidentId);

  const [isFullScreen, setIsFullScreen] = useState(false);

  const steps = data?.animationSequence || [];
  const currentStepData = steps.find((s) => s.stepIndex === activeStep) || steps[steps.length - 1];

  return (
    <div
      className={cn("animate-page-enter", isFullScreen && "fullscreen-investigation")}
      style={
        isFullScreen
          ? {
              position: "fixed",
              top: 0,
              left: 0,
              right: 0,
              bottom: 0,
              zIndex: 9999,
              background: "#030712",
              display: "flex",
              flexDirection: "column",
            }
          : { display: "flex", flexDirection: "column", gap: 16 }
      }
    >
      {/* Top Header Controls Bar */}
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          padding: "12px 16px",
          background: "hsl(var(--card))",
          borderBottom: "1px solid hsl(var(--border))",
          flexWrap: "wrap",
          gap: 12,
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          {onNavigate && (
            <button
              type="button"
              className="btn btn-ghost btn-sm"
              onClick={() => onNavigate("/attack-trace")}
              style={{ fontSize: 11 }}
            >
              <ArrowLeft size={13} style={{ marginRight: 4 }} /> Back to Attack Trace
            </button>
          )}

          <div>
            <div className="eyebrow" style={{ fontSize: 10 }}>
              3D ANIMATED ADVANCED BACKTRACE & NETWORK INTELLIGENCE
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <span className="mono" style={{ fontSize: 16, fontWeight: 800 }}>
                {data?.incidentId || "INC-2026-001"}
              </span>
              <span className="badge badge-critical" style={{ fontSize: 10 }}>
                {data?.severity.toUpperCase() || "HIGH"}
              </span>
              <span
                className="badge badge-low"
                style={{
                  background: "hsl(142 71% 16%)",
                  color: "hsl(142 71% 70%)",
                  fontSize: 10,
                }}
              >
                ● 3D ENGINE ACTIVE
              </span>
            </div>
          </div>
        </div>

        {/* Camera & View Controls */}
        <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
          <button
            type="button"
            className={cn("btn btn-sm", cameraMode === "3d" ? "btn-primary" : "btn-ghost")}
            style={{ fontSize: 11 }}
            onClick={() => setCameraMode("3d")}
          >
            <GitBranch size={13} style={{ marginRight: 4 }} /> 3D Network Graph
          </button>
          <button
            type="button"
            className={cn("btn btn-sm", cameraMode === "globe" ? "btn-primary" : "btn-ghost")}
            style={{ fontSize: 11 }}
            onClick={() => setCameraMode("globe")}
          >
            <Globe size={13} style={{ marginRight: 4 }} /> World Globe Mode
          </button>
          <button
            type="button"
            className="btn btn-ghost btn-sm"
            style={{ fontSize: 11 }}
            onClick={() => setCameraMode("trace_back")}
          >
            <RotateCcw size={13} style={{ marginRight: 4 }} /> TRACE BACK
          </button>

          <button
            type="button"
            className="btn btn-ghost btn-sm"
            style={{ fontSize: 11 }}
            onClick={() => setIsFullScreen(!isFullScreen)}
          >
            {isFullScreen ? <Minimize2 size={13} /> : <Maximize2 size={13} />}
          </button>
        </div>
      </div>

      {/* Main 3-Column 3D Layout */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "320px 1fr 340px",
          gap: 12,
          flex: 1,
          minHeight: 580,
        }}
      >
        {/* LEFT COLUMN: 12-Step Timeline & Trace Sequence */}
        <div
          className="card card-pad"
          style={{ display: "flex", flexDirection: "column", gap: 12, overflowY: "auto", maxHeight: 680 }}
        >
          <div className="panel-title">
            <h2>12-Step Attack Sequence</h2>
            <span className="muted" style={{ fontSize: 10 }}>
              Chronological 3D Replay
            </span>
          </div>

          <div style={{ display: "flex", gap: 6, marginBottom: 8 }}>
            <button type="button" className="btn btn-primary btn-sm" style={{ flex: 1, fontSize: 10 }} onClick={replay}>
              <Play size={11} style={{ marginRight: 4 }} /> Replay
            </button>
            <button
              type="button"
              className="btn btn-ghost btn-sm"
              style={{ fontSize: 10 }}
              onClick={() => setIsPlaying(!isPlaying)}
            >
              {isPlaying ? <Pause size={11} /> : <Play size={11} />}
            </button>
          </div>

          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {steps.map((st) => {
              const isActive = activeStep === st.stepIndex;
              const isPassed = activeStep >= st.stepIndex;

              return (
                <div
                  key={st.stepIndex}
                  style={{
                    padding: "8px 10px",
                    borderRadius: 6,
                    border: isActive ? "2px solid hsl(var(--primary))" : "1px solid hsl(var(--border))",
                    background: isActive ? "hsl(var(--primary) / 0.15)" : isPassed ? "hsl(var(--muted) / 0.5)" : "transparent",
                    cursor: "pointer",
                  }}
                  onClick={() => {
                    setActiveStep(st.stepIndex);
                    const targetNode = data?.nodes.find((n) => n.id === st.targetNodeId);
                    if (targetNode) setSelectedNode(targetNode);
                  }}
                >
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", fontSize: 11 }}>
                    <span className="mono" style={{ fontWeight: 800, color: isActive ? "hsl(var(--primary))" : "inherit" }}>
                      STEP {st.stepIndex}
                    </span>
                    <span className="muted mono" style={{ fontSize: 9 }}>
                      {new Date(st.timestamp).toLocaleTimeString()}
                    </span>
                  </div>
                  <div style={{ fontSize: 11, fontWeight: 700, marginTop: 2 }}>{st.stepName}</div>
                  <div className="muted" style={{ fontSize: 10, marginTop: 2 }}>{st.evidence}</div>
                </div>
              );
            })}
          </div>
        </div>

        {/* CENTER COLUMN: 3D Canvas Stage */}
        <div className="card" style={{ position: "relative", overflow: "hidden", minHeight: 540 }}>
          <Backtrace3DVisualizer
            data={data}
            activeStep={activeStep}
            selectedNode={selectedNode}
            onSelectNode={setSelectedNode}
            cameraMode={cameraMode}
          />

          {/* REPLAY COMPLETE — non-blocking toast, bottom-right, auto-dismisses */}
          {replayComplete && (
            <div
              className="replay-complete-toast"
              role="status"
              aria-live="polite"
            >
              <div className="replay-toast-bar" />
              <div className="replay-toast-icon">
                <Trophy size={16} />
              </div>
              <div className="replay-toast-body">
                <div className="replay-toast-title">REPLAY COMPLETE</div>
                <div className="replay-toast-sub">
                  {data?.animationSequence?.length || 12} forensic steps reconstructed in 3D.
                </div>
              </div>
              <button
                type="button"
                className="replay-toast-close"
                aria-label="Dismiss replay complete notification"
                onClick={dismissReplayComplete}
              >
                <X size={12} />
              </button>
            </div>
          )}
        </div>

        {/* RIGHT COLUMN: 3D Forensic Inspector & Intelligence */}
        <div
          className="card card-pad"
          style={{ display: "flex", flexDirection: "column", gap: 14, overflowY: "auto", maxHeight: 680 }}
        >
          <div className="panel-title">
            <h2>Forensic Inspector</h2>
            <span className="muted" style={{ fontSize: 10 }}>
              {selectedNode ? selectedNode.type.toUpperCase() : "SELECT 3D OBJECT"}
            </span>
          </div>

          {!selectedNode ? (
            <div className="muted" style={{ textAlign: "center", padding: "32px 0", fontSize: 12 }}>
              <Info size={24} style={{ marginBottom: 8, opacity: 0.5 }} />
              <p>Click any 3D node in the forensic canvas to inspect network identity, ASN/ISP metadata, PID, or file hashes.</p>
            </div>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
              <div>
                <div className="eyebrow">{selectedNode.type}</div>
                <h3 style={{ fontSize: 15, fontWeight: 700 }}>{selectedNode.label}</h3>
                <div className="muted mono" style={{ fontSize: 11, marginTop: 2 }}>
                  {selectedNode.sublabel}
                </div>
              </div>

              {selectedNode.intel && (
                <div style={{ borderTop: "1px solid hsl(var(--border))", paddingTop: 10 }}>
                  <div style={{ fontSize: 11, fontWeight: 700, marginBottom: 6, color: "hsl(var(--primary))" }}>
                    NETWORK INTELLIGENCE:
                  </div>
                  <div style={{ display: "flex", flexDirection: "column", gap: 4, fontSize: 11 }}>
                    <div><span className="muted mono">IP Address: </span><span className="mono">{selectedNode.intel.ip}</span></div>
                    <div><span className="muted mono">ASN: </span><span className="mono">{selectedNode.intel.asn}</span></div>
                    <div><span className="muted mono">ISP: </span><span>{selectedNode.intel.isp}</span></div>
                    <div><span className="muted mono">Classification: </span><b style={{ color: "hsl(var(--warning))" }}>{selectedNode.intel.classification}</b></div>
                    <div><span className="muted mono">Location: </span><span className="mono">{selectedNode.intel.geolocation?.city}, {selectedNode.intel.geolocation?.country}</span></div>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Endpoint Churn Analysis Card */}
          <div style={{ borderTop: "1px solid hsl(var(--border))", paddingTop: 12 }}>
            <div className="eyebrow" style={{ fontSize: 10, color: "hsl(var(--warning))" }}>
              ENDPOINT CHURN ANALYSIS
            </div>
            <div style={{ fontSize: 12, fontWeight: 700, marginTop: 2 }}>
              {data?.endpointChurn.interpretation || "ENDPOINT CHURN DETECTED"}
            </div>
            <div className="muted" style={{ fontSize: 10, marginTop: 2 }}>
              {data?.endpointChurn.uniqueIpCount} IP addresses rotated within {data?.endpointChurn.timeWindowSeconds} seconds linked to primary process.
            </div>
          </div>

          {/* Level 0-5 Attribution Assessment Card */}
          <div style={{ borderTop: "1px solid hsl(var(--border))", paddingTop: 12 }}>
            <div className="eyebrow" style={{ fontSize: 10, color: "hsl(var(--primary))" }}>
              ATTRIBUTION ASSESSMENT (LEVEL 0 - 5)
            </div>
            <div style={{ fontSize: 13, fontWeight: 800, color: "hsl(var(--primary))", marginTop: 2 }}>
              LEVEL {data?.attribution.level}: {data?.attribution.label}
            </div>
            <p className="muted" style={{ fontSize: 11, lineHeight: 1.4, marginTop: 4 }}>
              {data?.attribution.rationale}
            </p>
          </div>

          {/* Trace Boundary Enforced Card */}
          <div style={{ borderTop: "1px solid hsl(var(--border))", paddingTop: 12 }}>
            <div className="eyebrow" style={{ fontSize: 10, color: "hsl(var(--destructive))" }}>
              OBSERVABILITY BOUNDARY
            </div>
            <div className="mono" style={{ fontSize: 11, fontWeight: 800, color: "hsl(var(--destructive))", marginTop: 2 }}>
              {data?.traceBoundary.boundaryLabel}
            </div>
            <div className="muted" style={{ fontSize: 10, marginTop: 4 }}>
              Upstream Origin: <b>{data?.traceBoundary.upstreamOrigin}</b>
            </div>
            <div className="muted" style={{ fontSize: 10, marginTop: 2 }}>
              Physical Attacker: <b>{data?.traceBoundary.physicalAttacker}</b>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
