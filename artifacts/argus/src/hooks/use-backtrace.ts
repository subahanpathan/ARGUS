/**
 * useBacktrace — React hook for ARGUS 3D Advanced Forensic Backtrace & Network Intelligence.
 *
 * Consumes /api/attack-traces/:id/backtrace to drive live and recorded 3D forensic investigation,
 * 12-step sequential animation replay, camera transitions, IP network intelligence, and attribution levels.
 */

import { useCallback, useEffect, useState } from "react";

export type NetworkIntel = {
  ip: string;
  port?: number;
  protocol?: string;
  asn?: string;
  isp?: string;
  organization?: string;
  networkType?: string;
  geolocation?: {
    country: string;
    region?: string;
    city?: string;
  };
  isVpn: boolean;
  isProxy: boolean;
  isTorExit: boolean;
  classification: "POSSIBLE VPN" | "POSSIBLE PROXY" | "TOR EXIT" | "DIRECT CONNECTION" | "UNKNOWN";
  threatIntel?: {
    verdict: "Malicious" | "Suspicious" | "Advisory" | "Clean";
    score: number;
    provider: string;
    firstSeen?: string;
    lastSeen?: string;
    reason?: string;
  };
  dnsRecords?: string[];
};

export type BacktraceNode3D = {
  id: string;
  label: string;
  type:
    | "remote_endpoint"
    | "vpn_proxy_gateway"
    | "local_gateway"
    | "local_socket"
    | "process"
    | "parent_process"
    | "detection"
    | "file_activity"
    | "outbound_socket"
    | "destination"
    | "potential_target";
  sublabel?: string;
  x: number;
  y: number;
  z: number;
  pid?: number;
  processName?: string;
  executablePath?: string;
  ip?: string;
  port?: number;
  protocol?: string;
  observationStatus: "OBSERVED" | "CORRELATED" | "INFERRED" | "UNKNOWN";
  intel?: NetworkIntel;
  details?: Record<string, any>;
};

export type BacktraceLink3D = {
  id: string;
  source: string;
  target: string;
  direction: "inbound" | "outbound" | "local";
  intensity: number;
  flowParticleSpeed: number;
  observationStatus: "OBSERVED" | "CORRELATED" | "INFERRED" | "UNKNOWN";
  evidence: string;
};

export type EndpointChurnAnalysis = {
  churnDetected: boolean;
  uniqueIpCount: number;
  timeWindowSeconds: number;
  ips: string[];
  interpretation: string;
};

export type AttributionAssessment = {
  level: 0 | 1 | 2 | 3 | 4 | 5;
  label: string;
  confidence: number;
  rationale: string;
};

export type ObservabilityBoundary = {
  isReached: boolean;
  boundaryLabel: string;
  upstreamOrigin: string;
  physicalAttacker: string;
};

export type BacktraceAnimationStep = {
  stepIndex: number;
  stepName: string;
  timestamp: string;
  targetNodeId: string;
  action: string;
  evidence: string;
};

export type UnifiedBacktraceData = {
  incidentId: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low";
  confidence: number;
  remoteSource: NetworkIntel;
  argusHost: {
    hostname: string;
    localIp: string;
    gateway: string;
    os: string;
  };
  networkPathHops: Array<{
    hopIndex: number;
    label: string;
    ip?: string;
    type: string;
    observationStatus: "OBSERVED" | "CORRELATED" | "INFERRED" | "UNKNOWN";
  }>;
  nodes: BacktraceNode3D[];
  links: BacktraceLink3D[];
  endpointChurn: EndpointChurnAnalysis;
  attribution: AttributionAssessment;
  traceBoundary: ObservabilityBoundary;
  animationSequence: BacktraceAnimationStep[];
};

export function useBacktrace(incidentId?: string) {
  const [data, setData] = useState<UnifiedBacktraceData | null>(null);
  const [loading, setLoading] = useState(false);
  const [activeStep, setActiveStep] = useState<number>(12); // Default to full step 12
  const [isPlaying, setIsPlaying] = useState<boolean>(false);
  const [playbackSpeed, setPlaybackSpeed] = useState<number>(1.0);
  const [selectedNode, setSelectedNode] = useState<BacktraceNode3D | null>(null);
  const [cameraMode, setCameraMode] = useState<"3d" | "globe" | "trace_back" | "trace_forward">("3d");

  const fetchBacktrace = useCallback(async (targetId?: string) => {
    setLoading(true);
    try {
      const id = targetId || incidentId || "INC-2026-001";
      const resp = await fetch(`/api/attack-traces/${id}/backtrace`);
      if (resp.ok) {
        const result: UnifiedBacktraceData = await resp.json();
        setData(result);
        if (!selectedNode && result.nodes.length > 0) {
          setSelectedNode(result.nodes[0]);
        }
      }
    } catch {
      // offline or error
    } finally {
      setLoading(false);
    }
  }, [incidentId, selectedNode]);

  useEffect(() => {
    fetchBacktrace(incidentId);
  }, [incidentId, fetchBacktrace]);

  // Replay animation effect
  useEffect(() => {
    if (!isPlaying || !data) return;

    const interval = setInterval(() => {
      setActiveStep((prev) => {
        if (prev >= (data.animationSequence?.length || 12)) {
          setIsPlaying(false);
          return data.animationSequence?.length || 12;
        }
        return prev + 1;
      });
    }, 1500 / playbackSpeed);

    return () => clearInterval(interval);
  }, [isPlaying, data, playbackSpeed]);

  const stepBack = useCallback(() => {
    setActiveStep((prev) => Math.max(1, prev - 1));
  }, []);

  const stepForward = useCallback(() => {
    if (!data) return;
    setActiveStep((prev) => Math.min(data.animationSequence.length, prev + 1));
  }, [data]);

  const replay = useCallback(() => {
    setActiveStep(1);
    setIsPlaying(true);
  }, []);

  return {
    data,
    loading,
    activeStep,
    setActiveStep,
    isPlaying,
    setIsPlaying,
    playbackSpeed,
    setPlaybackSpeed,
    selectedNode,
    setSelectedNode,
    cameraMode,
    setCameraMode,
    stepBack,
    stepForward,
    replay,
    refresh: fetchBacktrace,
  };
}
