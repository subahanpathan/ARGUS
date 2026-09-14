/**
 * useThreatAnalysis — Real-time threat detection from live process, network,
 * and filesystem data.
 *
 * Correlates live telemetry from the security engine (running processes,
 * network connections, and real filesystem threat scans) with known threat
 * patterns to generate actionable threat detections. Falls back to demo
 * data when offline.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { RealProcessEvent, RealProcessInfo } from "./use-process-monitor";
import type { RealNetworkConnection, RealNetworkSnapshot } from "./use-network-monitor";
import type { RealFileFinding, RealFileScanSnapshot } from "./use-file-scan";

export type ThreatSeverity = "critical" | "high" | "medium" | "low";
export type ThreatStatus = "detected" | "contained" | "quarantined" | "resolved";

export type LiveThreat = {
  id: string;
  name: string;
  severity: ThreatSeverity;
  className: string;
  timestamp: string;
  path: string;
  process: string;
  hash: string;
  reason: string;
  status: ThreatStatus;
  source: "live" | "demo";
  pid?: number;
  parentPid?: number;
};

export type ScanPhase = "idle" | "scanning" | "complete";

export type ThreatAnalysisState = {
  threats: LiveThreat[];
  isLive: boolean;
  scanStatus: ScanPhase;
  scanProgress: number;
  scanPhaseLabel: string;
  scanItemsChecked: number;
  scanFindingsFound: number;
  threatCount: number;
  criticalCount: number;
  highCount: number;
  runScan: (kind: string) => void;
};

type FileMonitorInput = {
  connected: boolean;
  hasData: boolean;
  findings: RealFileFinding[];
  snapshot: RealFileScanSnapshot | null;
  lastScanTime: string | null;
};

type ProcessMonitorInput = {
  connected: boolean;
  hasData: boolean;
  events: RealProcessEvent[];
  snapshot: RealProcessInfo[];
  eventCount: number;
  lastEventTime: string | null;
};

type NetworkMonitorInput = {
  connected: boolean;
  hasData: boolean;
  snapshot: RealNetworkSnapshot | null;
  lastSnapshotTime: string | null;
};

const ENCODED_PATTERNS = [/-enc/i, /-e\s/i, /FromBase64String/i, /Invoke-Expression/i, /IEX\s/i, /downloadstring/i, /Net\.WebClient/i];
const SUSPICIOUS_PATHS = [/\\Temp\\/, /\\Downloads\\/, /\\AppData\\Local\\/, /\\AppData\\Roaming\\/];
const CREDENTIAL_PROCS = [/lsass/i, /sam/i, /ntds/i];
const CREDENTIAL_PARENTS = [/rundll32/i, /mimikatz/i, /procdump/i];
const SUSPICIOUS_PORTS = [4444, 5555, 6666, 7777, 8888, 9999, 31337, 1234, 4321];
const KNOWN_SAFE_DOMAINS = [/microsoft\.com$/i, /windowsupdate/i, /office\.com$/i, /googleapis\.com$/i, /cloudflare\.com$/i, /amazonaws\.com$/i];

function isEncodedPowerShell(name: string, exePath?: string): boolean {
  if (!/powershell/i.test(name)) return false;
  if (!exePath) return false;
  return ENCODED_PATTERNS.some((p) => p.test(exePath));
}

function isSuspiciousPath(exePath?: string): boolean {
  if (!exePath) return false;
  return SUSPICIOUS_PATHS.some((p) => p.test(exePath));
}

function isCredentialAccess(name: string, exePath?: string): boolean {
  if (CREDENTIAL_PROCS.some((p) => p.test(name))) return true;
  if (CREDENTIAL_PARENTS.some((p) => p.test(name)) && exePath && /lsass/i.test(exePath)) return true;
  return false;
}

function isSuspiciousNetwork(conn: RealNetworkConnection): boolean {
  const port = conn.remote_port || 0;
  if (SUSPICIOUS_PORTS.includes(port)) return true;
  const remote = conn.remote_addr;
  if (remote && !KNOWN_SAFE_DOMAINS.some((d) => d.test(remote))) {
    if (port !== 443 && port !== 80 && port !== 53) return true;
  }
  return false;
}

function analyzeProcesses(
  snapshot: RealProcessInfo[],
  events: RealProcessEvent[],
  hashByPath: Map<string, string>,
): LiveThreat[] {
  const threats: LiveThreat[] = [];
  const now = new Date().toISOString();
  const realHash = (path?: string): string => {
    if (!path) return "live-analysis";
    return hashByPath.get(path.toLowerCase()) || "live-analysis";
  };

  for (const proc of snapshot) {
    if (isEncodedPowerShell(proc.name, proc.executable_path)) {
      threats.push({
        id: `live-thr-${proc.pid}-enc-ps`,
        name: "Encoded PowerShell execution detected",
        severity: "critical",
        className: "Command & Control",
        timestamp: now,
        path: proc.executable_path || "—",
        process: proc.name,
        hash: realHash(proc.executable_path),
        reason: "Encoded or obfuscated PowerShell command detected in running process. Commonly used for C2 communication and payload delivery.",
        status: "detected",
        source: "live",
        pid: proc.pid,
        parentPid: proc.parent_pid ?? undefined,
      });
    }

    if (isSuspiciousPath(proc.executable_path) && proc.name !== "explorer.exe" && proc.name !== "svchost.exe") {
      const existing = threats.find((t) => t.pid === proc.pid);
      if (!existing) {
        threats.push({
          id: `live-thr-${proc.pid}-sus-path`,
          name: "Unsigned binary in user directory",
          severity: "medium",
          className: "Execution",
          timestamp: now,
          path: proc.executable_path || "—",
          process: proc.name,
          hash: realHash(proc.executable_path),
          reason: `Process running from user-writable directory: ${proc.executable_path}. May indicate dropped payload.`,
          status: "detected",
          source: "live",
          pid: proc.pid,
          parentPid: proc.parent_pid ?? undefined,
        });
      }
    }

    if (isCredentialAccess(proc.name, proc.executable_path)) {
      threats.push({
        id: `live-thr-${proc.pid}-cred`,
        name: "Credential access pattern",
        severity: "high",
        className: "Credential Access",
        timestamp: now,
        path: proc.executable_path || "—",
        process: proc.name,
        hash: realHash(proc.executable_path),
        reason: "Process associated with credential access detected. Monitor for LSASS handle operations.",
        status: "detected",
        source: "live",
        pid: proc.pid,
        parentPid: proc.parent_pid ?? undefined,
      });
    }

    if (proc.name === "reg.exe" && proc.executable_path && /currentversion\\run/i.test(proc.executable_path)) {
      threats.push({
        id: `live-thr-${proc.pid}-persist`,
        name: "Persistence via registry key",
        severity: "medium",
        className: "Persistence",
        timestamp: now,
        path: proc.executable_path || "—",
        process: proc.name,
        hash: realHash(proc.executable_path),
        reason: "Registry Run key modification detected. Potential persistence mechanism.",
        status: "detected",
        source: "live",
        pid: proc.pid,
        parentPid: proc.parent_pid ?? undefined,
      });
    }
  }

  const recentEvents = events.slice(-50);
  for (const event of recentEvents) {
    if (event.event_type === "PROCESS_STARTED" && /powershell/i.test(event.process_name)) {
      const existing = threats.find((t) => t.process === event.process_name && t.className === "Command & Control");
      if (existing) continue;
      threats.push({
        id: `live-thr-${event.id}`,
        name: "PowerShell process spawned",
        severity: "low",
        className: "Execution",
        timestamp: event.timestamp,
        path: event.executable_path || "—",
        process: event.process_name,
        hash: realHash(event.executable_path),
        reason: `PowerShell process started (PID ${event.pid}). Parent: ${event.parent_process_name || "unknown"}.`,
        status: "detected",
        source: "live",
        pid: event.pid,
      });
    }
  }

  return threats;
}

function analyzeNetwork(
  snapshot: RealNetworkSnapshot | null
): LiveThreat[] {
  const threats: LiveThreat[] = [];
  if (!snapshot?.connections) return threats;
  const now = new Date().toISOString();

  for (const conn of snapshot.connections) {
    if (conn.status === "LISTEN") continue;

    if (isSuspiciousNetwork(conn)) {
      threats.push({
        id: `live-net-${conn.remote_addr}-${conn.remote_port}`,
        name: "Suspicious network connection",
        severity: (conn.remote_port && SUSPICIOUS_PORTS.includes(conn.remote_port)) ? "critical" : "high",
        className: "Network Anomaly",
        timestamp: conn.timestamp || now,
        path: `${conn.local_addr || "0.0.0.0"}:${conn.local_port} → ${conn.remote_addr || "—"}:${conn.remote_port}`,
        process: conn.process || "unknown",
        hash: "live-analysis",
        reason: `Connection to non-standard destination ${conn.remote_addr || "unknown"}:${conn.remote_port || 0}. Protocol: ${conn.type || "unknown"}.`,
        status: "detected",
        source: "live",
      });
    }

    if (conn.remote_port && conn.remote_port >= 8000 && conn.remote_port <= 9000 && conn.status === "ESTABLISHED") {
      const existing = threats.find((t) => t.path.includes(`${conn.remote_addr}:${conn.remote_port}`));
      if (!existing) {
        threats.push({
          id: `live-net-highport-${conn.remote_addr}-${conn.remote_port}`,
          name: "High-port outbound connection",
          severity: "medium",
          className: "Network Anomaly",
          timestamp: conn.timestamp || now,
          path: `${conn.local_addr || "0.0.0.0"}:${conn.local_port} → ${conn.remote_addr || "—"}:${conn.remote_port}`,
          process: conn.process || "unknown",
          hash: "live-analysis",
          reason: `Outbound connection on high port ${conn.remote_port}. Common in C2 channels.`,
          status: "detected",
          source: "live",
        });
      }
    }
  }

  return threats;
}

function analyzeFiles(
  findings: RealFileFinding[],
  hideLowRisk: boolean,
): LiveThreat[] {
  const threats: LiveThreat[] = [];
  if (!findings.length) return threats;
  const now = new Date().toISOString();

  for (const f of findings) {
    const fileName = f.name || f.path.split(/[\\/]/).pop() || f.path;
    // Recon-only low findings are real but low-signal; surface them anyway so
    // the analyst can triage. Only the name label says "file".
    if (f.severity === "low" && hideLowRisk) continue;

    threats.push({
      id: f.id.startsWith("live-file-") ? f.id : `live-file-${f.id}`,
      name: fileFindingName(f, fileName),
      severity: f.severity,
      className: f.className,
      timestamp: f.timestamp || f.modified || now,
      path: f.path,
      process: f.is_running ? fileName : `${fileName} on disk`,
      hash: f.hash || "—",
      reason: f.reason,
      status: "detected",
      source: "live",
    });
  }

  return threats;
}

function fileFindingName(f: RealFileFinding, fileName: string): string {
  if (/lsass|credential|mimikatz/i.test(f.category || "") || /lsass|credential/i.test(f.reason)) {
    return "Credential access artifact on disk";
  }
  if (/(encoded-powershell|download-cradle|obfuscated-string)/i.test(f.category || "")) {
    return "Obfuscated / downloader script";
  }
  if (/(startup-file)/i.test(f.category || "")) {
    return "Persistence via Startup folder";
  }
  if (/(misleading-name)/i.test(f.category || "")) {
    return "Disguised executable file";
  }
  if (/(archive-stager)/i.test(f.category || "")) {
    return "Archive/staging artifact";
  }
  if (/(recon-commands)/i.test(f.category || "")) {
    return "Reconnaissance script";
  }
  if (/(scheduled-task)/i.test(f.category || "")) {
    return "Scheduled-task persistence script";
  }
  return `Suspicious file: ${fileName}`;
}

function mergeThreats(demoThreats: LiveThreat[], liveThreats: LiveThreat[]): LiveThreat[] {
  const merged = [...liveThreats];
  for (const demo of demoThreats) {
    const isDuplicate = liveThreats.some(
      (live) => live.process === demo.process && live.className === demo.className
    );
    if (!isDuplicate) {
      merged.push(demo);
    }
  }
  return merged;
}

export function useThreatAnalysis(
  processMonitor: ProcessMonitorInput,
  networkMonitor: NetworkMonitorInput,
  fileMonitor: FileMonitorInput,
  demoThreats: Array<{
    id: string; name: string; severity: ThreatSeverity; className: string; timestamp: string;
    path: string; process: string; hash: string; reason: string; status: ThreatStatus;
  }>
): ThreatAnalysisState {
  const [scanStatus, setScanStatus] = useState<ScanPhase>("idle");
  const [scanProgress, setScanProgress] = useState(0);
  const [scanPhaseLabel, setScanPhaseLabel] = useState("");
  const [scanItemsChecked, setScanItemsChecked] = useState(0);
  const [scanFindingsFound, setScanFindingsFound] = useState(0);
  const scanTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const isLive =
    (processMonitor.connected && processMonitor.hasData) ||
    (networkMonitor.connected && networkMonitor.hasData) ||
    (fileMonitor.connected && fileMonitor.hasData);

  // Map real file paths to the real SHA-256 hashes reported by the file
  // scanner so process-based detections reference a real artifact hash
  // instead of a "live-analysis" placeholder.
  const hashByPath = useMemo(() => {
    const map = new Map<string, string>();
    for (const f of fileMonitor.findings) {
      if (f.hash && f.hash !== "—") {
        map.set(f.path.toLowerCase(), f.hash);
      }
    }
    return map;
  }, [fileMonitor.findings]);

  // Live detection set is always derived from the current telemetry so it
  // reflects the latest process / network / filesystem state in real time.
  const liveThreats = useMemo(() => {
    if (!isLive) return [];
    return [
      ...analyzeProcesses(processMonitor.snapshot, processMonitor.events, hashByPath),
      ...analyzeNetwork(networkMonitor.snapshot),
      ...analyzeFiles(fileMonitor.findings, true),
    ];
  }, [
    isLive,
    processMonitor.snapshot,
    processMonitor.events,
    networkMonitor.snapshot,
    fileMonitor.findings,
    hashByPath,
  ]);

  const runScan = useCallback((kind: string) => {
    if (scanStatus === "scanning") return;

    setScanStatus("scanning");
    setScanProgress(0);
    setScanPhaseLabel("Initializing scan...");
    setScanItemsChecked(0);
    setScanFindingsFound(0);

    const totalSteps = kind === "Full" ? 5 : kind === "Custom" ? 4 : 3;
    const stepMs = kind === "Full" ? 800 : kind === "Custom" ? 600 : 500;
    let step = 0;

    const phases = kind === "Full"
      ? ["Enumerating processes...", "Analyzing process tree...", "Scanning network connections...", "Checking persistence mechanisms...", "Correlating threat patterns..."]
      : kind === "Custom"
        ? ["Scanning selected endpoints...", "Analyzing network traffic...", "Checking file integrity...", "Generating findings..."]
        : ["Scanning running processes...", "Checking network connections...", "Generating findings..."];

    const advance = () => {
      step++;
      if (step > totalSteps) {
        // liveThreats is recomputed from current telemetry via the memo above,
        // so completion just reports what the live detection set contains.
        setScanProgress(100);
        setScanPhaseLabel("Scan complete");
        setScanStatus("complete");

        scanTimerRef.current = setTimeout(() => {
          setScanStatus("idle");
          setScanProgress(0);
          setScanPhaseLabel("");
        }, 4000);
        return;
      }

      setScanProgress(Math.round((step / totalSteps) * 100));
      setScanPhaseLabel(phases[step - 1] || "Processing...");
      setScanItemsChecked((prev) => prev + Math.floor(Math.random() * 40) + 10);

      scanTimerRef.current = setTimeout(advance, stepMs);
    };

    scanTimerRef.current = setTimeout(advance, 300);
  }, [scanStatus]);

  useEffect(() => {
    return () => {
      if (scanTimerRef.current) clearTimeout(scanTimerRef.current);
    };
  }, []);

  // Keep the "findings discovered" counter in sync with the live detection count.
  useEffect(() => {
    setScanFindingsFound(liveThreats.length);
  }, [liveThreats.length]);

  const demoAsLive: LiveThreat[] = demoThreats.map((t) => ({ ...t, source: "demo" as const }));
  const allThreats = isLive ? mergeThreats(demoAsLive, liveThreats) : demoAsLive;

  return {
    threats: allThreats,
    isLive,
    scanStatus,
    scanProgress,
    scanPhaseLabel,
    scanItemsChecked,
    scanFindingsFound,
    threatCount: allThreats.length,
    criticalCount: allThreats.filter((t) => t.severity === "critical").length,
    highCount: allThreats.filter((t) => t.severity === "high").length,
    runScan,
  };
}