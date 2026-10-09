import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  ShieldAlert, ShieldCheck, FileWarning, Send, Cpu, Lock,
  RefreshCw, CheckCircle2, AlertTriangle, ArrowRight, Play,
  Check, X, FileText, Image, Database, Eye, Terminal, Zap, HardDriveDownload,
  Activity, Globe, Server, AlertCircle, FileCheck, Layers, BadgeAlert, CheckSquare,
  Radio, FileCode, Monitor, HardDrive, Wifi, Crosshair, ChevronRight, CornerDownRight, CheckSquare2
} from 'lucide-react';

export type JudgeSimStep = 'IDLE' | 'ENTRY' | 'LEAK_DETECT' | 'CYBER_CELL_CONSENT' | 'ROOT_CAUSE' | 'ADAPTIVE_BLOCK' | 'RECOVERY' | 'FINISHED';

export type AttackVectorType = 'EMAIL_PHISHING' | 'BROWSER_ZERO_DAY' | 'USB_AUTORUN';

interface JudgeSimulationModalProps {
  isOpen: boolean;
  onClose: () => void;
  toast: (title: string, msg: string) => void;
  onNavigate?: (path: string) => void;
}

export const JudgeSimulationModal: React.FC<JudgeSimulationModalProps> = ({
  isOpen,
  onClose,
  toast,
  onNavigate
}) => {
  const [currentStep, setCurrentStep] = useState<JudgeSimStep>('IDLE');
  const [selectedVector, setSelectedVector] = useState<AttackVectorType>('EMAIL_PHISHING');
  const [isAutoRunning, setIsAutoRunning] = useState(false);
  const [userPermissionGranted, setUserPermissionGranted] = useState<boolean | null>(null);
  const [reportReference, setReportReference] = useState<string | null>(null);
  const [terminalLogs, setTerminalLogs] = useState<string[]>([]);
  const [repeatAttackTestResult, setRepeatAttackTestResult] = useState<string | null>(null);
  const [selectedInspectFile, setSelectedInspectFile] = useState<any | null>(null);
  const [customTestCmd, setCustomTestCmd] = useState<string>('');
  const [customCmdLogs, setCustomCmdLogs] = useState<string[]>([]);
  
  // Live Metrics Simulation
  const [cpuUsage, setCpuUsage] = useState<number>(14);
  const [ramUsage, setRamUsage] = useState<number>(4.2);
  const [networkSpeed, setNetworkSpeed] = useState<number>(12);
  
  const terminalEndRef = useRef<HTMLDivElement>(null);

  // Vectors configuration
  const vectorsData = {
    EMAIL_PHISHING: {
      title: 'Phishing Email Cradle (Powershell Base64)',
      process: 'invoice_viewer.docx.exe',
      pid: 9482,
      parent: 'outlook.exe (PID 6230)',
      path: 'C:\\Users\\mira\\AppData\\Local\\Temp\\invoice_viewer.docx.exe',
      c2: '185.199.110.27:443',
      c2Loc: 'Frankfurt, DE (AS20473)'
    },
    BROWSER_ZERO_DAY: {
      title: 'Browser Drive-by Download (Heap Spray)',
      process: 'chrome_updater.exe',
      pid: 10420,
      parent: 'chrome.exe (PID 3104)',
      path: 'C:\\Users\\mira\\Downloads\\chrome_updater.exe',
      c2: '91.215.85.19:8080',
      c2Loc: 'Bucharest, RO (AS39412)'
    },
    USB_AUTORUN: {
      title: 'USB Mass Storage Stager (LNK Abuse)',
      process: 'usb_sync_service.exe',
      pid: 11840,
      parent: 'explorer.exe (PID 4100)',
      path: 'D:\\RECYCLER.BIN\\usb_sync_service.exe',
      c2: '45.154.255.88:4444',
      c2Loc: 'Amsterdam, NL (AS49210)'
    }
  };

  const activeVector = vectorsData[selectedVector];

  // Staged files metadata with rich EXIF / Privacy details
  const stagedDataFiles = [
    {
      name: 'family_photos_vault.zip',
      path: 'C:\\Users\\mira\\Pictures\\Personal\\family_photos_vault.zip',
      size: '14.2 MB',
      type: 'Intimate / Personal Media Vault',
      sensitivity: 'CRITICAL (Intimate PII Violation)',
      entropy: '7.89 (Encrypted ZIP Archive)',
      exif: 'Device: iPhone 15 Pro | GPS: 19.0760° N, 72.8777° E (Private Residence) | Dated: 2026-09-14',
      icon: Image,
      preHash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      postHash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    },
    {
      name: 'Q4_financial_strategy.pdf',
      path: 'C:\\Users\\mira\\Documents\\Corporate\\Q4_financial_strategy.pdf',
      size: '3.8 MB',
      type: 'Confidential Business Strategy',
      sensitivity: 'HIGH (Financial & Trade Secret)',
      entropy: '5.42 (PDF Stream)',
      exif: 'Author: Board of Directors | Classification: Strictly Confidential | Watermark: RESTRICTED',
      icon: FileText,
      preHash: 'f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2',
      postHash: 'f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2'
    },
    {
      name: 'master_passwords.kdbx',
      path: 'C:\\Users\\mira\\Documents\\Vault\\master_passwords.kdbx',
      size: '820 KB',
      type: 'Credential & Master Key Vault',
      sensitivity: 'CRITICAL (Security Master Keys)',
      entropy: '7.95 (KeePass AES-256 Vault)',
      exif: 'Entries: 142 Accounts | Hashes: Argon2id | Last Modified: 2 Hours Ago',
      icon: Database,
      preHash: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
      postHash: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08'
    }
  ];

  useEffect(() => {
    if (!isOpen) {
      setCurrentStep('IDLE');
      setIsAutoRunning(false);
      setUserPermissionGranted(null);
      setReportReference(null);
      setTerminalLogs([]);
      setRepeatAttackTestResult(null);
      setSelectedInspectFile(null);
      setCustomCmdLogs([]);
      setCpuUsage(14);
      setRamUsage(4.2);
      setNetworkSpeed(12);
    }
  }, [isOpen]);

  useEffect(() => {
    terminalEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [terminalLogs]);

  const appendLog = (logLine: string) => {
    setTerminalLogs(prev => [...prev, `[${new Date().toLocaleTimeString()}.${Math.floor(Math.random()*900+100)}] ${logLine}`]);
  };

  // Animate metrics based on step
  useEffect(() => {
    if (currentStep === 'ENTRY' || currentStep === 'LEAK_DETECT') {
      setCpuUsage(78);
      setRamUsage(6.7);
      setNetworkSpeed(1420);
    } else if (currentStep === 'ADAPTIVE_BLOCK' || currentStep === 'RECOVERY') {
      setCpuUsage(22);
      setRamUsage(4.5);
      setNetworkSpeed(18);
    } else {
      setCpuUsage(14);
      setRamUsage(4.2);
      setNetworkSpeed(12);
    }
  }, [currentStep]);

  // Step auto-progression loop with rich log stream
  useEffect(() => {
    let timer: NodeJS.Timeout;
    if (isAutoRunning) {
      if (currentStep === 'ENTRY') {
        appendLog(`ARGUS CORE: Subprocess invocation detected (${activeVector.process} PID ${activeVector.pid}).`);
        appendLog(`PARENT CHAIN: ${activeVector.parent} -> ${activeVector.process}.`);
        appendLog(`ATTACK VECTOR: ${activeVector.title}.`);
        timer = setTimeout(() => {
          setCurrentStep('LEAK_DETECT');
        }, 3200);
      } else if (currentStep === 'LEAK_DETECT') {
        appendLog('DETECTION WINDOW: Measuring exposure window activity between detection and quarantine.');
        appendLog('CLASSIFIER: Identified family_photos_vault.zip -> Intimate Personal Media (PII Violation).');
        appendLog('CLASSIFIER: Identified Q4_financial_strategy.pdf -> Confidential Proprietary Document.');
        appendLog(`C2 MONITOR: Outbound TLS session established to ${activeVector.c2} (${activeVector.c2Loc}).`);
        timer = setTimeout(() => {
          setCurrentStep('CYBER_CELL_CONSENT');
        }, 3500);
      } else if (currentStep === 'CYBER_CELL_CONSENT' && userPermissionGranted !== null) {
        timer = setTimeout(() => {
          setCurrentStep('ROOT_CAUSE');
        }, 3000);
      } else if (currentStep === 'ROOT_CAUSE') {
        appendLog('CORRELATION GRAPH: Reconstructing root cause process ancestry & network topology.');
        appendLog(`CORRELATION ENGINE: Linked ${activeVector.parent} -> ${activeVector.process} -> Staging -> ${activeVector.c2}.`);
        timer = setTimeout(() => {
          setCurrentStep('ADAPTIVE_BLOCK');
        }, 3500);
      } else if (currentStep === 'ADAPTIVE_BLOCK') {
        appendLog(`FIREWALL AGENT: Injected outbound DROP rule for remote IP ${activeVector.c2.split(':')[0]}.`);
        appendLog('APPLOCKER ENGINE: Added kernel deny policy for AppData\\Local\\Temp\\*.exe.');
        appendLog('ADAPTIVE HARDENING: Device self-healing complete. Zero-ms perimeter block active.');
        timer = setTimeout(() => {
          setCurrentStep('RECOVERY');
        }, 3500);
      } else if (currentStep === 'RECOVERY') {
        appendLog('RECOVERY ENGINE: Opening shadow snapshot volume (vss_snap_048).');
        appendLog('RESTORATION: Recovered family_photos_vault.zip (SHA-256 Hash Match 100%).');
        appendLog('RESTORATION: Recovered Q4_financial_strategy.pdf (SHA-256 Hash Match 100%).');
        appendLog('RESTORATION: Recovered master_passwords.kdbx (SHA-256 Hash Match 100%).');
        timer = setTimeout(() => {
          setCurrentStep('FINISHED');
          setIsAutoRunning(false);
        }, 3200);
      }
    }
    return () => clearTimeout(timer);
  }, [currentStep, isAutoRunning, userPermissionGranted, selectedVector]);

  if (!isOpen) return null;

  const startSimulation = () => {
    setCurrentStep('ENTRY');
    setIsAutoRunning(true);
    setUserPermissionGranted(null);
    setReportReference(null);
    setTerminalLogs([`[SYSTEM] Initializing ARGUS Live Judge Simulation (${activeVector.title})...`]);
    setRepeatAttackTestResult(null);
    toast('Judge Simulation Initialized', `Launching attack vector: ${activeVector.title}`);
  };

  const handleGrantConsent = (granted: boolean) => {
    setUserPermissionGranted(granted);
    if (granted) {
      const ref = `CC-ND-2026-${Math.floor(100000 + Math.random() * 900000)}-X`;
      setReportReference(ref);
      appendLog(`CYBER CELL DISPATCH: Forensic incident package #${ref} compiled & dispatched to Cyber Cell API.`);
      toast('Cyber Cell Portal Notified', `Official incident dossier ${ref} submitted with HTTP 200 OK.`);
    } else {
      appendLog('CYBER CELL DISPATCH: User withheld permission for automated report submission.');
      toast('Submission Deferred', 'Cyber Cell dispatch skipped per user selection.');
    }
    setTimeout(() => {
      setCurrentStep('ROOT_CAUSE');
    }, 1500);
  };

  const runRepeatAttackTest = () => {
    setRepeatAttackTestResult('TESTING...');
    setTimeout(() => {
      setRepeatAttackTestResult('BLOCKED IN 0.18ms');
      appendLog(`[KERNEL BLOCK] Attempted re-execution of ${activeVector.process} -> BLOCKED (0.18ms response time)`);
      toast('Adaptive Hardening Verified', 'Attempted repeat execution blocked instantly at kernel perimeter!');
    }, 1000);
  };

  const handleRunCustomCmd = (e: React.FormEvent) => {
    e.preventDefault();
    if (!customTestCmd.trim()) return;
    const cmd = customTestCmd.trim();
    setCustomTestCmd('');
    setCustomCmdLogs(prev => [...prev, `$ ${cmd}`]);
    setTimeout(() => {
      setCustomCmdLogs(prev => [
        ...prev,
        `[ARGUS HARDENING INTERCEPTOR] Execution DENIED for command: "${cmd}"`,
        `Reason: Target file/IP matches active Adaptive Defense Policy (Rule AR-BLOCK-${activeVector.pid})`
      ]);
    }, 400);
  };

  return (
    <div className="modal-backdrop" style={{ background: 'rgba(0, 0, 0, 0.9)', backdropFilter: 'blur(12px)', zIndex: 9999 }}>
      <motion.div
        initial={{ opacity: 0, scale: 0.96, y: 15 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        exit={{ opacity: 0, scale: 0.96 }}
        className="modal"
        style={{
          width: '95%',
          maxWidth: '1080px',
          background: 'hsl(224 71% 2%)',
          border: '1px solid hsl(var(--border))',
          boxShadow: '0 25px 60px -12px rgba(0,0,0,0.9)',
          padding: '24px',
          maxHeight: '94vh',
          overflowY: 'auto'
        }}
      >
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid hsl(var(--border))', paddingBottom: 16, marginBottom: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <div style={{ background: 'linear-gradient(135deg, #eab308 0%, #f97316 100%)', padding: 10, borderRadius: 8, color: '#000' }}>
              <Zap size={24} />
            </div>
            <div>
              <div style={{ fontSize: 11, fontWeight: 800, letterSpacing: '1px', color: 'hsl(var(--primary))', textTransform: 'uppercase' }}>
                ARGUS Security Intelligence · Ultimate Presentation Mode
              </div>
              <h2 style={{ fontSize: 20, margin: 0, fontWeight: 900, color: 'hsl(var(--foreground))' }}>
                Interactive Malware Entry, Leak Detection & Self-Healing Data Recovery Simulation
              </h2>
            </div>
          </div>
          <button className="btn btn-ghost" onClick={onClose} style={{ padding: 6 }}>
            <X size={20} />
          </button>
        </div>

        {/* Live System Gauges Meter Bar */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12, marginBottom: 16, background: 'hsl(224 50% 5%)', padding: 10, borderRadius: 8, border: '1px solid hsl(224 40% 12%)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <Cpu size={18} style={{ color: cpuUsage > 50 ? '#f87171' : 'hsl(var(--primary))' }} />
            <div>
              <div style={{ fontSize: 10, color: 'hsl(var(--muted-foreground))', fontWeight: 700 }}>CPU LOAD</div>
              <div style={{ fontSize: 14, fontWeight: 900, color: cpuUsage > 50 ? '#f87171' : 'hsl(var(--foreground))' }}>{cpuUsage}%</div>
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <HardDrive size={18} style={{ color: ramUsage > 5.5 ? '#f87171' : 'hsl(var(--primary))' }} />
            <div>
              <div style={{ fontSize: 10, color: 'hsl(var(--muted-foreground))', fontWeight: 700 }}>RAM USAGE</div>
              <div style={{ fontSize: 14, fontWeight: 900 }}>{ramUsage} GB</div>
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <Wifi size={18} style={{ color: networkSpeed > 500 ? '#f87171' : 'hsl(var(--primary))' }} />
            <div>
              <div style={{ fontSize: 10, color: 'hsl(var(--muted-foreground))', fontWeight: 700 }}>EXFIL NETWORK RATE</div>
              <div style={{ fontSize: 14, fontWeight: 900, color: networkSpeed > 500 ? '#f87171' : 'hsl(var(--foreground))' }}>{networkSpeed} KB/s</div>
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <ShieldCheck size={18} style={{ color: 'hsl(142 71% 50%)' }} />
            <div>
              <div style={{ fontSize: 10, color: 'hsl(var(--muted-foreground))', fontWeight: 700 }}>ARGUS HARDENING STATE</div>
              <div style={{ fontSize: 12, fontWeight: 900, color: 'hsl(142 71% 50%)' }}>
                {currentStep === 'ADAPTIVE_BLOCK' || currentStep === 'RECOVERY' || currentStep === 'FINISHED' ? 'ARMED & HARDENED' : 'ACTIVE SENSING'}
              </div>
            </div>
          </div>
        </div>

        {/* Stepper Progress Header */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6, 1fr)', gap: 6, marginBottom: 20, background: 'hsl(224 50% 6%)', padding: 8, borderRadius: 8, border: '1px solid hsl(224 40% 12%)' }}>
          {[
            { id: 'ENTRY', label: '1. Malware Entry' },
            { id: 'LEAK_DETECT', label: '2. Leak Window' },
            { id: 'CYBER_CELL_CONSENT', label: '3. Cyber Cell' },
            { id: 'ROOT_CAUSE', label: '4. Root Cause' },
            { id: 'ADAPTIVE_BLOCK', label: '5. Adaptive Block' },
            { id: 'RECOVERY', label: '6. Data Recovery' }
          ].map((s, idx) => {
            const stepOrder: JudgeSimStep[] = ['ENTRY', 'LEAK_DETECT', 'CYBER_CELL_CONSENT', 'ROOT_CAUSE', 'ADAPTIVE_BLOCK', 'RECOVERY', 'FINISHED'];
            const currentIdx = stepOrder.indexOf(currentStep);
            const isPassed = currentIdx > idx;
            const isCurrent = currentStep === s.id;
            return (
              <div
                key={s.id}
                style={{
                  textAlign: 'center',
                  padding: '8px 4px',
                  borderRadius: 6,
                  fontSize: 11,
                  fontWeight: 800,
                  background: isCurrent
                    ? 'linear-gradient(135deg, #eab308, #f97316)'
                    : isPassed
                    ? 'hsl(var(--primary) / 0.2)'
                    : 'transparent',
                  color: isCurrent ? '#000' : isPassed ? 'hsl(var(--primary))' : 'hsl(var(--muted-foreground))',
                  border: isCurrent ? '1px solid #f97316' : isPassed ? '1px solid hsl(var(--primary) / 0.4)' : '1px solid transparent',
                  transition: 'all 0.3s ease'
                }}
              >
                {s.label}
              </div>
            );
          })}
        </div>

        {/* Main Simulation Viewport */}
        <div style={{ minHeight: '380px' }}>
          {currentStep === 'IDLE' && (
            <div style={{ padding: '20px 10px' }}>
              <div style={{ textAlign: 'center', marginBottom: 24 }}>
                <ShieldAlert size={60} style={{ color: 'hsl(var(--primary))', marginBottom: 12 }} />
                <h3 style={{ fontSize: 24, fontWeight: 900, marginBottom: 8 }}>Select Attack Vector to Test</h3>
                <p style={{ color: 'hsl(var(--muted-foreground))', maxWidth: 680, margin: '0 auto', lineHeight: 1.6, fontSize: 13 }}>
                  Choose an attack scenario vector to launch in the controlled presentation sandbox. ARGUS will track entry, detect exposure window data leaks, request user consent for Cyber Cell reporting, reconstruct the attack graph, apply adaptive kernel hardening, and recover all data.
                </p>
              </div>

              {/* Vector Selector Cards */}
              <div className="grid" style={{ gridTemplateColumns: 'repeat(3, 1fr)', gap: 16, marginBottom: 28 }}>
                {[
                  { id: 'EMAIL_PHISHING' as AttackVectorType, title: 'Phishing Attachment Cradle', sub: 'Powershell Encoded Payload', badge: 'HIGH RISK' },
                  { id: 'BROWSER_ZERO_DAY' as AttackVectorType, title: 'Browser Zero-Day Drive-by', sub: 'Memory Heap Spray Execution', badge: 'CRITICAL RISK' },
                  { id: 'USB_AUTORUN' as AttackVectorType, title: 'USB AutoRun Stager', sub: 'LNK Abuse & Persistence', badge: 'MEDIUM RISK' }
                ].map((vec) => (
                  <div
                    key={vec.id}
                    onClick={() => setSelectedVector(vec.id)}
                    style={{
                      background: selectedVector === vec.id ? 'hsl(var(--primary) / 0.12)' : 'hsl(224 50% 5%)',
                      border: selectedVector === vec.id ? '2px solid hsl(var(--primary))' : '1px solid hsl(224 40% 12%)',
                      borderRadius: 8,
                      padding: 16,
                      cursor: 'pointer',
                      transition: 'all 0.2s ease'
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                      <Radio size={18} style={{ color: selectedVector === vec.id ? 'hsl(var(--primary))' : 'hsl(var(--muted-foreground))' }} />
                      <span className="badge badge-critical" style={{ fontSize: 10 }}>{vec.badge}</span>
                    </div>
                    <div style={{ fontWeight: 800, fontSize: 14 }}>{vec.title}</div>
                    <div style={{ fontSize: 11, color: 'hsl(var(--muted-foreground))', marginTop: 4 }}>{vec.sub}</div>
                  </div>
                ))}
              </div>

              <div style={{ textAlign: 'center' }}>
                <button className="btn btn-primary" onClick={startSimulation} style={{ padding: '14px 36px', fontSize: 16, fontWeight: 900, gap: 10, background: 'linear-gradient(135deg, #eab308 0%, #f97316 100%)', color: '#000', border: 'none', borderRadius: 8, boxShadow: '0 0 24px rgba(234, 179, 8, 0.4)' }}>
                  <Play size={20} /> Launch Selected Attack Vector Simulation
                </button>
              </div>
            </div>
          )}

          {/* STEP 1: MALWARE ENTRY */}
          {currentStep === 'ENTRY' && (
            <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} style={{ padding: 4 }}>
              <div style={{ background: 'hsl(var(--destructive) / 0.15)', border: '1px solid hsl(var(--destructive) / 0.4)', borderRadius: 8, padding: 16, marginBottom: 16 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10, color: 'hsl(var(--destructive))', fontWeight: 800 }}>
                    <AlertTriangle size={22} />
                    <span style={{ fontSize: 15 }}>STEP 1: HOST INTRUSION & MALWARE PAYLOAD ENTRY</span>
                  </div>
                  <span className="badge badge-critical" style={{ fontSize: 11 }}>STATUS: ACTIVE INFILTRATION</span>
                </div>
                <p style={{ margin: '8px 0 0', fontSize: 13, color: 'hsl(var(--foreground))' }}>
                  Simulated malware payload <code style={{ background: 'rgba(0,0,0,0.5)', padding: '2px 8px', borderRadius: 4, color: '#f87171' }}>{activeVector.process}</code> executed via <strong style={{ color: 'hsl(var(--primary))' }}>{activeVector.title}</strong>.
                </p>
              </div>

              <div className="grid split-grid" style={{ gap: 16 }}>
                <div style={{ background: 'hsl(224 50% 5%)', border: '1px solid hsl(224 40% 12%)', padding: 16, borderRadius: 8, fontSize: 12 }}>
                  <div style={{ fontWeight: 800, color: 'hsl(var(--primary))', marginBottom: 10, display: 'flex', alignItems: 'center', gap: 8 }}>
                    <Cpu size={16} /> PROCESS TELEMETRY METRICS
                  </div>
                  <div style={{ lineHeight: 2, fontFamily: 'var(--app-font-mono)' }}>
                    <div>Process Name: <strong style={{ color: '#f87171' }}>{activeVector.process}</strong></div>
                    <div>Process ID (PID): <strong>{activeVector.pid}</strong></div>
                    <div>Parent Process: <strong>{activeVector.parent}</strong></div>
                    <div>Executable Path: <strong>{activeVector.path}</strong></div>
                    <div>Target C2 Address: <strong style={{ color: '#f87171' }}>{activeVector.c2} ({activeVector.c2Loc})</strong></div>
                    <div>Behavior: <span className="badge badge-critical">Memory Staging & Directory Scan</span></div>
                  </div>
                </div>

                <div style={{ background: 'hsl(224 50% 5%)', border: '1px solid hsl(224 40% 12%)', padding: 16, borderRadius: 8, display: 'flex', flexDirection: 'column', justifyContent: 'center', alignItems: 'center', textAlign: 'center' }}>
                  <RefreshCw className="animate-spin" size={36} style={{ color: 'hsl(var(--destructive))', marginBottom: 12 }} />
                  <div style={{ fontWeight: 800, fontSize: 15 }}>Monitoring Exposure Window...</div>
                  <div style={{ fontSize: 12, color: 'hsl(var(--muted-foreground))', marginTop: 6 }}>
                    Tracking interval between initial detection and deletion/quarantine
                  </div>
                </div>
              </div>
            </motion.div>
          )}

          {/* STEP 2: EXPOSURE WINDOW & SENSITIVE DATA LEAK ANALYSIS */}
          {currentStep === 'LEAK_DETECT' && (
            <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} style={{ padding: 4 }}>
              <div style={{ background: 'hsl(38 90% 12% / 0.6)', border: '1px solid hsl(38 90% 30%)', borderRadius: 8, padding: 16, marginBottom: 16 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10, color: 'hsl(38 92% 50%)', fontWeight: 800 }}>
                    <Eye size={22} />
                    <span style={{ fontSize: 15 }}>STEP 2: EXPOSURE WINDOW & SENSITIVE DATA LEAK CLASSIFICATION</span>
                  </div>
                  <span className="badge badge-high" style={{ padding: '6px 12px', fontSize: 12 }}>Detection Interval: 1.48s</span>
                </div>
                <p style={{ margin: '8px 0 0', fontSize: 13, color: 'hsl(var(--foreground))' }}>
                  ARGUS monitored data access during the 1.48s window. 3 sensitive files were accessed/staged for exfiltration, including personal intimate media. Click any file to inspect privacy EXIF metadata.
                </p>
              </div>

              <div style={{ background: 'hsl(224 50% 5%)', border: '1px solid hsl(224 40% 12%)', borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, marginBottom: 12, color: 'hsl(var(--muted-foreground))', display: 'flex', justifyContent: 'space-between' }}>
                  <span>SENSITIVE DATA STAGING & LEAK ANALYSIS LEDGER</span>
                  <span className="mono" style={{ color: 'hsl(var(--destructive))' }}>3 TARGETS ACCESSED</span>
                </div>

                {stagedDataFiles.map((f, i) => (
                  <div
                    key={i}
                    onClick={() => setSelectedInspectFile(f)}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      padding: '12px 14px',
                      background: 'hsl(var(--card))',
                      borderRadius: 6,
                      marginBottom: 8,
                      border: selectedInspectFile?.name === f.name ? '2px solid hsl(var(--primary))' : '1px solid hsl(var(--border))',
                      cursor: 'pointer'
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
                      <div style={{ background: 'hsl(var(--primary) / 0.15)', padding: 10, borderRadius: 6, color: 'hsl(var(--primary))' }}>
                        <f.icon size={20} />
                      </div>
                      <div>
                        <div style={{ fontWeight: 800, fontSize: 14 }}>{f.name}</div>
                        <div className="mono muted" style={{ fontSize: 11, marginTop: 2 }}>{f.path} · {f.size}</div>
                      </div>
                    </div>
                    <div style={{ textAlign: 'right' }}>
                      <span className="badge badge-critical" style={{ fontSize: 11, padding: '4px 10px' }}>{f.sensitivity}</span>
                      <div className="mono muted" style={{ fontSize: 10, marginTop: 4 }}>Click to Inspect EXIF</div>
                    </div>
                  </div>
                ))}

                {/* Inspect File Privacy Details Card */}
                {selectedInspectFile && (
                  <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} style={{ marginTop: 12, background: 'hsl(224 60% 4%)', padding: 14, borderRadius: 6, border: '1px solid hsl(var(--primary) / 0.4)', fontSize: 12, fontFamily: 'var(--app-font-mono)' }}>
                    <div style={{ fontWeight: 800, color: 'hsl(var(--primary))', marginBottom: 6 }}>PRIVACY METADATA INSPECTOR: {selectedInspectFile.name}</div>
                    <div>Classification: <strong>{selectedInspectFile.type}</strong></div>
                    <div>EXIF / Privacy Signature: <strong style={{ color: '#f87171' }}>{selectedInspectFile.exif}</strong></div>
                    <div>Entropy Score: <strong>{selectedInspectFile.entropy}</strong></div>
                  </motion.div>
                )}
              </div>
            </motion.div>
          )}

          {/* STEP 3: CYBER CELL CONSENT & OFFICIAL INCIDENT REPORT */}
          {currentStep === 'CYBER_CELL_CONSENT' && (
            <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} style={{ padding: 4 }}>
              <div style={{ background: 'hsl(var(--primary) / 0.1)', border: '2px solid hsl(var(--primary))', borderRadius: 12, padding: 20 }}>
                <div style={{ textAlign: 'center', marginBottom: 16 }}>
                  <ShieldAlert size={48} style={{ color: 'hsl(var(--primary))', marginBottom: 10 }} />
                  <h3 style={{ fontSize: 20, fontWeight: 900, margin: '0 0 6px' }}>
                    STEP 3: AUTOMATED CYBER CELL INCIDENT REPORT PERMISSION
                  </h3>
                  <p style={{ fontSize: 13, color: 'hsl(var(--foreground))', maxWidth: 700, margin: '0 auto', lineHeight: 1.6 }}>
                    ARGUS detected an attempted leak involving <strong>personal intimate media and security credentials</strong>. 
                    Do you grant permission to auto-compile and submit an official incident report to the <strong>National Cyber Crime Reporting Portal (Cyber Cell API)</strong>?
                  </p>
                </div>

                {/* Hyper-realistic Cyber Cell Dossier Preview */}
                <div style={{ background: 'hsl(224 60% 4%)', border: '1px solid hsl(224 40% 16%)', borderRadius: 8, padding: 16, marginBottom: 18, fontSize: 12, fontFamily: 'var(--app-font-mono)' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px dashed hsl(var(--border))', paddingBottom: 8, marginBottom: 10 }}>
                    <span style={{ fontWeight: 800, color: 'hsl(var(--primary))' }}>OFFICIAL CYBER CELL INCIDENT DOSSIER PREVIEW</span>
                    <span style={{ color: 'hsl(var(--muted-foreground))' }}>ENDPOINT: https://api.cybercrime.gov.in/v2/incident/submit</span>
                  </div>
                  <div style={{ lineHeight: 1.8 }}>
                    <div>Subject: <strong>Exfiltration Attempt of Sensitive Personal Media & Credentials</strong></div>
                    <div>Origin Host: <strong>WS-0427 (IP: 10.14.8.27 · OS: Windows 11 Pro)</strong></div>
                    <div>Destination C2: <strong style={{ color: '#f87171' }}>{activeVector.c2} ({activeVector.c2Loc})</strong></div>
                    <div>HTTP Auth Header: <strong>Bearer CYBER_CELL_GOVT_API_KEY_2026</strong></div>
                    <div>Evidence Attached: <strong>3 SHA-256 Hashes + Process Ancestry JSON Payload</strong></div>
                  </div>
                </div>

                {userPermissionGranted === null ? (
                  <div style={{ display: 'flex', gap: 16, justifyContent: 'center' }}>
                    <button className="btn btn-ghost" onClick={() => handleGrantConsent(false)} style={{ padding: '12px 24px', fontSize: 14 }}>
                      <X size={16} /> Deny Permission
                    </button>
                    <button className="btn btn-primary" onClick={() => handleGrantConsent(true)} style={{ padding: '12px 28px', fontSize: 14, fontWeight: 800, gap: 8, background: 'linear-gradient(135deg, #eab308, #f97316)', color: '#000', border: 'none' }}>
                      <Send size={16} /> Approve & Auto-Submit to Cyber Cell
                    </button>
                  </div>
                ) : (
                  <div style={{ padding: 14, background: 'hsl(142 71% 10%)', borderRadius: 8, border: '1px solid hsl(142 71% 30%)', color: 'hsl(142 71% 70%)', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 10 }}>
                    <CheckCircle2 size={22} />
                    <span style={{ fontWeight: 800, fontSize: 15 }}>
                      {userPermissionGranted ? `Permission Granted — Report Dispatched (#${reportReference})` : 'Permission Denied by User'}
                    </span>
                  </div>
                )}
              </div>
            </motion.div>
          )}

          {/* STEP 4: ROOT CAUSE DIAGNOSIS & ATTACK GRAPH */}
          {currentStep === 'ROOT_CAUSE' && (
            <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} style={{ padding: 4 }}>
              <div style={{ background: 'hsl(217 91% 12% / 0.6)', border: '1px solid hsl(217 91% 35%)', borderRadius: 8, padding: 16, marginBottom: 16 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, color: 'hsl(217 91% 70%)', fontWeight: 800 }}>
                  <Cpu size={22} />
                  <span style={{ fontSize: 15 }}>STEP 4: ROOT CAUSE DIAGNOSIS & ATTACK PATTERN CORRELATION</span>
                </div>
                <p style={{ margin: '8px 0 0', fontSize: 13, color: 'hsl(var(--foreground))' }}>
                  ARGUS AI correlated host process ancestry, staging directories, and outbound TLS sockets to map the entry vector.
                </p>
              </div>

              {/* Interactive Visual Graph Flow */}
              <div style={{ background: 'hsl(224 50% 5%)', border: '1px solid hsl(224 40% 12%)', borderRadius: 8, padding: 24, display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12 }}>
                {[
                  { title: activeVector.parent, sub: activeVector.title, icon: FileText, color: 'hsl(var(--muted-foreground))' },
                  { title: activeVector.process, sub: `PID ${activeVector.pid}`, icon: Terminal, color: 'hsl(var(--destructive))' },
                  { title: 'Data Staging Vault', sub: 'Temp Vault', icon: Lock, color: 'hsl(38 92% 50%)' },
                  { title: 'C2 Socket Node', sub: activeVector.c2, icon: Send, color: 'hsl(var(--primary))' }
                ].map((node, i, arr) => (
                  <React.Fragment key={i}>
                    <div style={{ background: 'hsl(var(--card))', border: `1px solid ${node.color}`, borderRadius: 8, padding: '16px 20px', textAlign: 'center', minWidth: 150 }}>
                      <node.icon size={26} style={{ color: node.color, marginBottom: 8 }} />
                      <div style={{ fontSize: 13, fontWeight: 800 }}>{node.title}</div>
                      <div style={{ fontSize: 11, color: 'hsl(var(--muted-foreground))', marginTop: 2 }}>{node.sub}</div>
                    </div>
                    {i < arr.length - 1 && <ArrowRight size={22} style={{ color: 'hsl(var(--muted-foreground))' }} />}
                  </React.Fragment>
                ))}
              </div>
            </motion.div>
          )}

          {/* STEP 5: ADAPTIVE BLOCKING & REPEAT ATTACK PREVENTION */}
          {currentStep === 'ADAPTIVE_BLOCK' && (
            <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} style={{ padding: 4 }}>
              <div style={{ background: 'hsl(142 71% 10%)', border: '1px solid hsl(142 71% 30%)', borderRadius: 8, padding: 16, marginBottom: 16 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, color: 'hsl(142 71% 70%)', fontWeight: 800 }}>
                  <ShieldCheck size={22} />
                  <span style={{ fontSize: 15 }}>STEP 5: ADAPTIVE DEFENSE HARDENING & ATTACKER REPEAT BLOCK</span>
                </div>
                <p style={{ margin: '8px 0 0', fontSize: 13, color: 'hsl(var(--foreground))' }}>
                  ARGUS dynamically injected firewall and kernel execution policies so identical repeat attacks are blocked instantly. Try typing a test command below to test live enforcement!
                </p>
              </div>

              <div className="grid split-grid" style={{ gap: 16, marginBottom: 14 }}>
                <div style={{ background: 'hsl(224 50% 5%)', border: '1px solid hsl(224 40% 12%)', padding: 16, borderRadius: 8 }}>
                  <div style={{ fontWeight: 800, fontSize: 13, marginBottom: 10, color: 'hsl(var(--primary))' }}>
                    HARDENING POLICIES GENERATED
                  </div>
                  <div style={{ fontSize: 11, fontFamily: 'var(--app-font-mono)', lineHeight: 2 }}>
                    <div>1. Firewall Rule: <code style={{ background: 'rgba(0,0,0,0.4)', padding: '2px 6px' }}>netsh advfirewall drop remoteip={activeVector.c2.split(':')[0]}</code></div>
                    <div>2. AppLocker Rule: <code style={{ background: 'rgba(0,0,0,0.4)', padding: '2px 6px' }}>Deny Executable {activeVector.process}</code></div>
                    <div>3. Hash Restrict: <code style={{ background: 'rgba(0,0,0,0.4)', padding: '2px 6px' }}>Block PID {activeVector.pid} Hash System-wide</code></div>
                  </div>
                </div>

                <div style={{ background: 'hsl(142 71% 6% / 0.8)', border: '1px dashed hsl(142 71% 30%)', padding: 16, borderRadius: 8, display: 'flex', flexDirection: 'column', justifyContent: 'center', alignItems: 'center', textAlign: 'center' }}>
                  <CheckCircle2 size={36} style={{ color: 'hsl(142 71% 50%)', marginBottom: 10 }} />
                  <div style={{ fontWeight: 900, fontSize: 16, color: 'hsl(142 71% 70%)' }}>
                    {repeatAttackTestResult ? `REPEAT ATTACK TEST: ${repeatAttackTestResult}` : 'REPEAT ATTACK VERIFICATION'}
                  </div>
                  <button className="btn btn-outline" onClick={runRepeatAttackTest} style={{ marginTop: 12, fontSize: 12, fontWeight: 700, gap: 6 }}>
                    <Play size={14} /> 🧪 Test Repeat Attack Simulation
                  </button>
                </div>
              </div>

              {/* Interactive Console Tester for Judges */}
              <div style={{ background: 'hsl(224 60% 4%)', border: '1px solid hsl(224 40% 16%)', padding: 12, borderRadius: 8 }}>
                <div style={{ fontSize: 11, fontWeight: 800, color: 'hsl(var(--primary))', marginBottom: 8, display: 'flex', alignItems: 'center', gap: 6 }}>
                  <Terminal size={14} /> LIVE HARDENING CONSOLE TESTER (TYPE TEST COMMAND BELOW)
                </div>
                <form onSubmit={handleRunCustomCmd} style={{ display: 'flex', gap: 8, marginBottom: 8 }}>
                  <input
                    type="text"
                    value={customTestCmd}
                    onChange={(e) => setCustomTestCmd(e.target.value)}
                    placeholder={`e.g. start ${activeVector.process} or curl ${activeVector.c2}`}
                    style={{ flex: 1, background: 'rgba(0,0,0,0.6)', border: '1px solid hsl(var(--border))', borderRadius: 4, padding: '6px 10px', color: '#fff', fontSize: 12, fontFamily: 'var(--app-font-mono)' }}
                  />
                  <button className="btn btn-sm btn-primary" type="submit" style={{ fontSize: 11, fontWeight: 800 }}>Test Block</button>
                </form>
                {customCmdLogs.length > 0 && (
                  <div style={{ background: '#000', padding: 8, borderRadius: 4, maxHeight: 80, overflowY: 'auto', fontSize: 11, fontFamily: 'var(--app-font-mono)', color: '#f87171' }}>
                    {customCmdLogs.map((l, idx) => <div key={idx}>{l}</div>)}
                  </div>
                )}
              </div>
            </motion.div>
          )}

          {/* STEP 6: DATA RECOVERY ENGINE DEMONSTRATION */}
          {currentStep === 'RECOVERY' && (
            <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} style={{ padding: 4 }}>
              <div style={{ background: 'hsl(var(--primary) / 0.15)', border: '1px solid hsl(var(--primary) / 0.4)', borderRadius: 8, padding: 16, marginBottom: 16 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, color: 'hsl(var(--primary))', fontWeight: 800 }}>
                  <HardDriveDownload size={22} />
                  <span style={{ fontSize: 15 }}>STEP 6: DATA RECOVERY ENGINE DEMONSTRATION</span>
                </div>
                <p style={{ margin: '8px 0 0', fontSize: 13, color: 'hsl(var(--foreground))' }}>
                  Restoring compromised & staged files from ARGUS isolated shadow snapshot back to original host locations.
                </p>
              </div>

              <div style={{ background: 'hsl(224 50% 5%)', border: '1px solid hsl(224 40% 12%)', padding: 14, borderRadius: 8 }}>
                <div style={{ fontSize: 12, fontWeight: 800, marginBottom: 10, color: 'hsl(var(--muted-foreground))' }}>
                  SHA-256 HASH INTEGRITY RESTORATION VERIFICATION
                </div>
                {stagedDataFiles.map((f, i) => (
                  <div key={i} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '12px 14px', background: 'hsl(var(--card))', borderRadius: 6, marginBottom: 8, border: '1px solid hsl(var(--border))' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                      <FileCheck size={20} style={{ color: 'hsl(142 71% 50%)' }} />
                      <div>
                        <div style={{ fontSize: 13, fontWeight: 800 }}>{f.name}</div>
                        <div className="mono muted" style={{ fontSize: 10 }}>Pre-attack SHA: {f.preHash.slice(0, 16)}... | Recovered SHA: {f.postHash.slice(0, 16)}...</div>
                      </div>
                    </div>
                    <span className="badge badge-low" style={{ background: 'hsl(142 71% 15%)', color: 'hsl(142 71% 70%)', fontSize: 11, padding: '4px 10px' }}>
                      100% MATCH · RESTORED
                    </span>
                  </div>
                ))}
              </div>
            </motion.div>
          )}

          {/* FINISHED STATE */}
          {currentStep === 'FINISHED' && (
            <motion.div initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} style={{ padding: 24, textAlign: 'center' }}>
              <div style={{ width: 72, height: 72, borderRadius: '50%', background: 'hsl(142 71% 15%)', color: 'hsl(142 71% 60%)', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 16px', border: '2px solid hsl(142 71% 40%)' }}>
                <Check size={40} />
              </div>
              <h3 style={{ fontSize: 24, fontWeight: 900, margin: '0 0 8px' }}>Simulation Complete</h3>
              <p style={{ color: 'hsl(var(--muted-foreground))', maxWidth: 640, margin: '0 auto 24px', fontSize: 14, lineHeight: 1.6 }}>
                All 6 presentation phases successfully executed. Threat contained, exposure window measured, Cyber Cell notified with user consent, adaptive blocking rules enforced, and data 100% recovered.
              </p>

              <div style={{ display: 'flex', gap: 14, justifyContent: 'center' }}>
                <button className="btn btn-outline" onClick={startSimulation} style={{ gap: 8, padding: '10px 20px' }}>
                  <RefreshCw size={14} /> Re-run Simulation
                </button>
                {onNavigate && (
                  <button className="btn btn-primary" onClick={() => { onClose(); onNavigate('/cyber-cell'); }} style={{ gap: 8, padding: '10px 22px', background: 'linear-gradient(135deg, #eab308, #f97316)', color: '#000', fontWeight: 800 }}>
                    View Cyber Cell Portal <ArrowRight size={14} />
                  </button>
                )}
              </div>
            </motion.div>
          )}
        </div>

        {/* Live Terminal Output Drawer */}
        {currentStep !== 'IDLE' && (
          <div style={{ marginTop: 20, background: '#090d16', border: '1px solid #1e293b', borderRadius: 8, padding: 12, fontFamily: 'var(--app-font-mono)', fontSize: 11 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', color: '#94a3b8', borderBottom: '1px solid #1e293b', paddingBottom: 6, marginBottom: 8, fontWeight: 700 }}>
              <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <Terminal size={14} style={{ color: '#eab308' }} /> LIVE ARGUS EXECUTION TERMINAL LOG STREAM
              </span>
              <span>PARSER: ENGINE_ACTIVE</span>
            </div>
            <div style={{ maxHeight: '110px', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 4, color: '#38bdf8' }}>
              {terminalLogs.map((log, i) => (
                <div key={i} style={{ color: log.includes('CLASSIFIER') || log.includes('CORE') ? '#f87171' : log.includes('CYBER CELL') || log.includes('HARDENING') || log.includes('RESTORATION') ? '#4ade80' : '#38bdf8' }}>
                  {log}
                </div>
              ))}
              <div ref={terminalEndRef} />
            </div>
          </div>
        )}

        {/* Footer */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderTop: '1px solid hsl(var(--border))', paddingTop: 14, marginTop: 20 }}>
          <div style={{ fontSize: 12, color: 'hsl(var(--muted-foreground))' }}>
            Mode: <strong>JUDGE_PRESENTATION_DRILL_ULTIMATE</strong>
          </div>
          <div style={{ display: 'flex', gap: 10 }}>
            {currentStep !== 'IDLE' && currentStep !== 'FINISHED' && (
              <button className="btn btn-ghost" onClick={() => setIsAutoRunning(!isAutoRunning)} style={{ gap: 6 }}>
                {isAutoRunning ? 'Pause Simulation' : 'Resume Simulation'}
              </button>
            )}
            <button className="btn btn-secondary" onClick={onClose}>
              Close Presentation
            </button>
          </div>
        </div>
      </motion.div>
    </div>
  );
};
