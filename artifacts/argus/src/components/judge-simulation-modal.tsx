import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  ShieldAlert, ShieldCheck, FileWarning, Send, Cpu, Lock,
  RefreshCw, CheckCircle2, AlertTriangle, ArrowRight, Play,
  Check, X, FileText, Image, Database, Eye, Terminal, Zap, HardDriveDownload,
  Activity, Globe, Server, AlertCircle, FileCheck, Layers, BadgeAlert, CheckSquare
} from 'lucide-react';

export type JudgeSimStep = 'IDLE' | 'ENTRY' | 'LEAK_DETECT' | 'CYBER_CELL_CONSENT' | 'ROOT_CAUSE' | 'ADAPTIVE_BLOCK' | 'RECOVERY' | 'FINISHED';

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
  const [isAutoRunning, setIsAutoRunning] = useState(false);
  const [userPermissionGranted, setUserPermissionGranted] = useState<boolean | null>(null);
  const [reportReference, setReportReference] = useState<string | null>(null);
  const [terminalLogs, setTerminalLogs] = useState<string[]>([]);
  const [repeatAttackTestResult, setRepeatAttackTestResult] = useState<string | null>(null);
  const terminalEndRef = useRef<HTMLDivElement>(null);

  // Staged files metadata for hyper-realistic simulation
  const stagedDataFiles = [
    {
      name: 'family_photos_vault.zip',
      path: 'C:\\Users\\mira\\Pictures\\Personal\\family_photos_vault.zip',
      size: '14.2 MB',
      type: 'Intimate / Personal Media',
      sensitivity: 'CRITICAL (Intimate / PII)',
      entropy: '7.89 (Encrypted Archive)',
      icon: Image,
      preHash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      postHash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    },
    {
      name: 'Q4_financial_strategy.pdf',
      path: 'C:\\Users\\mira\\Documents\\Corporate\\Q4_financial_strategy.pdf',
      size: '3.8 MB',
      type: 'Confidential Strategy Document',
      sensitivity: 'HIGH (Financial / Proprietary)',
      entropy: '5.42 (PDF Stream)',
      icon: FileText,
      preHash: 'f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2',
      postHash: 'f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2'
    },
    {
      name: 'master_passwords.kdbx',
      path: 'C:\\Users\\mira\\Documents\\Vault\\master_passwords.kdbx',
      size: '820 KB',
      type: 'Credential & Key Vault',
      sensitivity: 'CRITICAL (Security Keys)',
      entropy: '7.95 (KeePass Database)',
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
    }
  }, [isOpen]);

  useEffect(() => {
    terminalEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [terminalLogs]);

  const appendLog = (logLine: string) => {
    setTerminalLogs(prev => [...prev, `[${new Date().toLocaleTimeString()}.${Math.floor(Math.random()*900+100)}] ${logLine}`]);
  };

  // Step auto-progression loop with rich log stream
  useEffect(() => {
    let timer: NodeJS.Timeout;
    if (isAutoRunning) {
      if (currentStep === 'ENTRY') {
        appendLog('SECURITY ENGINE: Subprocess invocation detected (PID 9482: trojan_stealer_v2.exe).');
        appendLog('ANCESTRY: explorer.exe (4100) -> outlook.exe (6230) -> trojan_stealer_v2.exe (9482).');
        appendLog('VECTOR: Malicious email attachment execution in temp directory.');
        timer = setTimeout(() => {
          setCurrentStep('LEAK_DETECT');
        }, 3000);
      } else if (currentStep === 'LEAK_DETECT') {
        appendLog('DETECTION WINDOW: Monitoring file access & staging operations during exposure window.');
        appendLog('SENSITIVITY SCAN: Classified family_photos_vault.zip -> Personal / Intimate Media (PII).');
        appendLog('SENSITIVITY SCAN: Classified Q4_financial_strategy.pdf -> Confidential Corporate Strategy.');
        appendLog('NETWORK MONITOR: Outbound TLS session established to C2 node 185.199.110.27:443.');
        timer = setTimeout(() => {
          setCurrentStep('CYBER_CELL_CONSENT');
        }, 3500);
      } else if (currentStep === 'CYBER_CELL_CONSENT' && userPermissionGranted !== null) {
        timer = setTimeout(() => {
          setCurrentStep('ROOT_CAUSE');
        }, 3000);
      } else if (currentStep === 'ROOT_CAUSE') {
        appendLog('AI CORRELATION ENGINE: Reconstructing full process ancestry & network graph.');
        appendLog('ATTACK VECTOR MATCH: Phishing Cradle -> Encoded PowerShell Stager -> C2 Exfiltration.');
        timer = setTimeout(() => {
          setCurrentStep('ADAPTIVE_BLOCK');
        }, 3500);
      } else if (currentStep === 'ADAPTIVE_BLOCK') {
        appendLog('HARDENING: Injecting Windows Firewall outbound block rule for C2 IP 185.199.110.27.');
        appendLog('KERNEL POLICY: Adding AppLocker execution restriction for AppData\\Local\\Temp\\*.exe.');
        appendLog('ADAPTIVE ENGINE: Perimeter policy locked. Zero-ms repeat attack defense armed.');
        timer = setTimeout(() => {
          setCurrentStep('RECOVERY');
        }, 3500);
      } else if (currentStep === 'RECOVERY') {
        appendLog('RECOVERY VAULT: Accessing shadow snapshot volume (vss_snap_048).');
        appendLog('DATA RESTORATION: Restoring family_photos_vault.zip (SHA-256 Verified 100%).');
        appendLog('DATA RESTORATION: Restoring Q4_financial_strategy.pdf (SHA-256 Verified 100%).');
        appendLog('DATA RESTORATION: Restoring master_passwords.kdbx (SHA-256 Verified 100%).');
        timer = setTimeout(() => {
          setCurrentStep('FINISHED');
          setIsAutoRunning(false);
        }, 3000);
      }
    }
    return () => clearTimeout(timer);
  }, [currentStep, isAutoRunning, userPermissionGranted]);

  if (!isOpen) return null;

  const startSimulation = () => {
    setCurrentStep('ENTRY');
    setIsAutoRunning(true);
    setUserPermissionGranted(null);
    setReportReference(null);
    setTerminalLogs(['[SYSTEM] Initializing ARGUS Live Judge Simulation Suite...']);
    setRepeatAttackTestResult(null);
    toast('Judge Simulation Initialized', 'Launching end-to-end malware entry and defense cycle.');
  };

  const handleGrantConsent = (granted: boolean) => {
    setUserPermissionGranted(granted);
    if (granted) {
      const ref = `CC-ND-2026-${Math.floor(100000 + Math.random() * 900000)}-X`;
      setReportReference(ref);
      appendLog(`CYBER CELL DISPATCH: Official Incident Dossier #${ref} generated & transmitted.`);
      toast('Cyber Cell Portal Notified', `Official incident package ${ref} submitted via secure API.`);
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
      appendLog('[TEST ATTEMPT] Relaunching trojan_stealer_v2.exe -> KERNEL BLOCK (Rule AR-BLOCK-9482 applied in 0.18ms)');
      toast('Adaptive Hardening Verified', 'Attempted repeat execution blocked instantly at kernel perimeter!');
    }, 1000);
  };

  return (
    <div className="modal-backdrop" style={{ background: 'rgba(0, 0, 0, 0.88)', backdropFilter: 'blur(10px)', zIndex: 9999 }}>
      <motion.div
        initial={{ opacity: 0, scale: 0.96, y: 15 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        exit={{ opacity: 0, scale: 0.96 }}
        className="modal"
        style={{
          width: '94%',
          maxWidth: '1020px',
          background: 'hsl(224 71% 3%)',
          border: '1px solid hsl(var(--border))',
          boxShadow: '0 25px 50px -12px rgba(0,0,0,0.85)',
          padding: '24px',
          maxHeight: '92vh',
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
                ARGUS Security Intelligence · Presentation Mode
              </div>
              <h2 style={{ fontSize: 20, margin: 0, fontWeight: 900, color: 'hsl(var(--foreground))' }}>
                Live Malware Entry, Leak Detection & Self-Healing Data Recovery Simulation
              </h2>
            </div>
          </div>
          <button className="btn btn-ghost" onClick={onClose} style={{ padding: 6 }}>
            <X size={20} />
          </button>
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
            <div style={{ textAlign: 'center', padding: '50px 20px' }}>
              <ShieldAlert size={64} style={{ color: 'hsl(var(--primary))', marginBottom: 16 }} />
              <h3 style={{ fontSize: 24, fontWeight: 800, marginBottom: 10 }}>Judges Live Attack & Recovery Simulation Ready</h3>
              <p style={{ color: 'hsl(var(--muted-foreground))', maxWidth: 680, margin: '0 auto 28px', lineHeight: 1.6, fontSize: 14 }}>
                Launch the interactive simulation to demonstrate ARGUS in real-time to the judges. Show how malware entry is tracked, exposure window data leaks (including personal/intimate media) are detected, user permission is requested for automated Cyber Cell incident reporting, attack paths are visually analyzed, adaptive defense rules block repeat attacks, and data is 100% recovered.
              </p>
              <button className="btn btn-primary" onClick={startSimulation} style={{ padding: '14px 32px', fontSize: 16, fontWeight: 800, gap: 10, background: 'linear-gradient(135deg, #eab308 0%, #f97316 100%)', color: '#000', border: 'none', borderRadius: 8, boxShadow: '0 0 20px rgba(234, 179, 8, 0.4)' }}>
                <Play size={20} /> Launch Real-Time Simulation
              </button>
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
                  Simulated malware payload <code style={{ background: 'rgba(0,0,0,0.5)', padding: '2px 8px', borderRadius: 4, color: '#f87171' }}>trojan_stealer_v2.exe</code> executed via suspicious Outlook attachment cradle.
                </p>
              </div>

              <div className="grid split-grid" style={{ gap: 16 }}>
                <div style={{ background: 'hsl(224 50% 5%)', border: '1px solid hsl(224 40% 12%)', padding: 16, borderRadius: 8, fontSize: 12 }}>
                  <div style={{ fontWeight: 800, color: 'hsl(var(--primary))', marginBottom: 10, display: 'flex', alignItems: 'center', gap: 8 }}>
                    <Cpu size={16} /> PROCESS TELEMETRY METRICS
                  </div>
                  <div style={{ lineHeight: 2, fontFamily: 'var(--app-font-mono)' }}>
                    <div>Process Name: <strong style={{ color: '#f87171' }}>trojan_stealer_v2.exe</strong></div>
                    <div>Process ID (PID): <strong>9482</strong></div>
                    <div>Parent Process: <strong>outlook.exe (PID 6230)</strong></div>
                    <div>Path: <strong>C:\Users\mira\AppData\Local\Temp\trojan_stealer_v2.exe</strong></div>
                    <div>SHA-256 Hash: <strong style={{ color: 'hsl(var(--muted-foreground))' }}>a7f1c82e9d04b6f1e3aa92c4...</strong></div>
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
                  ARGUS monitored data access during the 1.48s window. 3 sensitive files were accessed/staged for exfiltration, including personal intimate media.
                </p>
              </div>

              <div style={{ background: 'hsl(224 50% 5%)', border: '1px solid hsl(224 40% 12%)', borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, marginBottom: 12, color: 'hsl(var(--muted-foreground))', display: 'flex', justifyContent: 'space-between' }}>
                  <span>SENSITIVE DATA STAGING & LEAK ANALYSIS LEDGER</span>
                  <span className="mono" style={{ color: 'hsl(var(--destructive))' }}>3 TARGETS ACCESSED</span>
                </div>

                {stagedDataFiles.map((f, i) => (
                  <div key={i} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '12px 14px', background: 'hsl(var(--card))', borderRadius: 6, marginBottom: 8, border: '1px solid hsl(var(--border))' }}>
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
                      <div className="mono muted" style={{ fontSize: 10, marginTop: 4 }}>Entropy: {f.entropy}</div>
                    </div>
                  </div>
                ))}
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
                    <span style={{ color: 'hsl(var(--muted-foreground))' }}>FORMAT: JSON / FORENSIC PDF</span>
                  </div>
                  <div style={{ lineHeight: 1.8 }}>
                    <div>Subject: <strong>Exfiltration Attempt of Sensitive Personal Media & Credentials</strong></div>
                    <div>Origin Host: <strong>WS-0427 (IP: 10.14.8.27 · OS: Windows 11 Pro)</strong></div>
                    <div>Destination C2: <strong style={{ color: '#f87171' }}>185.199.110.27:443 (Frankfurt, DE)</strong></div>
                    <div>Evidence Hashes Attached: <strong>3 SHA-256 Hashes + Process Ancestry Tree</strong></div>
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
                  { title: 'Outlook Email Client', sub: 'Phishing Attachment', icon: FileText, color: 'hsl(var(--muted-foreground))' },
                  { title: 'stealer_v2.exe', sub: 'PID 9482 (Temp Dir)', icon: Terminal, color: 'hsl(var(--destructive))' },
                  { title: 'Data Staging', sub: 'Sensitive Vault', icon: Lock, color: 'hsl(38 92% 50%)' },
                  { title: 'C2 Socket', sub: '185.199.110.27:443', icon: Send, color: 'hsl(var(--primary))' }
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
                  ARGUS dynamically injected firewall and kernel execution policies so identical repeat attacks are blocked instantly.
                </p>
              </div>

              <div className="grid split-grid" style={{ gap: 16 }}>
                <div style={{ background: 'hsl(224 50% 5%)', border: '1px solid hsl(224 40% 12%)', padding: 16, borderRadius: 8 }}>
                  <div style={{ fontWeight: 800, fontSize: 13, marginBottom: 10, color: 'hsl(var(--primary))' }}>
                    HARDENING POLICIES GENERATED
                  </div>
                  <div style={{ fontSize: 11, fontFamily: 'var(--app-font-mono)', lineHeight: 2 }}>
                    <div>1. Firewall Rule: <code style={{ background: 'rgba(0,0,0,0.4)', padding: '2px 6px' }}>netsh advfirewall drop remoteip=185.199.110.27</code></div>
                    <div>2. AppLocker Rule: <code style={{ background: 'rgba(0,0,0,0.4)', padding: '2px 6px' }}>Deny Executable Temp\*.exe</code></div>
                    <div>3. Hash Restrict: <code style={{ background: 'rgba(0,0,0,0.4)', padding: '2px 6px' }}>Block a7f1c82e... System-wide</code></div>
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
                <div key={i} style={{ color: log.includes('SENSITIVITY') || log.includes('INTRUSION') ? '#f87171' : log.includes('CYBER CELL') || log.includes('HARDENING') ? '#4ade80' : '#38bdf8' }}>
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
            Mode: <strong>JUDGE_PRESENTATION_DRILL_REALISTIC</strong>
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
