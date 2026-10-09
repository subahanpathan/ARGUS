import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  ShieldAlert, ShieldCheck, FileWarning, Send, Cpu, Lock,
  RefreshCw, CheckCircle2, AlertTriangle, ArrowRight, Play,
  Check, X, FileText, Image, Database, Eye, Terminal, Zap, HardDriveDownload
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
  const [restoredFiles, setRestoredFiles] = useState<string[]>([]);

  // Simulation State Data
  const stagedDataFiles = [
    { name: 'family_photos_vault.zip', type: 'Intimate / Personal Media', sensitivity: 'CRITICAL (Intimate)', icon: Image, hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' },
    { name: 'Q4_financial_strategy.pdf', type: 'Confidential Document', sensitivity: 'HIGH (Financial)', icon: FileText, hash: 'f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2' },
    { name: 'master_passwords.kdbx', type: 'Credential Store', sensitivity: 'CRITICAL (Security)', icon: Database, hash: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08' }
  ];

  useEffect(() => {
    if (!isOpen) {
      setCurrentStep('IDLE');
      setIsAutoRunning(false);
      setUserPermissionGranted(null);
      setReportReference(null);
      setRestoredFiles([]);
    }
  }, [isOpen]);

  // Handle step auto-progression except when waiting for Cyber Cell consent
  useEffect(() => {
    let timer: NodeJS.Timeout;
    if (isAutoRunning) {
      if (currentStep === 'ENTRY') {
        timer = setTimeout(() => setCurrentStep('LEAK_DETECT'), 2500);
      } else if (currentStep === 'LEAK_DETECT') {
        timer = setTimeout(() => setCurrentStep('CYBER_CELL_CONSENT'), 3000);
      } else if (currentStep === 'CYBER_CELL_CONSENT' && userPermissionGranted !== null) {
        timer = setTimeout(() => setCurrentStep('ROOT_CAUSE'), 2500);
      } else if (currentStep === 'ROOT_CAUSE') {
        timer = setTimeout(() => setCurrentStep('ADAPTIVE_BLOCK'), 3000);
      } else if (currentStep === 'ADAPTIVE_BLOCK') {
        timer = setTimeout(() => {
          setRestoredFiles(stagedDataFiles.map(f => f.name));
          setCurrentStep('RECOVERY');
        }, 3000);
      } else if (currentStep === 'RECOVERY') {
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
    setRestoredFiles([]);
    toast('Judge Simulation Started', 'Simulating malware entry and exposure window analysis.');
  };

  const handleGrantConsent = (granted: boolean) => {
    setUserPermissionGranted(granted);
    if (granted) {
      const ref = `CC-2026-N${Math.floor(100000 + Math.random() * 900000)}`;
      setReportReference(ref);
      toast('Cyber Cell Incident Reported', `Official incident report ${ref} generated and dispatched.`);
    } else {
      toast('Reporting Skipped', 'User denied permission for Cyber Cell auto-submission.');
    }
    // Continue simulation after decision
    setTimeout(() => {
      setCurrentStep('ROOT_CAUSE');
    }, 1500);
  };

  return (
    <div className="modal-backdrop" style={{ background: 'rgba(0,0,0,0.85)', backdropFilter: 'blur(8px)', zIndex: 9999 }}>
      <motion.div
        initial={{ opacity: 0, scale: 0.95, y: 10 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        exit={{ opacity: 0, scale: 0.95 }}
        className="modal"
        style={{
          width: '90%',
          maxWidth: '900px',
          background: 'hsl(224 71% 4%)',
          border: '1px solid hsl(var(--border))',
          boxShadow: '0 25px 50px -12px rgba(0,0,0,0.7)',
          padding: '28px',
          maxHeight: '90vh',
          overflowY: 'auto'
        }}
      >
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid hsl(var(--border))', paddingBottom: 16, marginBottom: 20 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <div style={{ background: 'hsl(var(--primary) / 0.15)', padding: 10, borderRadius: 8, color: 'hsl(var(--primary))' }}>
              <Zap size={22} />
            </div>
            <div>
              <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: '1px', color: 'hsl(var(--primary))', textTransform: 'uppercase' }}>
                ARGUS Live Presentation Engine
              </div>
              <h2 style={{ fontSize: 20, margin: 0, fontWeight: 800 }}>End-to-End Attack, Leak & Recovery Simulation</h2>
            </div>
          </div>
          <button className="btn btn-ghost" onClick={onClose} style={{ padding: 6 }}>
            <X size={18} />
          </button>
        </div>

        {/* Stepper Header Bar */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6, 1fr)', gap: 6, marginBottom: 24, background: 'hsl(var(--muted) / 0.4)', padding: 8, borderRadius: 8 }}>
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
                  padding: '6px 4px',
                  borderRadius: 6,
                  fontSize: 11,
                  fontWeight: 700,
                  background: isCurrent ? 'hsl(var(--primary))' : isPassed ? 'hsl(var(--primary) / 0.2)' : 'transparent',
                  color: isCurrent ? '#000' : isPassed ? 'hsl(var(--primary))' : 'hsl(var(--muted-foreground))',
                  transition: 'all 0.3s ease'
                }}
              >
                {s.label}
              </div>
            );
          })}
        </div>

        {/* Content Body Based on Current Step */}
        <div style={{ minHeight: '340px' }}>
          {currentStep === 'IDLE' && (
            <div style={{ textAlign: 'center', padding: '40px 20px' }}>
              <ShieldAlert size={56} style={{ color: 'hsl(var(--primary))', marginBottom: 16 }} />
              <h3 style={{ fontSize: 22, fontWeight: 700, marginBottom: 8 }}>Judges Demonstration Mode Ready</h3>
              <p style={{ color: 'hsl(var(--muted-foreground))', maxWidth: 600, margin: '0 auto 24px', lineHeight: 1.6 }}>
                Click below to launch the live step-by-step malware entry simulation. This will demonstrate real-time leak window detection, sensitivity classification (including intimate/personal media), automated Cyber Cell report generation with user consent, root-cause pattern analysis, adaptive blocker creation, and 100% data recovery.
              </p>
              <button className="btn btn-primary" onClick={startSimulation} style={{ padding: '12px 28px', fontSize: 15, fontWeight: 700, gap: 8 }}>
                <Play size={18} /> Launch Live Judge Simulation
              </button>
            </div>
          )}

          {currentStep === 'ENTRY' && (
            <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} style={{ padding: 12 }}>
              <div style={{ background: 'hsl(var(--destructive) / 0.15)', border: '1px solid hsl(var(--destructive) / 0.4)', borderRadius: 8, padding: 16, marginBottom: 20 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, color: 'hsl(var(--destructive))', fontWeight: 800 }}>
                  <AlertTriangle size={20} />
                  <span>STEP 1: MALWARE ENTRY DETECTED</span>
                </div>
                <p style={{ margin: '8px 0 0', fontSize: 13, color: 'hsl(var(--foreground))' }}>
                  Simulated threat payload <code style={{ background: 'rgba(0,0,0,0.4)', padding: '2px 6px', borderRadius: 4 }}>trojan_stealer_payload.exe</code> spawned from email client attachment.
                </p>
              </div>

              <div className="grid split-grid" style={{ gap: 16 }}>
                <div style={{ background: 'hsl(var(--muted) / 0.3)', padding: 16, borderRadius: 8, fontFamily: 'var(--app-font-mono)', fontSize: 12 }}>
                  <div style={{ fontWeight: 700, color: 'hsl(var(--primary))', marginBottom: 8 }}>PROCESS METRICS</div>
                  <div>PID: <strong>9482</strong></div>
                  <div>Parent PID: <strong>4100 (outlook.exe)</strong></div>
                  <div>Executable Path: <strong>C:\Users\mira\AppData\Local\Temp\stealer_v2.exe</strong></div>
                  <div>Vector: <strong>Phishing Attachment Executable</strong></div>
                </div>

                <div style={{ background: 'hsl(var(--muted) / 0.3)', padding: 16, borderRadius: 8, display: 'flex', flexDirection: 'column', justifyContent: 'center', alignItems: 'center' }}>
                  <RefreshCw className="animate-spin" size={32} style={{ color: 'hsl(var(--destructive))', marginBottom: 12 }} />
                  <div style={{ fontWeight: 700, fontSize: 14 }}>Tracking Exposure Window...</div>
                  <div style={{ fontSize: 12, color: 'hsl(var(--muted-foreground))', marginTop: 4 }}>Monitoring file read & staging operations</div>
                </div>
              </div>
            </motion.div>
          )}

          {currentStep === 'LEAK_DETECT' && (
            <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} style={{ padding: 12 }}>
              <div style={{ background: 'hsl(38 90% 15% / 0.4)', border: '1px solid hsl(38 90% 30%)', borderRadius: 8, padding: 16, marginBottom: 20 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10, color: 'hsl(38 92% 50%)', fontWeight: 800 }}>
                    <Eye size={20} />
                    <span>STEP 2: EXPOSURE WINDOW & SENSITIVE DATA LEAK ANALYSIS</span>
                  </div>
                  <span className="badge badge-high">Interval: 1.48s</span>
                </div>
                <p style={{ margin: '8px 0 0', fontSize: 13, color: 'hsl(var(--foreground))' }}>
                  ARGUS identified 3 sensitive files accessed during the detection-to-containment window. Sensitive media & confidential data classification triggered.
                </p>
              </div>

              <div style={{ background: 'hsl(var(--muted) / 0.2)', borderRadius: 8, padding: 12 }}>
                <div style={{ fontSize: 12, fontWeight: 700, marginBottom: 10, color: 'hsl(var(--muted-foreground))' }}>
                  STAGED / LEAKED DATA CLASSIFICATION LEDGER
                </div>
                {stagedDataFiles.map((f, i) => (
                  <div key={i} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '10px 12px', background: 'hsl(var(--card))', borderRadius: 6, marginBottom: 8, border: '1px solid hsl(var(--border))' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                      <f.icon size={18} style={{ color: 'hsl(var(--primary))' }} />
                      <div>
                        <div style={{ fontWeight: 700, fontSize: 13 }}>{f.name}</div>
                        <div style={{ fontSize: 11, color: 'hsl(var(--muted-foreground))' }}>{f.type}</div>
                      </div>
                    </div>
                    <div style={{ textAlign: 'right' }}>
                      <span className="badge badge-critical" style={{ fontSize: 10 }}>{f.sensitivity}</span>
                      <div className="mono muted" style={{ fontSize: 10, marginTop: 2 }}>{f.hash.slice(0, 16)}...</div>
                    </div>
                  </div>
                ))}
              </div>
            </motion.div>
          )}

          {currentStep === 'CYBER_CELL_CONSENT' && (
            <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} style={{ padding: 12 }}>
              <div style={{ background: 'hsl(var(--primary) / 0.1)', border: '2px solid hsl(var(--primary))', borderRadius: 12, padding: 20, textAlign: 'center' }}>
                <ShieldAlert size={42} style={{ color: 'hsl(var(--primary))', marginBottom: 12 }} />
                <h3 style={{ fontSize: 18, fontWeight: 800, margin: '0 0 8px' }}>
                  STEP 3: AUTOMATED CYBER CELL INCIDENT REPORT PERMISSION
                </h3>
                <p style={{ fontSize: 13, color: 'hsl(var(--foreground))', maxWidth: 650, margin: '0 auto 16px', lineHeight: 1.6 }}>
                  ARGUS detected an attempted leak involving <strong>personal intimate media and security credentials</strong>. 
                  Do you authorize ARGUS to compile a forensic incident package (system info, file hashes, C2 IPs) and dispatch it directly to the official <strong>National Cyber Crime Reporting Portal (Cyber Cell API)</strong>?
                </p>

                {userPermissionGranted === null ? (
                  <div style={{ display: 'flex', gap: 16, justifyContent: 'center', marginTop: 20 }}>
                    <button className="btn btn-ghost" onClick={() => handleGrantConsent(false)} style={{ padding: '10px 20px' }}>
                      <X size={16} /> Deny Permission
                    </button>
                    <button className="btn btn-primary" onClick={() => handleGrantConsent(true)} style={{ padding: '10px 24px', fontWeight: 700, gap: 8 }}>
                      <Send size={16} /> Approve & Auto-Report to Cyber Cell
                    </button>
                  </div>
                ) : (
                  <div style={{ marginTop: 16, padding: 12, background: 'hsl(142 71% 10%)', borderRadius: 8, border: '1px solid hsl(142 71% 30%)', color: 'hsl(142 71% 70%)', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 10 }}>
                    <CheckCircle2 size={20} />
                    <span style={{ fontWeight: 700, fontSize: 14 }}>
                      {userPermissionGranted ? `Permission Granted — Report Dispatched (#${reportReference})` : 'Permission Denied by User'}
                    </span>
                  </div>
                )}
              </div>
            </motion.div>
          )}

          {currentStep === 'ROOT_CAUSE' && (
            <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} style={{ padding: 12 }}>
              <div style={{ background: 'hsl(217 91% 15% / 0.4)', border: '1px solid hsl(217 91% 35%)', borderRadius: 8, padding: 16, marginBottom: 20 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, color: 'hsl(217 91% 70%)', fontWeight: 800 }}>
                  <Cpu size={20} />
                  <span>STEP 4: ROOT CAUSE DIAGNOSIS & ATTACK GRAPH CORRELATION</span>
                </div>
                <p style={{ margin: '8px 0 0', fontSize: 13, color: 'hsl(var(--foreground))' }}>
                  ARGUS AI correlated process ancestry, network sockets, and file staging events to reconstruct the full attack graph.
                </p>
              </div>

              <div style={{ background: 'hsl(var(--muted) / 0.3)', borderRadius: 8, padding: 20, display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12 }}>
                {[
                  { title: 'Outlook Email', sub: 'Phishing Vector', icon: FileText, color: 'hsl(var(--muted-foreground))' },
                  { title: 'stealer_v2.exe', sub: 'PID 9482', icon: Terminal, color: 'hsl(var(--destructive))' },
                  { title: 'Data Staging', sub: 'Temp Vault', icon: Lock, color: 'hsl(38 92% 50%)' },
                  { title: 'C2 Socket', sub: '185.199.110.27', icon: Send, color: 'hsl(var(--primary))' }
                ].map((node, i, arr) => (
                  <React.Fragment key={i}>
                    <div style={{ background: 'hsl(var(--card))', border: `1px solid ${node.color}`, borderRadius: 8, padding: '12px 16px', textAlign: 'center', minWidth: 130 }}>
                      <node.icon size={22} style={{ color: node.color, marginBottom: 6 }} />
                      <div style={{ fontSize: 12, fontWeight: 700 }}>{node.title}</div>
                      <div style={{ fontSize: 10, color: 'hsl(var(--muted-foreground))' }}>{node.sub}</div>
                    </div>
                    {i < arr.length - 1 && <ArrowRight size={18} style={{ color: 'hsl(var(--muted-foreground))' }} />}
                  </React.Fragment>
                ))}
              </div>
            </motion.div>
          )}

          {currentStep === 'ADAPTIVE_BLOCK' && (
            <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} style={{ padding: 12 }}>
              <div style={{ background: 'hsl(142 71% 10%)', border: '1px solid hsl(142 71% 30%)', borderRadius: 8, padding: 16, marginBottom: 20 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, color: 'hsl(142 71% 70%)', fontWeight: 800 }}>
                  <ShieldCheck size={20} />
                  <span>STEP 5: ADAPTIVE DEFENSE HARDENING & ATTACKER REPEAT BLOCK</span>
                </div>
                <p style={{ margin: '8px 0 0', fontSize: 13, color: 'hsl(var(--foreground))' }}>
                  ARGUS dynamically generated adaptive rules to prevent this exact attack pattern from executing again on this device.
                </p>
              </div>

              <div className="grid split-grid" style={{ gap: 14 }}>
                <div style={{ background: 'hsl(var(--muted) / 0.3)', padding: 14, borderRadius: 8 }}>
                  <div style={{ fontWeight: 700, fontSize: 12, marginBottom: 8, color: 'hsl(var(--primary))' }}>ADAPTIVE POLICY RULES APPLIED</div>
                  <ul style={{ margin: 0, paddingLeft: 18, fontSize: 12, lineHeight: 1.8 }}>
                    <li>Blocked Binary Hash: <code className="mono">e3b0c442...991b7852</code></li>
                    <li>Firewall Drop: Destination <code className="mono">185.199.110.27:443</code></li>
                    <li>Directory Rule: Restrict executable spawn from <code className="mono">AppData\Local\Temp</code></li>
                  </ul>
                </div>
                <div style={{ background: 'hsl(142 71% 8% / 0.6)', border: '1px dashed hsl(142 71% 30%)', padding: 14, borderRadius: 8, display: 'flex', flexDirection: 'column', justifyContent: 'center', alignItems: 'center', textAlign: 'center' }}>
                  <CheckCircle2 size={32} style={{ color: 'hsl(142 71% 50%)', marginBottom: 8 }} />
                  <div style={{ fontWeight: 800, fontSize: 14, color: 'hsl(142 71% 70%)' }}>REPEATED ATTACK TEST: BLOCKED</div>
                  <div style={{ fontSize: 11, color: 'hsl(var(--muted-foreground))', marginTop: 4 }}>Response Time: <strong>0ms (Perimeter Prevention)</strong></div>
                </div>
              </div>
            </motion.div>
          )}

          {currentStep === 'RECOVERY' && (
            <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} style={{ padding: 12 }}>
              <div style={{ background: 'hsl(var(--primary) / 0.15)', border: '1px solid hsl(var(--primary) / 0.4)', borderRadius: 8, padding: 16, marginBottom: 20 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, color: 'hsl(var(--primary))', fontWeight: 800 }}>
                  <HardDriveDownload size={20} />
                  <span>STEP 6: DATA RECOVERY ENGINE DEMONSTRATION</span>
                </div>
                <p style={{ margin: '8px 0 0', fontSize: 13, color: 'hsl(var(--foreground))' }}>
                  Restoring compromised & staged files from ARGUS isolated shadow snapshot back to original host locations.
                </p>
              </div>

              <div style={{ background: 'hsl(var(--muted) / 0.2)', padding: 14, borderRadius: 8 }}>
                {stagedDataFiles.map((f, i) => (
                  <div key={i} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '10px 12px', background: 'hsl(var(--card))', borderRadius: 6, marginBottom: 8 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                      <CheckCircle2 size={18} style={{ color: 'hsl(142 71% 50%)' }} />
                      <span style={{ fontSize: 13, fontWeight: 700 }}>{f.name}</span>
                    </div>
                    <span className="badge badge-low" style={{ background: 'hsl(142 71% 15%)', color: 'hsl(142 71% 70%)' }}>
                      Restored & Verified (100% Match)
                    </span>
                  </div>
                ))}
              </div>
            </motion.div>
          )}

          {currentStep === 'FINISHED' && (
            <motion.div initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} style={{ padding: 20, textAlign: 'center' }}>
              <div style={{ width: 64, height: 64, borderRadius: '50%', background: 'hsl(142 71% 15%)', color: 'hsl(142 71% 60%)', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 16px', border: '2px solid hsl(142 71% 40%)' }}>
                <Check size={36} />
              </div>
              <h3 style={{ fontSize: 22, fontWeight: 800, margin: '0 0 8px' }}>Simulation Complete</h3>
              <p style={{ color: 'hsl(var(--muted-foreground))', maxWidth: 600, margin: '0 auto 24px', fontSize: 14, lineHeight: 1.6 }}>
                All 6 presentation phases successfully executed. Threat contained, exposure measured, Cyber Cell notified with user approval, adaptive blocking rules enforced, and data 100% recovered.
              </p>

              <div style={{ display: 'flex', gap: 12, justifyContent: 'center' }}>
                <button className="btn btn-outline" onClick={startSimulation} style={{ gap: 8 }}>
                  <RefreshCw size={14} /> Re-run Simulation
                </button>
                {onNavigate && (
                  <button className="btn btn-primary" onClick={() => { onClose(); onNavigate('/cyber-cell'); }} style={{ gap: 8 }}>
                    View Cyber Cell Portal <ArrowRight size={14} />
                  </button>
                )}
              </div>
            </motion.div>
          )}
        </div>

        {/* Modal Footer Controls */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderTop: '1px solid hsl(var(--border))', paddingTop: 16, marginTop: 24 }}>
          <div style={{ fontSize: 12, color: 'hsl(var(--muted-foreground))' }}>
            Mode: <strong>JUDGE_PRESENTATION_DRILL</strong>
          </div>
          <div style={{ display: 'flex', gap: 10 }}>
            {currentStep !== 'IDLE' && currentStep !== 'FINISHED' && (
              <button className="btn btn-ghost" onClick={() => setIsAutoRunning(!isAutoRunning)} style={{ gap: 6 }}>
                {isAutoRunning ? 'Pause Auto-Play' : 'Resume Auto-Play'}
              </button>
            )}
            <button className="btn btn-secondary" onClick={onClose}>
              Close Window
            </button>
          </div>
        </div>
      </motion.div>
    </div>
  );
};
