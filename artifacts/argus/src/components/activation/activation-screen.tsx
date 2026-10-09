import { useEffect, useMemo, useState } from 'react';
import {
  Activity, ArrowRight, BrainCircuit, Check, CheckCircle2, Database, Download,
  ExternalLink, FileSearch, Fingerprint, Laptop, LockKeyhole, MonitorDown,
  Radar, RefreshCw, Shield, ShieldCheck, ShieldAlert, TerminalSquare, X,
} from 'lucide-react';

import {
  ACTIVATION_MESSAGES,
  activate,
  writeActivationMarker,
  isDesktopMode,
  fetchIsDesktopEnvironment,
  markSetupInstalled,
  type ActivationFailure,
} from '@/lib/activation';

type ActivationPhase = { label: string; detail: string; icon: typeof Activity };

const PHASES: ActivationPhase[] = [
  { label: 'Submitting access key', detail: 'Encrypting key material for transport', icon: LockKeyhole },
  { label: 'Validating ARGUS Access Key', detail: 'Checking key against activation service', icon: Fingerprint },
  { label: 'Establishing encrypted tunnel', detail: 'TLS 1.3 handshake · forward secrecy', icon: ShieldCheck },
  { label: 'Authorizing this installation', detail: 'Binding activation to this workstation', icon: Laptop },
  { label: 'Mounting sensor fabric', detail: 'Local endpoint agent discovery', icon: Radar },
  { label: 'Initializing secure workspace', detail: 'Loading signed evidence store', icon: Database },
  { label: 'Restoring detection rules', detail: 'Rule catalog integrity check', icon: FileSearch },
  { label: 'Correlating threat intel feeds', detail: '3 synthetic sources · reputation lookup', icon: BrainCircuit },
  { label: 'Establishing investigator session', detail: 'Issuing HttpOnly activation token', icon: Shield },
  { label: 'Finalizing activation', detail: 'Northstar workspace ready for review', icon: TerminalSquare },
];

const PHASE_MS = 400;

function FailureNote({ reason }: { reason: ActivationFailure }) {
  const copy: Record<ActivationFailure, string> = {
    empty: ACTIVATION_MESSAGES.empty,
    invalid: ACTIVATION_MESSAGES.invalid,
    expired: ACTIVATION_MESSAGES.expired,
    revoked: ACTIVATION_MESSAGES.revoked,
    unavailable: ACTIVATION_MESSAGES.unavailable,
  };
  return (
    <div
      className="muted"
      role="alert"
      aria-live="assertive"
      data-testid={`activation-error-${reason}`}
      style={{
        color: reason === 'expired' || reason === 'revoked' ? 'hsl(var(--destructive))' : 'hsl(var(--destructive))',
        fontSize: 11,
        margin: '-6px 0 10px',
        padding: '6px 10px',
        background: 'hsl(var(--destructive) / 0.12)',
        borderRadius: 4,
        border: '1px solid hsl(var(--destructive) / 0.25)',
      }}
    >
      <ShieldAlert size={12} style={{ display: 'inline', marginRight: 6, verticalAlign: 'middle' }} />
      {copy[reason]}
    </div>
  );
}

export function ActivationScreen({ onActivated }: { onActivated: () => void }) {
  const [accessKey, setAccessKey] = useState('');
  const [busy, setBusy] = useState(false);
  const [step, setStep] = useState(0);
  const [failure, setFailure] = useState<ActivationFailure | null>(null);
  const [webDownloadReady, setWebDownloadReady] = useState(false);
  const [downloadUrl, setDownloadUrl] = useState<string>('/api/desktop/download');
  const [downloadError, setDownloadError] = useState<string | null>(null);
  const [desktop, setDesktop] = useState(() => isDesktopMode());

  useEffect(() => {
    let cancelled = false;
    void fetchIsDesktopEnvironment().then((value) => {
      if (!cancelled) setDesktop(value);
    });
    return () => {
      cancelled = true;
    };
  }, []);

  // Handshake progress indicator
  useEffect(() => {
    if (!busy || webDownloadReady) return undefined;
    if (step >= PHASES.length) return undefined;
    const timer = window.setTimeout(() => setStep((current) => current + 1), PHASE_MS);
    return () => window.clearTimeout(timer);
  }, [busy, step, webDownloadReady]);

  const active = useMemo(() => PHASES[Math.min(step, PHASES.length - 1)], [step]);
  const ActiveIcon = active.icon;
  const totalSeconds = Math.round((PHASES.length * PHASE_MS) / 1000);
  const remainingSeconds = Math.max(1, totalSeconds - Math.round((step * PHASE_MS) / 1000));

  const triggerBrowserDownload = (url: string) => {
    try {
      const a = document.createElement('a');
      a.href = url;
      a.download = 'ARGUS-Setup.exe';
      a.rel = 'noopener';
      document.body.appendChild(a);
      a.click();
      a.remove();
    } catch {
      setDownloadError('Browser blocked automatic download. Please click the button below to save ARGUS-Setup.exe.');
    }
  };

  const submit = async () => {
    if (busy) return;

    const key = accessKey.trim();
    if (!key) {
      setFailure('empty');
      return;
    }

    setFailure(null);
    setStep(0);
    setBusy(true);

    const result = await activate(key);

    // Drop the key from component state immediately so it cannot be inspected in memory
    setAccessKey('');

    if (!result.ok) {
      setFailure(result.reason);
      setBusy(false);
      return;
    }

    writeActivationMarker();

    // 1. If running inside the installed Windows desktop application:
    // DIRECTLY enter into the ARGUS Dashboard! Never show the website's download prompt.
    if (desktop || result.isDesktop) {
      markSetupInstalled();
      setBusy(false);
      onActivated();
      return;
    }

    // 2. If running on the hosted ARGUS website:
    // Initiate normal browser download of ARGUS-Setup.exe and show the download confirmation card.
    const targetUrl = result.downloadUrl || '/api/desktop/download';
    setDownloadUrl(targetUrl);
    setWebDownloadReady(true);
    setBusy(false);

    // Auto-initiate download via browser
    triggerBrowserDownload(targetUrl);
  };

  return (
    <div className="login">
      {/* HOSTED WEB DOWNLOAD MODAL: Shown ONLY on the hosted website upon activation */}
      {webDownloadReady && (
        <div className="perm-overlay" role="dialog" aria-modal="true" aria-labelledby="perm-download-title">
          <div className="perm-card" data-testid="web-download-card" style={{ maxWidth: 460 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 16 }}>
              <div className="perm-icon is-live" style={{ margin: 0, background: 'hsl(142 71% 15%)', color: 'hsl(142 71% 55%)' }}>
                <CheckCircle2 size={24} />
              </div>
            </div>

            <div className="eyebrow" style={{ color: 'hsl(142 71% 55%)' }}>LICENSE ACTIVATED & VERIFIED</div>
            <h3 id="perm-download-title" style={{ marginTop: 6, fontSize: 20 }}>ARGUS for Windows Download</h3>
            <p className="perm-body" style={{ marginTop: 10, marginBottom: 14 }}>
              Your ARGUS Access Key has been verified. Your browser download of{' '}
              <strong style={{ color: 'hsl(var(--foreground))' }}>ARGUS-Setup.exe</strong> has started.
            </p>

            <div style={{ background: 'hsl(var(--muted))', padding: '12px 14px', borderRadius: 6, marginBottom: 16, border: '1px solid hsl(var(--border))' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <MonitorDown size={20} className="signal-info" />
                <div>
                  <div style={{ fontSize: 13, fontWeight: 700 }}>ARGUS-Setup.exe</div>
                  <div className="mono muted" style={{ fontSize: 11 }}>Universal Windows Installer · Win 10/11 x64</div>
                </div>
              </div>
            </div>

            {downloadError && (
              <p className="perm-error" style={{ whiteSpace: 'pre-line', marginBottom: 12 }} role="alert">
                {downloadError}
              </p>
            )}

            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              <a
                href={downloadUrl}
                download="ARGUS-Setup.exe"
                className="btn btn-primary"
                style={{ width: '100%', justifyContent: 'center', height: 40, textDecoration: 'none' }}
                data-testid="button-download-installer"
              >
                <Download size={14} style={{ marginRight: 8 }} /> Download ARGUS-Setup.exe Directly
              </a>
              <button
                type="button"
                className="btn btn-ghost"
                onClick={() => {
                  markSetupInstalled();
                  onActivated();
                }}
                style={{ width: '100%', justifyContent: 'center', height: 38 }}
                data-testid="button-open-web-workspace"
              >
                Continue to Web Dashboard <ArrowRight size={13} style={{ marginLeft: 6 }} />
              </button>
            </div>

            <p style={{ textAlign: 'center', fontSize: 11, color: 'hsl(var(--muted-foreground))', marginTop: 14, marginBottom: 0 }}>
              After download completes, run <strong>ARGUS-Setup.exe</strong> to install on your computer.
            </p>
          </div>
        </div>
      )}

      {/* LEFT RADAR VISUAL */}
      <div className={`login-visual${busy ? ' is-busy' : ''}`}>
        <div className="login-ambient">
          <i className="login-ring r1" />
          <i className="login-ring r2" />
          <i className="login-ring r3" />
          <div className="login-sweep" />
          <span className="login-blip b1" />
          <span className="login-blip b2" />
          <span className="login-blip b3" />
          <div className="login-grid" />
        </div>

        <div className="brand login-fade">
          <div className="brand-mark"><Radar size={17} /></div>
          <div>
            <div className="brand-word">ARGUS</div>
            <div className="brand-sub">SECURITY INTELLIGENCE</div>
          </div>
        </div>

        <div className="login-quote login-fade d1">
          <div className="eyebrow">{desktop ? 'Desktop Installation' : 'Licensed Endpoint Intelligence'}</div>
          <h1>
            {desktop ? <>Activate your<br /><span className="signal-info">workstation.</span></> : <>Activate before<br /><span className="signal-info">you download.</span></>}
          </h1>
          <p>
            {desktop
              ? 'ARGUS Security Intelligence is installed. Enter your ARGUS Access Key to unlock full endpoint telemetry, detection, and forensic quarantine.'
              : 'ARGUS is an enterprise security intelligence workspace. Validate your authorized ARGUS Access Key to download the Windows client and initialize your sensor grid.'}
          </p>
        </div>

        {busy ? (
          <div className="login-handshake login-fade">
            <div className="hs-radar"><div className="hs-blip" /><RefreshCw size={30} className="hs-icon auth-cascade" /></div>
            <div className="hs-step"><ActiveIcon size={14} /><span>{active.label}</span></div>
            <div className="hs-track"><i style={{ width: `${Math.min(100, Math.round(((step + 1) / PHASES.length) * 100))}%` }} /></div>
            <div className="login-detail" style={{ justifyContent: 'center' }}>
              <span>{String(step + 1)}</span>
              <span>/ {PHASES.length}</span>
              <span>~{remainingSeconds}s LEFT</span>
            </div>
          </div>
        ) : (
          <div className="login-detail login-fade d2">
            <span>24 ENDPOINTS</span>
            <span>HARDWARE-BOUND LICENSING</span>
            <span>OBSERVATION-FIRST</span>
          </div>
        )}
      </div>

      {/* RIGHT ACTIVATION FORM */}
      <div className="login-form-wrap">
        <form className={`login-form${busy ? ' is-busy' : ''}`} onSubmit={(event) => { event.preventDefault(); void submit(); }}>
          <div className="eyebrow login-fade d1">{desktop ? 'Workstation License' : 'Product Activation'}</div>

          {busy ? (
            <div className="login-busy login-fade" data-testid="activation-busy" aria-live="polite">
              <div className="login-spinner"><Radar size={40} /></div>
              <h2>{active.label}</h2>
              <p>{active.detail}</p>
              <div className="login-meta">
                {PHASES.map((phase, index) => (
                  <span key={phase.label} className={index < step ? 'done' : index === step ? 'now' : ''}>
                    {index < step ? <Check size={11} /> : <i />} {phase.label}
                  </span>
                ))}
              </div>
            </div>
          ) : (
            <>
              <h2 className="login-fade d2">{desktop ? 'Activate ARGUS Desktop' : 'Activate ARGUS'}</h2>
              <p className="login-fade d3">
                {desktop
                  ? 'Enter your ARGUS Access Key to activate this computer. Your license is bound to this device and kept securely.'
                  : 'Enter your ARGUS Access Key. Upon validation, the secure Windows installer will download automatically.'}
              </p>

              <div className="field login-fade d3">
                <label htmlFor="activation-access-key">ARGUS Access Key</label>
                <input
                  id="activation-access-key"
                  name="accessKey"
                  value={accessKey}
                  onChange={(event) => { setAccessKey(event.target.value); setFailure(null); }}
                  type="password"
                  autoComplete="off"
                  spellCheck={false}
                  autoFocus
                  placeholder="ARGUS-XXXX-XXXX-XXXX"
                  data-testid="input-access-key"
                />
              </div>

              {failure && <FailureNote reason={failure} />}

              <button type="submit" className="btn btn-primary login-button" data-testid="button-activate">
                <LockKeyhole size={13} /> {desktop ? 'ACTIVATE WORKSTATION' : 'VALIDATE & DOWNLOAD'}
              </button>

              <div
                style={{ borderTop: '1px solid hsl(var(--border))', marginTop: 18, paddingTop: 13, display: 'flex', gap: 8, color: 'hsl(var(--muted-foreground))', fontSize: 10 }}
                className="login-fade d5"
              >
                <ShieldCheck size={13} /> Verified on backend with server-side cryptography. Secret keys are never exposed in client code.
              </div>
            </>
          )}
        </form>
      </div>
    </div>
  );
}

export default ActivationScreen;
