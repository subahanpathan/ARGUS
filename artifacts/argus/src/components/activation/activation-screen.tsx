import { useEffect, useMemo, useState } from 'react';
import {
  Activity, BrainCircuit, Check, Database, Download, FileSearch, Fingerprint, Laptop, LockKeyhole,
  MonitorDown, Radar, RefreshCw, Shield, ShieldCheck, ShieldAlert, TerminalSquare, X,
} from 'lucide-react';

import { ACTIVATION_MESSAGES, activate, writeActivationMarker, type ActivationFailure } from '@/lib/activation';

/**
 * ARGUS activation screen.
 *
 * This replaces the old login / create-account pair. There is no registration
 * path: an installation is opened by presenting an ARGUS Access Key, which the
 * server validates. The key is held in component state for the lifetime of the
 * request and is never mirrored to storage.
 */

type ActivationPhase = { label: string; detail: string; icon: typeof Activity };

type DesktopPermission = 'pending' | 'accepted' | 'declined';

const PHASES: ActivationPhase[] = [
  { label: 'Submitting access key', detail: 'Encrypting key material for transport', icon: LockKeyhole },
  { label: 'Validating ARGUS Access Key', detail: 'Checking key against the activation service', icon: Fingerprint },
  { label: 'Establishing encrypted tunnel', detail: 'TLS 1.3 handshake · forward secrecy', icon: ShieldCheck },
  { label: 'Authorizing this installation', detail: 'Binding activation to this workstation', icon: Laptop },
  { label: 'Mounting sensor fabric', detail: 'Local endpoint agent discovery', icon: Radar },
  { label: 'Initializing secure workspace', detail: 'Loading signed evidence store', icon: Database },
  { label: 'Restoring detection rules', detail: 'Rule catalog integrity check', icon: FileSearch },
  { label: 'Correlating threat intel feeds', detail: '3 synthetic sources · reputation lookup', icon: BrainCircuit },
  { label: 'Establishing investigator session', detail: 'Issuing HttpOnly activation token', icon: Shield },
  { label: 'Finalizing activation', detail: 'Northstar workspace ready for review', icon: TerminalSquare },
];

const PHASE_MS = 500;

function FailureNote({ reason }: { reason: ActivationFailure }) {
  const copy: Record<ActivationFailure, string> = {
    empty: ACTIVATION_MESSAGES.empty,
    invalid: ACTIVATION_MESSAGES.invalid,
    unavailable: ACTIVATION_MESSAGES.unavailable,
  };
  return (
    <div
      className="muted"
      role="alert"
      aria-live="assertive"
      data-testid={`activation-error-${reason}`}
      style={{ color: 'hsl(var(--destructive))', fontSize: 11, margin: '-6px 0 10px' }}
    >
      {copy[reason]}
    </div>
  );
}

export function ActivationScreen({ onActivated }: { onActivated: () => void }) {
  const [accessKey, setAccessKey] = useState('');
  const [busy, setBusy] = useState(false);
  const [step, setStep] = useState(0);
  const [failure, setFailure] = useState<ActivationFailure | null>(null);
  const [succeeded, setSucceeded] = useState(false);
  const [permission, setPermission] = useState<DesktopPermission>('pending');
  const [downloading, setDownloading] = useState(false);
  const [downloadError, setDownloadError] = useState<string | null>(null);

  const requestDownload = async () => {
    setDownloading(true);
    setDownloadError(null);
    try {
      // Ask the server whether the installer exists, then trigger the download.
      // The endpoint serves the bundled installer, or redirects (302) to a
      // static asset on serverless hosts, or to the GitHub Release asset.
      let status = 0;
      let url = '/api/desktop/download';
      for (let hop = 0; hop < 4; hop++) {
        const probe = await fetch(url, { method: 'HEAD', redirect: 'manual' });
        status = probe.status;
        const loc = probe.headers.get('location');
        if (status >= 300 && status < 400 && loc) {
          url = loc.startsWith('http') ? loc : new URL(loc, window.location.origin).href;
          continue;
        }
        break;
      }
      if (status !== 200) {
        setDownloadError('The desktop installer is not available on this server yet.');
        setDownloading(false);
        return;
      }
      // Native anchor download (browser/desktop window handles Save As).
      const a = document.createElement('a');
      a.href = url;
      a.download = 'ARGUS-Setup.exe';
      document.body.appendChild(a);
      a.click();
      a.remove();
      setDownloading(false);
    } catch {
      setDownloadError('Download failed. Please try again.');
      setDownloading(false);
    }
  };

  const acceptPermission = () => {
    setPermission('accepted');
    void requestDownload();
  };

  const declinePermission = () => {
    setPermission('declined');
    onActivated();
  };

  const continueToWorkspace = () => {
    onActivated();
  };

  // The handshake is a progress indicator, so it must outlast a fast local API
  // response instead of flashing past. Paused once the key has been accepted.
  useEffect(() => {
    if (!busy || succeeded) return undefined;
    if (step >= PHASES.length) return undefined;
    const timer = window.setTimeout(() => setStep((current) => current + 1), PHASE_MS);
    return () => window.clearTimeout(timer);
  }, [busy, step, succeeded]);

  const active = useMemo(() => PHASES[Math.min(step, PHASES.length - 1)], [step]);
  const ActiveIcon = active.icon;
  const totalSeconds = Math.round((PHASES.length * PHASE_MS) / 1000);
  const remainingSeconds = Math.max(1, totalSeconds - Math.round((step * PHASE_MS) / 1000));

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

    // Drop the key from component state as soon as the request settles so it
    // cannot be recovered from a React DevTools snapshot.
    setAccessKey('');

    if (!result.ok) {
      setFailure(result.reason);
      setBusy(false);
      return;
    }

    setSucceeded(true);
    writeActivationMarker();
    // Per-product flow: after a valid key, ask permission to download the
    // desktop software. The workspace opens once the prompt is answered.
  };

  return (
    <div className="login">
      {/* PERMISSION PROMPT - download desktop software after a valid key */}
      {succeeded && permission === 'pending' && (
        <div className="perm-overlay" role="dialog" aria-modal="true" aria-labelledby="perm-title">
          <div className="perm-card" data-testid="desktop-download-permission">
            <div className="perm-icon"><MonitorDown size={22} /></div>
            <h3 id="perm-title">Download ARGUS Desktop?</h3>
            <p className="perm-body">
              Your access key is valid. To finish setup, ARGUS needs permission to
              download and install the desktop application on this laptop.
            </p>
            <ul className="perm-points">
              <li><ShieldCheck size={12} /> Installs the ARGUS Security Intelligence app locally</li>
              <li><Laptop size={12} /> Runs the endpoint protection agent on this device</li>
              <li><Shield size={12} /> No data leaves your machine</li>
            </ul>
            {downloadError && <p className="perm-error" role="alert">{downloadError}</p>}
            <div className="perm-actions">
              <button type="button" className="btn btn-ghost btn-sm" onClick={declinePermission}>
                <X size={12} /> No thanks
              </button>
              <button type="button" className="btn btn-primary btn-sm" onClick={acceptPermission}>
                <Download size={12} /> Allow download
              </button>
            </div>
          </div>
        </div>
      )}

      {succeeded && permission === 'accepted' && (
        <div className="perm-overlay" role="dialog" aria-modal="true" aria-labelledby="perm-downloading">
          <div className="perm-card" data-testid="desktop-downloading">
            <div className="perm-icon is-live"><RefreshCw size={22} className="auth-cascade" /></div>
            <h3 id="perm-downloading">Preparing your download…</h3>
            <p className="perm-body">
              Your browser or desktop window will prompt you to save
              {' '}<b>ARGUS-Setup.exe</b>. Run it once saved to install ARGUS on this laptop.
            </p>
            {downloadError && <p className="perm-error" role="alert">{downloadError}</p>}
            <div className="perm-actions">
              <button type="button" className="btn btn-primary btn-sm" onClick={continueToWorkspace}>
                Continue to workspace
              </button>
            </div>
          </div>
        </div>
      )}

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
          <div className="eyebrow">Licensed installation</div>
          <h1>Activate before<br /><span className="signal-info">you investigate.</span></h1>
          <p>ARGUS is an access-controlled workspace. Enter the ARGUS Access Key issued to this installation to unlock endpoint intelligence, detection, and recovery.</p>
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
            <span>LOCAL SYNTHETIC DATA</span>
            <span>OBSERVATION-FIRST</span>
          </div>
        )}
      </div>

      <div className="login-form-wrap">
        <form className={`login-form${busy ? ' is-busy' : ''}`} onSubmit={(event) => { event.preventDefault(); void submit(); }}>
          <div className="eyebrow login-fade d1">Activate ARGUS</div>

          {busy ? (
            <div className="login-busy login-fade" data-testid="activation-busy" aria-live="polite">
              <div className="login-spinner"><Radar size={40} /></div>
              <h2>{succeeded ? 'ARGUS activated' : active.label}</h2>
              <p>{succeeded ? 'Access key accepted.' : active.detail}</p>
              <div className="login-meta">
                {PHASES.map((phase, index) => (
                  <span key={phase.label} className={index < step ? 'done' : index === step ? 'now' : ''}>
                    {index < step ? <Check size={11} /> : <i />}{phase.label}
                  </span>
                ))}
              </div>
            </div>
          ) : (
            <>
              <h2 className="login-fade d2">Activate ARGUS</h2>
              <p className="login-fade d3">Enter your ARGUS Access Key to activate this installation.</p>

              <div className="field login-fade d3">
                <label htmlFor="activation-access-key">Access Key</label>
                <input
                  id="activation-access-key"
                  name="accessKey"
                  value={accessKey}
                  onChange={(event) => { setAccessKey(event.target.value); setFailure(null); }}
                  type="password"
                  autoComplete="off"
                  spellCheck={false}
                  autoFocus
                  placeholder="XXXX-XXXX-XXXX-XXXX"
                  data-testid="input-access-key"
                />
              </div>

              {failure && <FailureNote reason={failure} />}

              <button type="submit" className="btn btn-primary login-button" data-testid="button-activate">
                <LockKeyhole size={13} /> ACTIVATE ARGUS
              </button>

              <div
                style={{ borderTop: '1px solid hsl(var(--border))', marginTop: 18, paddingTop: 13, display: 'flex', gap: 8, color: 'hsl(var(--muted-foreground))', fontSize: 10 }}
                className="login-fade d5"
              >
                <LockKeyhole size={13} /> Key is validated on the ARGUS activation service and is never stored in this browser.
              </div>
            </>
          )}
        </form>
      </div>
    </div>
  );
}

export default ActivationScreen;
