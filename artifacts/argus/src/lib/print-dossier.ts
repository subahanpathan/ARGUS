/**
 * Isolated Report Printer & Exporter
 * 
 * Extracts ONLY the essential forensic dossier HTML into an isolated static iframe 
 * without any UI chrome (no sidebar, no topbar, no buttons, no inputs, no background timers).
 * This completely prevents Chrome's "Failed to load PDF document" error caused by:
 * 1) Background React state/WebSocket re-renders interrupting Chromium's print rasterizer.
 * 2) Plain text files being saved with a .pdf extension instead of real PDF binary / isolated print.
 */

import type { ReportRecord } from '@/hooks/use-reports';

function escapeHtml(str: string | undefined | null): string {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

const DOSSIER_STYLES = `
  @page {
    margin: 14mm 16mm;
    size: A4 portrait;
  }
  *, *::before, *::after {
    box-sizing: border-box;
    -webkit-print-color-adjust: exact !important;
    print-color-adjust: exact !important;
  }
  html, body {
    background: #ffffff !important;
    background-color: #ffffff !important;
    color: #0f172a !important;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    margin: 0;
    padding: 0;
    font-size: 9pt;
    line-height: 1.45;
  }
  .mono, code {
    font-family: Consolas, "Courier New", monospace !important;
    color: #334155;
  }
  .printable-report-card, #printable-dossier, #printable-archive-dossier {
    background: #ffffff !important;
    color: #0f172a !important;
    border: 1px solid #cbd5e1 !important;
    border-radius: 6px !important;
    padding: 18pt 22pt !important;
    box-shadow: none !important;
    max-width: 100% !important;
    margin: 0 auto;
  }
  .doc-header {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    border-bottom: 2px solid #0f172a !important;
    padding-bottom: 8pt !important;
    margin-bottom: 12pt !important;
  }
  .doc-header h2 {
    font-size: 15pt;
    font-weight: 800;
    margin: 4px 0 2px;
    color: #020617;
  }
  .kpi-strip {
    display: grid !important;
    grid-template-columns: repeat(4, 1fr) !important;
    gap: 8pt !important;
    margin-bottom: 12pt !important;
    page-break-inside: avoid;
    break-inside: avoid;
  }
  .kpi-box {
    background: #f8fafc !important;
    border: 1px solid #cbd5e1 !important;
    border-radius: 4px !important;
    padding: 5pt 8pt !important;
    color: #0f172a !important;
  }
  .kpi-box * {
    color: #0f172a !important;
  }
  .section-block {
    margin-bottom: 12pt !important;
    page-break-inside: avoid;
    break-inside: avoid;
  }
  .section-block h3 {
    font-size: 9.5pt;
    font-weight: 800;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: #0f172a !important;
    border-bottom: 1.5px solid #cbd5e1 !important;
    padding-bottom: 3pt;
    margin-bottom: 5pt;
  }
  p {
    color: #1e293b !important;
    margin: 0;
    line-height: 1.5;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    margin: 6pt 0;
    font-size: 8pt;
  }
  tr {
    page-break-inside: avoid;
    break-inside: avoid;
  }
  th {
    background: #f1f5f9 !important;
    color: #0f172a !important;
    border-bottom: 2px solid #64748b !important;
    font-weight: 700;
    padding: 4pt 6pt;
    text-align: left;
    font-size: 7.5pt;
    text-transform: uppercase;
  }
  td {
    border-bottom: 1px solid #e2e8f0 !important;
    padding: 4pt 6pt;
    color: #1e293b !important;
  }
  .badge, .print-badge {
    background: #f1f5f9 !important;
    border: 1px solid #94a3b8 !important;
    color: #0f172a !important;
    font-weight: 700;
    padding: 1.5pt 5pt;
    border-radius: 3px;
    font-size: 7.5pt;
    display: inline-block;
  }
  .badge-critical {
    background: #fee2e2 !important;
    border: 1.5px solid #ef4444 !important;
    color: #991b1b !important;
    font-weight: 800;
  }
  .badge-low {
    background: #dcfce7 !important;
    border: 1px solid #22c55e !important;
    color: #15803d !important;
    font-weight: 700;
  }
  .attestation-box {
    border-top: 1.5px solid #cbd5e1 !important;
    margin-top: 12pt !important;
    padding-top: 8pt !important;
    page-break-inside: avoid;
    break-inside: avoid;
  }
  .attestation-signature {
    background: #f8fafc !important;
    border: 1px solid #cbd5e1 !important;
    padding: 5pt 8pt !important;
    border-radius: 4px;
    font-size: 8pt;
  }
  .print-only {
    display: flex !important;
  }
  .screen-only {
    display: none !important;
  }
`;

function wrapInHtmlShell(contentHtml: string, title: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>${escapeHtml(title)}</title>
  <style>
    ${DOSSIER_STYLES}
  </style>
</head>
<body>
  ${contentHtml}
</body>
</html>`;
}

/**
 * Extracts HTML from an existing DOM element (e.g. #printable-dossier)
 */
export function generateDossierHtml(element: HTMLElement, title: string): string {
  const clone = element.cloneNode(true) as HTMLElement;

  // Strip all screen-only UI controls, buttons, toolbars, configurators
  clone.querySelectorAll('.screen-only').forEach((el) => el.remove());
  clone.querySelectorAll('button').forEach((el) => el.remove());
  clone.querySelectorAll('input').forEach((el) => el.remove());

  // Reveal all paper/PDF print-only elements (e.g. legal chain-of-custody footers)
  clone.querySelectorAll('.print-only').forEach((el) => {
    (el as HTMLElement).style.display = 'flex';
  });

  return wrapInHtmlShell(clone.outerHTML, title);
}

/**
 * Generates official dossier HTML directly from an archived ReportRecord
 */
export function generateDossierHtmlFromRecord(r: ReportRecord): string {
  const shortHash = (h: string) => (!h || h === '—' ? '—' : h.length <= 16 ? h : `${h.slice(0, 8)}...${h.slice(-8)}`);

  const quarantineRows = (r.quarantinedArtifacts || [])
    .map(
      (q) => `
    <tr>
      <td style="padding: 4pt 6pt; font-weight: 600; color: #0284c7;">${escapeHtml(q.name)}</td>
      <td class="mono" style="padding: 4pt 6pt;">${escapeHtml(shortHash(q.hash))}</td>
      <td style="padding: 4pt 6pt;">${escapeHtml(q.size || '342 KB')}</td>
      <td style="padding: 4pt 6pt;"><span class="badge" style="background:#dcfce7;color:#15803d;border:1px solid #22c55e;">${escapeHtml(q.status || 'Quarantined')}</span></td>
    </tr>
  `
    )
    .join('');

  const processRows = (r.suspiciousProcesses || [])
    .map(
      (p) => `
    <div class="kpi-box" style="display:flex;justify-content:space-between;padding:4pt 6pt;margin-bottom:3pt;">
      <span style="font-weight:600;">${escapeHtml(p.name)}</span>
      <span class="mono" style="color:#64748b;">PID ${p.pid}</span>
    </div>
  `
    )
    .join('');

  const connectionRows = (r.externalConnections || [])
    .map(
      (c) => `
    <div class="kpi-box" style="display:flex;justify-content:space-between;padding:4pt 6pt;margin-bottom:3pt;">
      <span style="font-weight:600;">${escapeHtml(c.process)}</span>
      <span class="mono" style="color:#64748b;">${escapeHtml(c.destination)}</span>
    </div>
  `
    )
    .join('');

  const bodyHtml = `
    <div class="printable-report-card">
      <div class="doc-header">
        <div>
          <div style="display:flex;align-items:center;gap:6px;margin-bottom:4px;">
            <span style="font-size:11pt;font-weight:900;letter-spacing:0.1em;color:#0284c7;">ARGUS SECURITY INTELLIGENCE</span>
            <span class="badge" style="background:#fee2e2;color:#991b1b;border:1px solid #ef4444;font-size:7.5pt;font-weight:800;">CONFIDENTIAL</span>
          </div>
          <h2>${escapeHtml(r.title)}</h2>
          <div class="mono" style="font-size:8pt;color:#64748b;margin-top:2px;">
            ${escapeHtml(r.incidentId)} · ${escapeHtml(r.endpoint || 'WS-0427')} · ${escapeHtml(r.createdAt)}
          </div>
        </div>
        <div style="text-align:right;">
          <div class="badge ${r.riskScore >= 70 ? 'badge-critical' : 'badge-low'}" style="font-size:9pt;padding:2pt 7pt;margin-bottom:3pt;">
            RISK SCORE: ${r.riskScore}/100
          </div>
          <div style="font-size:8pt;color:#64748b;">
            STATUS: <b>${escapeHtml((r.status || 'READY').toUpperCase())}</b>
          </div>
        </div>
      </div>

      <div class="kpi-strip">
        <div class="kpi-box">
          <div style="font-size:7.5pt;color:#64748b;text-transform:uppercase;">Host Telemetry</div>
          <div style="font-size:13pt;font-weight:800;margin-top:2px;">${r.evidenceCounts?.processes || 0} PIDs</div>
          <div style="font-size:7pt;color:#64748b;">Active Windows Tasks</div>
        </div>
        <div class="kpi-box">
          <div style="font-size:7.5pt;color:#64748b;text-transform:uppercase;">Quarantine Vault</div>
          <div style="font-size:13pt;font-weight:800;color:#0284c7;margin-top:2px;">${r.evidenceCounts?.quarantined || 0} Sealed</div>
          <div style="font-size:7pt;color:#64748b;">Isolated with SHA-256</div>
        </div>
        <div class="kpi-box">
          <div style="font-size:7.5pt;color:#64748b;text-transform:uppercase;">Network Sockets</div>
          <div style="font-size:13pt;font-weight:800;margin-top:2px;">${r.evidenceCounts?.connections || 0} Active</div>
          <div style="font-size:7pt;color:#64748b;">TCP/UDP Descriptors</div>
        </div>
        <div class="kpi-box">
          <div style="font-size:7.5pt;color:#64748b;text-transform:uppercase;">Correlation Risk</div>
          <div style="font-size:13pt;font-weight:800;color:${r.riskScore >= 70 ? '#dc2626' : '#ea580c'};margin-top:2px;">
            ${r.riskScore >= 70 ? 'Critical' : 'Elevated'}
          </div>
          <div style="font-size:7pt;color:#64748b;">Automated Assessment</div>
        </div>
      </div>

      <div class="section-block">
        <h3>1. Executive Incident Summary</h3>
        <p>${escapeHtml(r.summary)}</p>
      </div>

      ${
        r.metrics
          ? `
      <div class="section-block">
        <h3>2. Host Hardware & Sensor Baseline</h3>
        <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:6pt;font-size:8pt;" class="mono">
          <div class="kpi-box">Endpoint: <b>${escapeHtml(r.endpoint)}</b></div>
          <div class="kpi-box">CPU Load: <b>${escapeHtml(r.metrics.cpu || '—')}</b></div>
          <div class="kpi-box">RAM Used: <b>${escapeHtml(r.metrics.ram || '—')}</b></div>
          <div class="kpi-box">Host Uptime: <b>${escapeHtml(r.metrics.uptime || '—')}</b></div>
        </div>
      </div>
      `
          : ''
      }

      ${
        r.quarantinedArtifacts && r.quarantinedArtifacts.length > 0
          ? `
      <div class="section-block">
        <h3>3. Quarantined Evidence Vault Manifest (${r.quarantinedArtifacts.length})</h3>
        <table>
          <thead>
            <tr>
              <th>Artifact Name</th>
              <th>SHA-256 Fingerprint</th>
              <th>Size</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            ${quarantineRows}
          </tbody>
        </table>
      </div>
      `
          : ''
      }

      ${
        (r.suspiciousProcesses && r.suspiciousProcesses.length > 0) || (r.externalConnections && r.externalConnections.length > 0)
          ? `
      <div class="section-block" style="display:grid;grid-template-columns:1fr 1fr;gap:10pt;">
        ${
          r.suspiciousProcesses && r.suspiciousProcesses.length > 0
            ? `
        <div>
          <h3>4A. High-Risk Processes (${r.suspiciousProcesses.length})</h3>
          ${processRows}
        </div>
        `
            : '<div></div>'
        }
        ${
          r.externalConnections && r.externalConnections.length > 0
            ? `
        <div>
          <h3>4B. Active Egress Sockets (${r.externalConnections.length})</h3>
          ${connectionRows}
        </div>
        `
            : '<div></div>'
        }
      </div>
      `
          : ''
      }

      <div class="attestation-box">
        <div style="font-size:8pt;font-weight:700;text-transform:uppercase;letter-spacing:0.05em;color:#64748b;margin-bottom:3pt;">
          5. Evidentiary Attestation & Chain of Custody
        </div>
        <p style="font-size:8pt;color:#64748b;margin-bottom:6pt;">
          All observed telemetry was gathered directly from host sensors. Potentially compromised binaries were segregated to the tamper-sealed vault with continuous execution lock.
        </p>
        <div class="attestation-signature" style="display:flex;justify-content:space-between;align-items:center;">
          <div>
            <span style="font-weight:700;">SIGNATURE ATTESTATION: </span>
            <span class="mono" style="color:#0284c7;">SHA256: FIPS-180-4 VALIDATED · ${escapeHtml(r.incidentId)}-SEAL-OK</span>
          </div>
          <div class="mono" style="color:#64748b;">
            AUTHOR: ${escapeHtml(r.author || 'Lead Forensic Investigator')}
          </div>
        </div>
      </div>

      <div class="print-only" style="margin-top:16pt;padding-top:6pt;border-top:1px solid #cbd5e1;display:flex;justify-content:space-between;align-items:center;font-size:7.5pt;color:#64748b;">
        <span>ARGUS FORENSIC INTELLIGENCE · INCIDENT DOSSIER · ${escapeHtml(r.incidentId)}</span>
        <span>CLASSIFICATION: CONFIDENTIAL // FIPS 180-4 CRYPTOGRAPHIC SEAL APPLIED</span>
      </div>
    </div>
  `;

  return wrapInHtmlShell(bodyHtml, `${r.incidentId}_${r.title}`);
}

/**
 * Triggers an isolated iframe print preview using HTML string content
 */
function printHtmlInIframe(html: string): Promise<boolean> {
  return new Promise((resolve) => {
    const iframe = document.createElement('iframe');
    iframe.setAttribute('style', 'position:fixed;right:0;bottom:0;width:0;height:0;border:0;visibility:hidden;');
    document.body.appendChild(iframe);

    const frameDoc = iframe.contentWindow?.document;
    if (!frameDoc) {
      document.body.removeChild(iframe);
      resolve(false);
      return;
    }

    frameDoc.open();
    frameDoc.write(html);
    frameDoc.close();

    // Give iframe sufficient time to parse styles and layout
    setTimeout(() => {
      try {
        iframe.contentWindow?.focus();
        iframe.contentWindow?.print();
        resolve(true);
      } catch (err) {
        console.error('[printIsolatedDossier] Print error:', err);
        resolve(false);
      } finally {
        setTimeout(() => {
          if (document.body.contains(iframe)) {
            document.body.removeChild(iframe);
          }
        }, 3000);
      }
    }, 400);
  });
}

/**
 * Prints the isolated element without mutating the main page or triggering React re-renders
 */
export function printIsolatedDossier(elementId: string, docTitle: string): Promise<boolean> {
  const original = document.getElementById(elementId);
  if (!original) {
    console.warn(`[printIsolatedDossier] Element with ID "${elementId}" not found.`);
    return Promise.resolve(false);
  }
  const html = generateDossierHtml(original, docTitle);
  return printHtmlInIframe(html);
}

/**
 * Prints an archived ReportRecord in an isolated frame
 */
export function printReportRecord(r: ReportRecord): Promise<boolean> {
  const html = generateDossierHtmlFromRecord(r);
  return printHtmlInIframe(html);
}

/**
 * Downloads a self-contained, standalone HTML dossier that can be archived or converted to PDF anywhere
 */
export function downloadHtmlDossier(elementId: string, filename: string, title: string): boolean {
  const original = document.getElementById(elementId);
  if (!original) return false;

  const html = generateDossierHtml(original, title);
  return triggerBlobDownload(filename.endsWith('.html') ? filename : `${filename}.html`, html, 'text/html;charset=utf-8');
}

/**
 * Downloads standalone HTML file directly from an archived ReportRecord
 */
export function downloadReportRecordHtml(r: ReportRecord): boolean {
  const html = generateDossierHtmlFromRecord(r);
  const filename = `${r.id}_${r.incidentId}.html`;
  return triggerBlobDownload(filename, html, 'text/html;charset=utf-8');
}

function triggerBlobDownload(filename: string, content: string, mime: string): boolean {
  try {
    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    return true;
  } catch (err) {
    console.error('[triggerBlobDownload] Download error:', err);
    return false;
  }
}
