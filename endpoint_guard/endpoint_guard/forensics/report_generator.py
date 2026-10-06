import html
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..config import Config
from ..database.manager import DatabaseManager


class ReportGenerator:
    """Generates comprehensive, standalone HTML forensic incident reports."""

    def __init__(self, config: Config, db: DatabaseManager):
        self.config = config
        self.db = db

    def generate_html_report(self, incident_id: str, output_path: Optional[str] = None) -> str:
        inc = self.db.get_incident(incident_id)
        if not inc:
            raise ValueError(f"Incident {incident_id} not found in database.")

        events = self.db.get_incident_events(incident_id)
        evidence = self.db.list_evidence(incident_id)
        attacker = self.db.get_attacker(inc.get("attacker_ip", "")) if inc.get("attacker_ip") else None
        chain_valid, broken_id, total_checked = self.db.verify_hash_chain()

        # Extract IOCs
        iocs_ips = set()
        iocs_hashes = set()
        iocs_commands = set()
        for ev in events:
            if ev.get("attacker_ip"):
                iocs_ips.add(ev["attacker_ip"])
            if ev.get("file_hash_sha256") and ev["file_hash_sha256"] != "N/A":
                iocs_hashes.add(ev["file_hash_sha256"])
            if ev.get("command_line"):
                iocs_commands.add(ev["command_line"])

        # Timeline rows
        timeline_rows = ""
        for ev in events:
            sev = ev.get("severity", "Low")
            badge_color = {
                "Critical": "#ef4444",
                "High": "#f97316",
                "Medium": "#eab308",
                "Low": "#3b82f6"
            }.get(sev, "#6b7280")

            timeline_rows += f"""
            <tr>
                <td style="white-space: nowrap; font-family: monospace;">{html.escape(str(ev.get('timestamp')))}</td>
                <td><span style="background: {badge_color}; color: white; padding: 2px 8px; border-radius: 4px; font-weight: bold; font-size: 11px;">{sev}</span></td>
                <td><b>{html.escape(str(ev.get('event_type')))}</b><br><small style="color: #9ca3af;">{html.escape(str(ev.get('source_module')))}</small></td>
                <td>
                    {f"<b>Process:</b> {html.escape(str(ev.get('process_name')))} (PID {ev.get('pid')})<br>" if ev.get('process_name') else ""}
                    {f"<code>{html.escape(str(ev.get('command_line')))}</code><br>" if ev.get('command_line') else ""}
                    {f"<b>File:</b> <code>{html.escape(str(ev.get('file_path')))}</code><br>" if ev.get('file_path') else ""}
                    {f"<b>Details:</b> <span style='font-family: monospace; font-size: 11px;'>{html.escape(str(ev.get('details')))}</span>" if ev.get('details') else ""}
                </td>
                <td style="font-family: monospace; font-size: 10px; color: #10b981;">{ev.get('entry_hash', '')[:16]}...</td>
            </tr>
            """

        evidence_rows = ""
        for evd in evidence:
            evidence_rows += f"""
            <tr>
                <td>{html.escape(str(evd.get('timestamp')))}</td>
                <td><b>{html.escape(str(evd.get('evidence_type')))}</b></td>
                <td><code>{html.escape(str(evd.get('file_path')))}</code></td>
                <td>{html.escape(str(evd.get('description')))}</td>
            </tr>
            """

        mitre_list = json.loads(inc.get("mitre_techniques") or "[]")
        mitre_badges = " ".join(
            f"<span style='background: #374151; color: #60a5fa; padding: 3px 8px; border-radius: 4px; margin-right: 4px;'>{html.escape(m)}</span>"
            for m in mitre_list
        )

        verification_badge = (
            "<span style='color: #10b981; font-weight: bold;'>✔ VERIFIED (Cryptographic SHA-256 Hash Chain Untampered)</span>"
            if chain_valid else
            f"<span style='color: #ef4444; font-weight: bold;'>✖ TAMPER DETECTED at entry ID {broken_id}</span>"
        )

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Endpoint Guard - Forensic Incident Report: {html.escape(inc['id'])}</title>
    <style>
        body {{
            background-color: #0f172a;
            color: #f1f5f9;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            margin: 0;
            padding: 30px;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{ border-bottom: 2px solid #334155; padding-bottom: 20px; margin-bottom: 30px; display: flex; justify-content: space-between; align-items: center; }}
        .title {{ font-size: 26px; font-weight: 800; color: #38bdf8; }}
        .badge {{ padding: 4px 12px; border-radius: 9999px; font-weight: bold; font-size: 14px; text-transform: uppercase; }}
        .badge-Critical {{ background-color: #ef4444; color: white; }}
        .badge-High {{ background-color: #f97316; color: white; }}
        .badge-Medium {{ background-color: #eab308; color: black; }}
        .badge-Low {{ background-color: #3b82f6; color: white; }}
        .card {{ background-color: #1e293b; border-radius: 8px; padding: 20px; margin-bottom: 24px; border: 1px solid #334155; }}
        .card h2 {{ margin-top: 0; color: #94a3b8; font-size: 16px; text-transform: uppercase; letter-spacing: 0.05em; border-bottom: 1px solid #334155; padding-bottom: 10px; }}
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; }}
        .metric-label {{ color: #94a3b8; font-size: 12px; }}
        .metric-value {{ font-size: 18px; font-weight: 700; color: #f8fafc; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        th, td {{ padding: 10px 12px; text-align: left; border-bottom: 1px solid #334155; font-size: 13px; vertical-align: top; }}
        th {{ background-color: #0f172a; color: #94a3b8; font-weight: 600; text-transform: uppercase; font-size: 11px; }}
        code {{ background: #0f172a; padding: 2px 6px; border-radius: 4px; font-family: monospace; color: #38bdf8; word-break: break-all; }}
        .ioc-list {{ list-style-type: none; padding-left: 0; }}
        .ioc-list li {{ margin-bottom: 6px; }}
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <div>
            <div class="title">ENDPOINT GUARD // FORENSIC INCIDENT REPORT</div>
            <div style="color: #94a3b8; margin-top: 5px;">Incident ID: <b>{html.escape(inc['id'])}</b> &bull; Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}</div>
        </div>
        <div>
            <span class="badge badge-{inc['severity']}">{inc['severity']} SEVERITY</span>
        </div>
    </div>

    <div class="grid">
        <div class="card">
            <h2>Incident Overview</h2>
            <div style="margin-bottom: 12px;"><span class="metric-label">TITLE</span><div class="metric-value">{html.escape(inc['title'])}</div></div>
            <div style="margin-bottom: 12px;"><span class="metric-label">STATUS</span><div class="metric-value">{html.escape(inc['status'])} (Containment: {html.escape(inc['containment_status'])})</div></div>
            <div style="margin-bottom: 12px;"><span class="metric-label">ACTION TAKEN</span><div style="font-size: 14px; color: #10b981;">{html.escape(str(inc.get('containment_action') or 'None'))}</div></div>
            <div><span class="metric-label">MITRE ATT&CK TECHNIQUES</span><div style="margin-top: 6px;">{mitre_badges}</div></div>
        </div>

        <div class="card">
            <h2>Attacker Profile</h2>
            <div style="margin-bottom: 12px;"><span class="metric-label">SOURCE IP</span><div class="metric-value" style="color: #ef4444;">{html.escape(str(inc.get('attacker_ip') or 'N/A'))}</div></div>
            <div style="margin-bottom: 12px;"><span class="metric-label">MAC ADDRESS</span><div class="metric-value">{html.escape(str(attacker.get('mac_address') if attacker else 'N/A'))}</div></div>
            <div style="margin-bottom: 12px;"><span class="metric-label">HOSTNAME</span><div class="metric-value">{html.escape(str(attacker.get('hostname') if attacker else 'N/A'))}</div></div>
            <div><span class="metric-label">AUTO-BLOCKED IN FIREWALL</span><div class="metric-value" style="color: {'#10b981' if attacker and attacker.get('is_blocked') else '#f97316'};">{'YES' if attacker and attacker.get('is_blocked') else 'NO'}</div></div>
        </div>
    </div>

    <div class="card">
        <h2>Indicators of Compromise (IOCs)</h2>
        <div class="grid">
            <div>
                <b style="color: #94a3b8; font-size: 12px;">ATTACKER IPS</b>
                <ul class="ioc-list">
                    {"".join(f"<li><code>{html.escape(ip)}</code></li>" for ip in iocs_ips) if iocs_ips else "<li>None</li>"}
                </ul>
            </div>
            <div>
                <b style="color: #94a3b8; font-size: 12px;">FILE SHA-256 HASHES</b>
                <ul class="ioc-list">
                    {"".join(f"<li><code>{html.escape(h)}</code></li>" for h in iocs_hashes) if iocs_hashes else "<li>None</li>"}
                </ul>
            </div>
            <div>
                <b style="color: #94a3b8; font-size: 12px;">COMMAND LINES EXECUTED</b>
                <ul class="ioc-list">
                    {"".join(f"<li><code>{html.escape(cmd)}</code></li>" for cmd in list(iocs_commands)[:5]) if iocs_commands else "<li>None</li>"}
                </ul>
            </div>
        </div>
    </div>

    <div class="card">
        <h2>Chronological Forensic Event Timeline</h2>
        <table>
            <thead>
                <tr>
                    <th>Timestamp (UTC)</th>
                    <th>Severity</th>
                    <th>Event Type</th>
                    <th>Observed Activity</th>
                    <th>Hash Chain Checksum</th>
                </tr>
            </thead>
            <tbody>
                {timeline_rows}
            </tbody>
        </table>
    </div>

    <div class="card">
        <h2>Captured Evidence Artifacts</h2>
        <table>
            <thead>
                <tr>
                    <th>Timestamp</th>
                    <th>Type</th>
                    <th>File Path</th>
                    <th>Description</th>
                </tr>
            </thead>
            <tbody>
                {evidence_rows if evidence_rows else "<tr><td colspan='4'>No evidence files recorded</td></tr>"}
            </tbody>
        </table>
    </div>

    <div class="card" style="text-align: center; border-color: #10b981;">
        <h2>Forensic Integrity & Tamper-Evident Seal</h2>
        <div style="font-size: 16px; margin: 10px 0;">{verification_badge}</div>
        <div style="color: #94a3b8; font-size: 12px;">Checked {total_checked} sequential records in the cryptographic SHA-256 event ledger.</div>
    </div>
</div>
</body>
</html>
"""
        target = output_path or os.path.join(self.config.incident_dir, f"report_{incident_id}.html")
        os.makedirs(os.path.dirname(os.path.abspath(target)), exist_ok=True)
        with open(target, "w", encoding="utf-8") as f:
            f.write(html_content)
        return target
