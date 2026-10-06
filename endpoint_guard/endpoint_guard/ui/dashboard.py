import html
import os
import threading
from typing import Optional

from flask import Flask, jsonify, redirect, render_template_string, request, send_file, url_for

from ..config import Config
from ..database.manager import DatabaseManager
from ..engine.orchestrator import EndpointGuardOrchestrator


DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Endpoint Guard - Defense SOC</title>
    <style>
        :root {
            --bg-main: #0b0f19;
            --bg-card: #131b2e;
            --border: #1e293b;
            --text-main: #f1f5f9;
            --text-muted: #94a3b8;
            --accent-cyan: #06b6d4;
            --accent-red: #ef4444;
            --accent-green: #10b981;
            --accent-amber: #f59e0b;
        }
        body {
            background-color: var(--bg-main);
            color: var(--text-main);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            margin: 0; padding: 0;
        }
        .navbar {
            background-color: #080c14;
            border-bottom: 1px solid var(--border);
            padding: 14px 28px;
            display: flex; justify-content: space-between; align-items: center;
        }
        .logo { font-size: 18px; font-weight: 800; color: var(--accent-cyan); letter-spacing: 1px; display: flex; align-items: center; gap: 10px; }
        .nav-links a { color: var(--text-muted); text-decoration: none; margin-left: 20px; font-size: 14px; font-weight: 600; }
        .nav-links a:hover, .nav-links a.active { color: var(--accent-cyan); }
        .container { max-width: 1400px; margin: 30px auto; padding: 0 20px; }
        .grid-stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 24px; }
        .stat-card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px; padding: 18px; }
        .stat-title { color: var(--text-muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em; }
        .stat-val { font-size: 26px; font-weight: 700; margin-top: 6px; }
        .card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px; padding: 22px; margin-bottom: 24px; }
        .card-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; }
        .card-title { font-size: 16px; font-weight: 700; color: var(--text-main); text-transform: uppercase; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 10px 12px; text-align: left; border-bottom: 1px solid var(--border); font-size: 13px; }
        th { background: #0c1220; color: var(--text-muted); text-transform: uppercase; font-size: 11px; }
        .badge { padding: 3px 8px; border-radius: 4px; font-weight: 700; font-size: 11px; text-transform: uppercase; }
        .badge-Critical { background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid #ef4444; }
        .badge-High { background: rgba(249, 115, 22, 0.2); color: #fb923c; border: 1px solid #f97316; }
        .badge-Medium { background: rgba(234, 179, 8, 0.2); color: #facc15; border: 1px solid #eab308; }
        .badge-Low { background: rgba(59, 130, 246, 0.2); color: #60a5fa; border: 1px solid #3b82f6; }
        .btn { padding: 6px 14px; border-radius: 4px; border: none; cursor: pointer; font-weight: 600; font-size: 12px; text-decoration: none; display: inline-block; }
        .btn-panic { background: var(--accent-red); color: white; }
        .btn-restore { background: var(--accent-green); color: white; }
        .btn-cyan { background: var(--accent-cyan); color: #080c14; }
        .btn-secondary { background: #1e293b; color: var(--text-main); }
        code { background: #080c14; padding: 2px 6px; border-radius: 4px; color: var(--accent-cyan); font-family: monospace; }
    </style>
</head>
<body>
    <div class="navbar">
        <div class="logo">
            <span style="display:inline-block; width:10px; height:10px; border-radius:50%; background:var(--accent-green);"></span>
            ENDPOINT GUARD // DEFENSE CONSOLE
        </div>
        <div class="nav-links">
            <a href="/" class="active">Overview</a>
            <a href="/attackers">Attackers Directory</a>
            <a href="/quarantine">Quarantine Vault</a>
            <a href="/timeline">Forensic Ledger</a>
        </div>
        <div>
            <form action="/api/panic" method="POST" style="display:inline;">
                <button type="submit" class="btn btn-panic" onclick="return confirm('SEVER ALL EXTERNAL CONNECTIONS IMMEDIATELY?');">⚠ PANIC ISOLATE</button>
            </form>
            <form action="/api/restore_network" method="POST" style="display:inline; margin-left:8px;">
                <button type="submit" class="btn btn-restore">RESTORE NETWORK</button>
            </form>
        </div>
    </div>

    <div class="container">
        <div class="grid-stats">
            <div class="stat-card">
                <div class="stat-title">Active Incidents</div>
                <div class="stat-val" style="color: var(--accent-red);">{{ incidents|length }}</div>
            </div>
            <div class="stat-card">
                <div class="stat-title">Firewall Blocked IPs</div>
                <div class="stat-val" style="color: var(--accent-amber);">{{ blocked_ips|length }}</div>
            </div>
            <div class="stat-card">
                <div class="stat-title">Quarantined Payloads</div>
                <div class="stat-val" style="color: var(--accent-cyan);">{{ quarantined|length }}</div>
            </div>
            <div class="stat-card">
                <div class="stat-title">Cryptographic Integrity</div>
                <div class="stat-val" style="color: {% if chain_valid %}var(--accent-green){% else %}var(--accent-red){% endif %};">
                    {% if chain_valid %}VERIFIED 100%{% else %}TAMPER DETECTED{% endif %}
                </div>
            </div>
        </div>

        <div class="card">
            <div class="card-header">
                <div class="card-title">Live Incidents & Containment Actions</div>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Incident ID</th>
                        <th>Created</th>
                        <th>Severity</th>
                        <th>Attacker IP</th>
                        <th>Title / Description</th>
                        <th>Containment State</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {% for inc in incidents %}
                    <tr>
                        <td><code>{{ inc.id }}</code></td>
                        <td>{{ inc.created_at[:19] }}</td>
                        <td><span class="badge badge-{{ inc.severity }}">{{ inc.severity }}</span></td>
                        <td><b style="color: var(--accent-red);">{{ inc.attacker_ip or 'Local' }}</b></td>
                        <td>
                            <b>{{ inc.title }}</b><br>
                            <small style="color: var(--text-muted);">{{ inc.description }}</small>
                        </td>
                        <td>
                            <span style="color: var(--accent-green); font-weight:600;">{{ inc.containment_status }}</span><br>
                            <small>{{ inc.containment_action or 'Logged' }}</small>
                        </td>
                        <td>
                            <a href="/reports/{{ inc.id }}" target="_blank" class="btn btn-cyan">View Report</a>
                        </td>
                    </tr>
                    {% else %}
                    <tr><td colspan="7" style="text-align: center; color: var(--text-muted);">No active attacks detected. Endpoint is guarded.</td></tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>
"""

ATTACKERS_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Attackers Directory - Endpoint Guard</title>
    <style>
        body { background: #0b0f19; color: #f1f5f9; font-family: sans-serif; margin: 0; padding: 20px; }
        .navbar { margin-bottom: 24px; padding-bottom: 12px; border-bottom: 1px solid #1e293b; display: flex; justify-content: space-between; }
        a { color: #06b6d4; text-decoration: none; margin-right: 16px; font-weight: bold; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 12px; border-bottom: 1px solid #1e293b; text-align: left; }
        th { background: #131b2e; color: #94a3b8; }
        code { background: #1e293b; color: #06b6d4; padding: 2px 6px; border-radius: 4px; }
        .btn { padding: 4px 10px; border-radius: 4px; border: none; cursor: pointer; font-size: 12px; }
        .btn-unblock { background: #10b981; color: white; }
    </style>
</head>
<body>
    <div class="navbar">
        <div><b>ENDPOINT GUARD // ATTACKERS DIRECTORY</b></div>
        <div>
            <a href="/">← Back to Overview</a>
            <a href="/quarantine">Quarantine Vault</a>
            <a href="/timeline">Forensic Ledger</a>
        </div>
    </div>
    <table>
        <thead>
            <tr>
                <th>Attacker IP</th>
                <th>MAC Address</th>
                <th>Hostname</th>
                <th>First Seen</th>
                <th>Last Seen</th>
                <th>Attack Tags</th>
                <th>Risk Score</th>
                <th>Firewall Status</th>
                <th>Action</th>
            </tr>
        </thead>
        <tbody>
            {% for a in attackers %}
            <tr>
                <td><code style="color: #ef4444; font-size: 14px;">{{ a.source_ip }}</code></td>
                <td><code>{{ a.mac_address or 'Unknown' }}</code></td>
                <td>{{ a.hostname or 'Unknown' }}</td>
                <td>{{ a.first_seen[:19] }}</td>
                <td>{{ a.last_seen[:19] }}</td>
                <td>{{ a.attack_tags }}</td>
                <td><b style="color: #ef4444;">{{ a.risk_score }}/100</b></td>
                <td>{% if a.is_blocked %}<span style="color: #ef4444; font-weight:bold;">BLOCKED</span>{% else %}Not Blocked{% endif %}</td>
                <td>
                    {% if a.is_blocked %}
                    <form action="/api/unblock" method="POST" style="display:inline;">
                        <input type="hidden" name="ip" value="{{ a.source_ip }}">
                        <button type="submit" class="btn btn-unblock">Unblock</button>
                    </form>
                    {% endif %}
                </td>
            </tr>
            {% else %}
            <tr><td colspan="9" style="text-align:center; color:#94a3b8;">No external attackers recorded.</td></tr>
            {% endfor %}
        </tbody>
    </table>
</body>
</html>
"""

QUARANTINE_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Quarantine Vault - Endpoint Guard</title>
    <style>
        body { background: #0b0f19; color: #f1f5f9; font-family: sans-serif; margin: 0; padding: 20px; }
        .navbar { margin-bottom: 24px; padding-bottom: 12px; border-bottom: 1px solid #1e293b; display: flex; justify-content: space-between; }
        a { color: #06b6d4; text-decoration: none; margin-right: 16px; font-weight: bold; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 12px; border-bottom: 1px solid #1e293b; text-align: left; }
        th { background: #131b2e; color: #94a3b8; }
        code { background: #1e293b; color: #06b6d4; padding: 2px 6px; border-radius: 4px; word-break: break-all; }
        .btn { padding: 4px 10px; border-radius: 4px; border: none; cursor: pointer; font-size: 12px; background: #06b6d4; color: black; font-weight: bold; }
    </style>
</head>
<body>
    <div class="navbar">
        <div><b>ENDPOINT GUARD // QUARANTINE VAULT</b></div>
        <div>
            <a href="/">← Back to Overview</a>
            <a href="/attackers">Attackers Directory</a>
            <a href="/timeline">Forensic Ledger</a>
        </div>
    </div>
    <table>
        <thead>
            <tr>
                <th>ID</th>
                <th>Original File Path</th>
                <th>SHA-256 Hash</th>
                <th>Size (Bytes)</th>
                <th>Quarantined At</th>
                <th>Reason</th>
                <th>Status</th>
                <th>Action</th>
            </tr>
        </thead>
        <tbody>
            {% for q in items %}
            <tr>
                <td>{{ q.id }}</td>
                <td><code>{{ q.original_path }}</code></td>
                <td><code>{{ q.sha256[:20] }}...</code></td>
                <td>{{ q.file_size }}</td>
                <td>{{ q.quarantined_at[:19] }}</td>
                <td>{{ q.reason }}</td>
                <td>{% if q.restored %}<span style="color: #10b981;">Restored</span>{% else %}<span style="color: #ef4444;">Isolated</span>{% endif %}</td>
                <td>
                    {% if not q.restored %}
                    <form action="/api/restore_file" method="POST" style="display:inline;">
                        <input type="hidden" name="item_id" value="{{ q.id }}">
                        <button type="submit" class="btn" onclick="return confirm('Restore this file to its original location?');">Restore</button>
                    </form>
                    {% endif %}
                </td>
            </tr>
            {% else %}
            <tr><td colspan="8" style="text-align:center; color:#94a3b8;">Quarantine vault is empty.</td></tr>
            {% endfor %}
        </tbody>
    </table>
</body>
</html>
"""

TIMELINE_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Forensic Event Ledger - Endpoint Guard</title>
    <style>
        body { background: #0b0f19; color: #f1f5f9; font-family: sans-serif; margin: 0; padding: 20px; }
        .navbar { margin-bottom: 24px; padding-bottom: 12px; border-bottom: 1px solid #1e293b; display: flex; justify-content: space-between; }
        a { color: #06b6d4; text-decoration: none; margin-right: 16px; font-weight: bold; }
        table { width: 100%; border-collapse: collapse; font-size: 12px; }
        th, td { padding: 8px 10px; border-bottom: 1px solid #1e293b; text-align: left; }
        th { background: #131b2e; color: #94a3b8; }
        code { background: #1e293b; color: #06b6d4; padding: 2px 4px; border-radius: 4px; font-family: monospace; }
    </style>
</head>
<body>
    <div class="navbar">
        <div><b>ENDPOINT GUARD // CRYPTOGRAPHIC SHA-256 EVENT LEDGER</b></div>
        <div>
            <a href="/">← Back to Overview</a>
            <a href="/attackers">Attackers Directory</a>
            <a href="/quarantine">Quarantine Vault</a>
        </div>
    </div>
    <table>
        <thead>
            <tr>
                <th>ID</th>
                <th>Timestamp</th>
                <th>Severity</th>
                <th>Event Type</th>
                <th>Source</th>
                <th>Attacker IP</th>
                <th>PID / Process</th>
                <th>Command / Details</th>
                <th>Previous Hash</th>
                <th>Entry Hash</th>
            </tr>
        </thead>
        <tbody>
            {% for ev in events %}
            <tr>
                <td>{{ ev.id }}</td>
                <td>{{ ev.timestamp[:19] }}</td>
                <td><b>{{ ev.severity }}</b></td>
                <td>{{ ev.event_type }}</td>
                <td>{{ ev.source_module }}</td>
                <td>{{ ev.attacker_ip or '-' }}</td>
                <td>{{ ev.process_name }} ({{ ev.pid or '-' }})</td>
                <td><code>{{ ev.command_line or ev.details }}</code></td>
                <td><code style="color: #94a3b8;">{{ ev.prev_hash[:10] }}...</code></td>
                <td><code style="color: #10b981;">{{ ev.entry_hash[:10] }}...</code></td>
            </tr>
            {% else %}
            <tr><td colspan="10" style="text-align:center; color:#94a3b8;">No events recorded yet.</td></tr>
            {% endfor %}
        </tbody>
    </table>
</body>
</html>
"""


def create_dashboard_app(orchestrator: EndpointGuardOrchestrator) -> Flask:
    app = Flask(__name__)
    app.secret_key = orchestrator.config.get("dashboard", "secret_key", "sec-key")
    db = orchestrator.db

    @app.route("/")
    def index():
        incidents = db.list_incidents()
        blocked_ips = db.list_blocked_ips()
        quarantined = db.list_quarantined_items()
        chain_valid, _, _ = db.verify_hash_chain()
        return render_template_string(
            DASHBOARD_TEMPLATE,
            incidents=incidents,
            blocked_ips=blocked_ips,
            quarantined=quarantined,
            chain_valid=chain_valid
        )

    @app.route("/attackers")
    def attackers():
        atk_list = db.list_attackers()
        return render_template_string(ATTACKERS_TEMPLATE, attackers=atk_list)

    @app.route("/quarantine")
    def quarantine():
        items = db.list_quarantined_items()
        return render_template_string(QUARANTINE_TEMPLATE, items=items)

    @app.route("/timeline")
    def timeline():
        events = db._get_connection().execute("SELECT * FROM events ORDER BY id DESC LIMIT 200").fetchall()
        return render_template_string(TIMELINE_TEMPLATE, events=[dict(e) for e in events])

    @app.route("/reports/<incident_id>")
    def view_report(incident_id: str):
        report_file = os.path.join(orchestrator.config.incident_dir, f"report_{incident_id}.html")
        if not os.path.exists(report_file):
            try:
                report_file = orchestrator.report_generator.generate_html_report(incident_id)
            except Exception as e:
                return f"Error creating report: {e}", 404
        return send_file(report_file, mimetype="text/html")

    @app.route("/api/panic", methods=["POST"])
    def panic():
        orchestrator.response_engine.panic_isolate()
        return redirect(url_for("index"))

    @app.route("/api/restore_network", methods=["POST"])
    def restore_network():
        orchestrator.response_engine.panic_restore()
        return redirect(url_for("index"))

    @app.route("/api/unblock", methods=["POST"])
    def unblock():
        ip = request.form.get("ip")
        if ip:
            orchestrator.response_engine.firewall.unblock_ip(f"EndpointGuard_Block_{ip.replace('.', '_')}")
            db.mark_ip_unblocked(ip)
            db.set_attacker_blocked(ip, False)
        return redirect(url_for("attackers"))

    @app.route("/api/restore_file", methods=["POST"])
    def restore_file():
        item_id = request.form.get("item_id")
        if item_id and item_id.isdigit():
            orchestrator.response_engine.quarantine.restore_file(int(item_id))
        return redirect(url_for("quarantine"))

    return app


class DashboardServer:
    """Runs the Flask web dashboard in a background daemon thread."""

    def __init__(self, orchestrator: EndpointGuardOrchestrator):
        self.orchestrator = orchestrator
        self.app = create_dashboard_app(orchestrator)
        self.host = orchestrator.config.get("dashboard", "host", "127.0.0.1")
        self.port = int(orchestrator.config.get("dashboard", "port", 8443))
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        self._thread = threading.Thread(
            target=lambda: self.app.run(host=self.host, port=self.port, debug=False, use_reloader=False),
            name="DashboardServerThread",
            daemon=True
        )
        self._thread.start()
        print(f"[+] Endpoint Guard Web Console running at: http://{self.host}:{self.port}")
