"""
SQLite Database Schema for Endpoint Guard.
Tables:
  - attackers: Profiles per source IP (MAC, hostname, ports, bytes, risk score, blocked state)
  - incidents: Correlated attack incidents with severity, status, and containment status
  - events: Fine-grained security events with cryptographic previous_hash chaining
  - evidence: Forensic artifacts (quarantined files, PCAPs, process snapshots, screenshots)
  - blocked_ips: Active firewall blocks and audit metadata
  - audit_log: System administrative and containment actions
"""

SCHEMA_SQL = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS attackers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_ip TEXT UNIQUE NOT NULL,
    mac_address TEXT,
    hostname TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    ports_used TEXT, -- JSON array of ports
    protocols TEXT,  -- JSON array of protocols (TCP/UDP)
    connection_direction TEXT DEFAULT 'inbound', -- inbound, outbound, both
    total_connections INTEGER DEFAULT 1,
    bytes_sent INTEGER DEFAULT 0,
    bytes_received INTEGER DEFAULT 0,
    attack_tags TEXT, -- JSON array of tags (e.g. ['port_scan', 'reverse_shell'])
    risk_score INTEGER DEFAULT 0, -- 0 to 100
    is_blocked INTEGER DEFAULT 0, -- 0 or 1
    blocked_at TEXT,
    block_rule_name TEXT,
    notes TEXT
);

CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY, -- e.g. INC-20261006-001
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    attacker_ip TEXT,
    title TEXT NOT NULL,
    description TEXT,
    severity TEXT NOT NULL, -- Low, Medium, High, Critical
    status TEXT NOT NULL DEFAULT 'Active', -- Active, Contained, Closed
    risk_score INTEGER DEFAULT 0,
    mitre_techniques TEXT, -- JSON array
    containment_status TEXT DEFAULT 'None', -- None, Partially Contained, Fully Contained
    containment_action TEXT, -- e.g. "Killed PID 4120, Blocked IP 192.168.1.50"
    contained_at TEXT,
    FOREIGN KEY(attacker_ip) REFERENCES attackers(source_ip) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT,
    timestamp TEXT NOT NULL,
    event_type TEXT NOT NULL, -- network_connection, process_spawn, file_touch, peripheral_access, detection, response_action
    source_module TEXT NOT NULL, -- network, process, file, peripheral, orchestrator
    severity TEXT NOT NULL, -- Low, Medium, High, Critical
    attacker_ip TEXT,
    pid INTEGER,
    process_name TEXT,
    command_line TEXT,
    parent_pid INTEGER,
    parent_process_name TEXT,
    user_account TEXT,
    remote_port INTEGER,
    local_port INTEGER,
    protocol TEXT,
    file_path TEXT,
    file_hash_sha256 TEXT,
    details TEXT, -- JSON string with extra metadata
    prev_hash TEXT NOT NULL, -- SHA-256 hash of previous row in chain
    entry_hash TEXT NOT NULL, -- SHA-256 hash of this row including prev_hash
    FOREIGN KEY(incident_id) REFERENCES incidents(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    evidence_type TEXT NOT NULL, -- pcap, process_snapshot, quarantined_file, netstat_dump, screenshot
    file_path TEXT NOT NULL,
    file_hash_sha256 TEXT NOT NULL,
    file_size_bytes INTEGER,
    description TEXT,
    metadata TEXT, -- JSON string
    FOREIGN KEY(incident_id) REFERENCES incidents(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS blocked_ips (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT UNIQUE NOT NULL,
    blocked_at TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    reason TEXT,
    incident_id TEXT,
    active INTEGER DEFAULT 1,
    unblocked_at TEXT
);

CREATE TABLE IF NOT EXISTS quarantined_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    original_path TEXT NOT NULL,
    quarantine_path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    quarantined_at TEXT NOT NULL,
    reason TEXT,
    incident_id TEXT,
    restored INTEGER DEFAULT 0,
    restored_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_attackers_ip ON attackers(source_ip);
CREATE INDEX IF NOT EXISTS idx_incidents_attacker ON incidents(attacker_ip);
CREATE INDEX IF NOT EXISTS idx_events_incident ON events(incident_id);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_entry_hash ON events(entry_hash);
CREATE INDEX IF NOT EXISTS idx_evidence_incident ON evidence(incident_id);
CREATE INDEX IF NOT EXISTS idx_blocked_ip ON blocked_ips(ip_address);
"""
