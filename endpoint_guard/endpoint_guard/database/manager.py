import csv
import hashlib
import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .schema import SCHEMA_SQL

GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"


def current_iso_time() -> str:
    return datetime.now(timezone.utc).isoformat()


class DatabaseManager:
    """Thread-safe SQLite manager for Endpoint Guard with SHA-256 hash chaining."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        self._lock = threading.Lock()
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=30.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._lock:
            conn = self._get_connection()
            try:
                conn.executescript(SCHEMA_SQL)
                conn.commit()
            finally:
                conn.close()

    # =========================================================================
    # HASH-CHAINED EVENT LOGGING
    # =========================================================================

    def _compute_entry_hash(self, prev_hash: str, timestamp: str, event_type: str,
                            source_module: str, severity: str, details_str: str) -> str:
        payload = f"{prev_hash}|{timestamp}|{event_type}|{source_module}|{severity}|{details_str}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def record_event(self, event: Dict[str, Any]) -> int:
        """Appends an event to the ledger with tamper-evident cryptographic hash chaining."""
        with self._lock:
            conn = self._get_connection()
            try:
                # Find last entry_hash
                cursor = conn.cursor()
                cursor.execute("SELECT entry_hash FROM events ORDER BY id DESC LIMIT 1")
                row = cursor.fetchone()
                prev_hash = row["entry_hash"] if row else GENESIS_HASH

                timestamp = event.get("timestamp") or current_iso_time()
                event_type = event.get("event_type", "generic")
                source_module = event.get("source_module", "system")
                severity = event.get("severity", "Low")
                details = event.get("details", {})
                details_str = json.dumps(details, sort_keys=True) if isinstance(details, dict) else str(details)

                entry_hash = self._compute_entry_hash(
                    prev_hash, timestamp, event_type, source_module, severity, details_str
                )

                cursor.execute("""
                    INSERT INTO events (
                        incident_id, timestamp, event_type, source_module, severity,
                        attacker_ip, pid, process_name, command_line, parent_pid,
                        parent_process_name, user_account, remote_port, local_port,
                        protocol, file_path, file_hash_sha256, details, prev_hash, entry_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    event.get("incident_id"),
                    timestamp,
                    event_type,
                    source_module,
                    severity,
                    event.get("attacker_ip"),
                    event.get("pid"),
                    event.get("process_name"),
                    event.get("command_line"),
                    event.get("parent_pid"),
                    event.get("parent_process_name"),
                    event.get("user_account"),
                    event.get("remote_port"),
                    event.get("local_port"),
                    event.get("protocol"),
                    event.get("file_path"),
                    event.get("file_hash_sha256"),
                    details_str,
                    prev_hash,
                    entry_hash
                ))
                conn.commit()
                return cursor.lastrowid
            finally:
                conn.close()

    def verify_hash_chain(self) -> Tuple[bool, Optional[int], int]:
        """Verifies the SHA-256 chain of the events table. Returns (is_valid, broken_at_id, total_checked)."""
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT id, timestamp, event_type, source_module, severity, details, prev_hash, entry_hash
                    FROM events ORDER BY id ASC
                """)
                rows = cursor.fetchall()
                if not rows:
                    return (True, None, 0)

                expected_prev = GENESIS_HASH
                for row in rows:
                    row_id = row["id"]
                    if row["prev_hash"] != expected_prev:
                        return (False, row_id, len(rows))

                    recomputed = self._compute_entry_hash(
                        row["prev_hash"],
                        row["timestamp"],
                        row["event_type"],
                        row["source_module"],
                        row["severity"],
                        row["details"] or ""
                    )
                    if recomputed != row["entry_hash"]:
                        return (False, row_id, len(rows))

                    expected_prev = row["entry_hash"]

                return (True, None, len(rows))
            finally:
                conn.close()

    # =========================================================================
    # ATTACKER PROFILES
    # =========================================================================

    def upsert_attacker(self, data: Dict[str, Any]) -> None:
        """Creates or updates an attacker profile based on source_ip."""
        with self._lock:
            conn = self._get_connection()
            try:
                ip = data["source_ip"]
                now = current_iso_time()
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM attackers WHERE source_ip = ?", (ip,))
                existing = cursor.fetchone()

                ports_json = json.dumps(list(set(data.get("ports", []))))
                protocols_json = json.dumps(list(set(data.get("protocols", ["TCP"]))))
                tags_json = json.dumps(list(set(data.get("attack_tags", []))))

                if existing:
                    # Merge ports and tags
                    old_ports = set(json.loads(existing["ports_used"] or "[]"))
                    new_ports = old_ports.union(set(data.get("ports", [])))

                    old_tags = set(json.loads(existing["attack_tags"] or "[]"))
                    new_tags = old_tags.union(set(data.get("attack_tags", [])))

                    total_conn = existing["total_connections"] + int(data.get("connection_increment", 1))
                    sent = existing["bytes_sent"] + int(data.get("bytes_sent", 0))
                    recv = existing["bytes_received"] + int(data.get("bytes_received", 0))
                    risk = max(existing["risk_score"], int(data.get("risk_score", existing["risk_score"])))

                    cursor.execute("""
                        UPDATE attackers SET
                            last_seen = ?,
                            ports_used = ?,
                            protocols = ?,
                            connection_direction = COALESCE(?, connection_direction),
                            total_connections = ?,
                            bytes_sent = ?,
                            bytes_received = ?,
                            attack_tags = ?,
                            risk_score = ?,
                            mac_address = COALESCE(?, mac_address),
                            hostname = COALESCE(?, hostname)
                        WHERE source_ip = ?
                    """, (
                        now,
                        json.dumps(list(new_ports)),
                        protocols_json,
                        data.get("connection_direction"),
                        total_conn,
                        sent,
                        recv,
                        json.dumps(list(new_tags)),
                        risk,
                        data.get("mac_address"),
                        data.get("hostname"),
                        ip
                    ))
                else:
                    cursor.execute("""
                        INSERT INTO attackers (
                            source_ip, mac_address, hostname, first_seen, last_seen,
                            ports_used, protocols, connection_direction, total_connections,
                            bytes_sent, bytes_received, attack_tags, risk_score
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        ip,
                        data.get("mac_address"),
                        data.get("hostname"),
                        data.get("first_seen", now),
                        now,
                        ports_json,
                        protocols_json,
                        data.get("connection_direction", "inbound"),
                        data.get("total_connections", 1),
                        data.get("bytes_sent", 0),
                        data.get("bytes_received", 0),
                        tags_json,
                        data.get("risk_score", 10)
                    ))
                conn.commit()
            finally:
                conn.close()

    def get_attacker(self, ip: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM attackers WHERE source_ip = ?", (ip,))
                row = cursor.fetchone()
                return dict(row) if row else None
            finally:
                conn.close()

    def list_attackers(self) -> List[Dict[str, Any]]:
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM attackers ORDER BY last_seen DESC")
                return [dict(r) for r in cursor.fetchall()]
            finally:
                conn.close()

    def set_attacker_blocked(self, ip: str, is_blocked: bool, rule_name: str = "") -> None:
        with self._lock:
            conn = self._get_connection()
            try:
                now = current_iso_time() if is_blocked else None
                conn.execute("""
                    UPDATE attackers SET
                        is_blocked = ?,
                        blocked_at = ?,
                        block_rule_name = ?
                    WHERE source_ip = ?
                """, (1 if is_blocked else 0, now, rule_name, ip))
                conn.commit()
            finally:
                conn.close()

    # =========================================================================
    # INCIDENTS
    # =========================================================================

    def create_incident(self, data: Dict[str, Any]) -> str:
        with self._lock:
            conn = self._get_connection()
            try:
                now = current_iso_time()
                inc_id = data.get("id") or f"INC-{datetime.now().strftime('%Y%m%d%H%M%S')}-{os.urandom(2).hex()}"
                mitre_json = json.dumps(data.get("mitre_techniques", []))

                conn.execute("""
                    INSERT INTO incidents (
                        id, created_at, updated_at, attacker_ip, title, description,
                        severity, status, risk_score, mitre_techniques, containment_status,
                        containment_action, contained_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    inc_id,
                    data.get("created_at", now),
                    now,
                    data.get("attacker_ip"),
                    data.get("title", "Suspicious Host Activity"),
                    data.get("description", ""),
                    data.get("severity", "Medium"),
                    data.get("status", "Active"),
                    data.get("risk_score", 50),
                    mitre_json,
                    data.get("containment_status", "None"),
                    data.get("containment_action"),
                    data.get("contained_at")
                ))
                conn.commit()
                return inc_id
            finally:
                conn.close()

    def update_incident_containment(self, incident_id: str, status: str, action: str) -> None:
        with self._lock:
            conn = self._get_connection()
            try:
                now = current_iso_time()
                conn.execute("""
                    UPDATE incidents SET
                        updated_at = ?,
                        containment_status = ?,
                        containment_action = ?,
                        contained_at = ?,
                        status = 'Contained'
                    WHERE id = ?
                """, (now, status, action, now, incident_id))
                conn.commit()
            finally:
                conn.close()

    def get_incident(self, incident_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,))
                row = cursor.fetchone()
                return dict(row) if row else None
            finally:
                conn.close()

    def list_incidents(self) -> List[Dict[str, Any]]:
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM incidents ORDER BY created_at DESC")
                return [dict(r) for r in cursor.fetchall()]
            finally:
                conn.close()

    def get_incident_events(self, incident_id: str) -> List[Dict[str, Any]]:
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM events WHERE incident_id = ? ORDER BY id ASC", (incident_id,))
                return [dict(r) for r in cursor.fetchall()]
            finally:
                conn.close()

    # =========================================================================
    # EVIDENCE ARTIFACTS
    # =========================================================================

    def record_evidence(self, data: Dict[str, Any]) -> int:
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO evidence (
                        incident_id, timestamp, evidence_type, file_path,
                        file_hash_sha256, file_size_bytes, description, metadata
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    data["incident_id"],
                    data.get("timestamp", current_iso_time()),
                    data.get("evidence_type", "snapshot"),
                    data.get("file_path", ""),
                    data.get("file_hash_sha256", ""),
                    data.get("file_size_bytes", 0),
                    data.get("description", ""),
                    json.dumps(data.get("metadata", {}))
                ))
                conn.commit()
                return cursor.lastrowid
            finally:
                conn.close()

    def list_evidence(self, incident_id: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                if incident_id:
                    cursor.execute("SELECT * FROM evidence WHERE incident_id = ? ORDER BY id ASC", (incident_id,))
                else:
                    cursor.execute("SELECT * FROM evidence ORDER BY id DESC")
                return [dict(r) for r in cursor.fetchall()]
            finally:
                conn.close()

    # =========================================================================
    # BLOCKED IPS & QUARANTINE
    # =========================================================================

    def record_blocked_ip(self, ip: str, rule_name: str, reason: str = "", incident_id: Optional[str] = None) -> None:
        with self._lock:
            conn = self._get_connection()
            try:
                conn.execute("""
                    INSERT INTO blocked_ips (ip_address, blocked_at, rule_name, reason, incident_id, active)
                    VALUES (?, ?, ?, ?, ?, 1)
                    ON CONFLICT(ip_address) DO UPDATE SET
                        active = 1,
                        blocked_at = excluded.blocked_at,
                        rule_name = excluded.rule_name,
                        reason = excluded.reason
                """, (ip, current_iso_time(), rule_name, reason, incident_id))
                conn.commit()
            finally:
                conn.close()

    def mark_ip_unblocked(self, ip: str) -> None:
        with self._lock:
            conn = self._get_connection()
            try:
                conn.execute("""
                    UPDATE blocked_ips SET active = 0, unblocked_at = ? WHERE ip_address = ?
                """, (current_iso_time(), ip))
                conn.commit()
            finally:
                conn.close()

    def list_blocked_ips(self, active_only: bool = True) -> List[Dict[str, Any]]:
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                if active_only:
                    cursor.execute("SELECT * FROM blocked_ips WHERE active = 1 ORDER BY id DESC")
                else:
                    cursor.execute("SELECT * FROM blocked_ips ORDER BY id DESC")
                return [dict(r) for r in cursor.fetchall()]
            finally:
                conn.close()

    def record_quarantined_item(self, item: Dict[str, Any]) -> int:
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO quarantined_items (
                        original_path, quarantine_path, sha256, file_size,
                        quarantined_at, reason, incident_id, restored
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, 0)
                """, (
                    item["original_path"],
                    item["quarantine_path"],
                    item["sha256"],
                    item.get("file_size", 0),
                    current_iso_time(),
                    item.get("reason", "Malicious or untrusted file"),
                    item.get("incident_id")
                ))
                conn.commit()
                return cursor.lastrowid
            finally:
                conn.close()

    def mark_item_restored(self, item_id: int) -> None:
        with self._lock:
            conn = self._get_connection()
            try:
                conn.execute("""
                    UPDATE quarantined_items SET restored = 1, restored_at = ? WHERE id = ?
                """, (current_iso_time(), item_id))
                conn.commit()
            finally:
                conn.close()

    def list_quarantined_items(self) -> List[Dict[str, Any]]:
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM quarantined_items ORDER BY id DESC")
                return [dict(r) for r in cursor.fetchall()]
            finally:
                conn.close()

    # =========================================================================
    # EXPORT HELPERS (JSON & CSV)
    # =========================================================================

    def export_incident_json(self, incident_id: str, out_path: str) -> None:
        inc = self.get_incident(incident_id)
        if not inc:
            raise ValueError(f"Incident {incident_id} not found")
        events = self.get_incident_events(incident_id)
        evidence = self.list_evidence(incident_id)
        attacker = self.get_attacker(inc.get("attacker_ip", "")) if inc.get("attacker_ip") else None

        data = {
            "incident": inc,
            "attacker": attacker,
            "events": events,
            "evidence": evidence,
            "exported_at": current_iso_time(),
        }
        os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def export_incident_csv(self, incident_id: str, out_path: str) -> None:
        events = self.get_incident_events(incident_id)
        os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
        with open(out_path, "w", newline="", encoding="utf-8") as f:
            if not events:
                f.write("No events recorded for this incident\n")
                return
            fieldnames = list(events[0].keys())
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for ev in events:
                writer.writerow(ev)
