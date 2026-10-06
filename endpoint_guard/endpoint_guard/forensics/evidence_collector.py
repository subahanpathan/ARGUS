import csv
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import psutil

from ..config import Config
from ..database.manager import DatabaseManager
from ..detection.rules_base import DetectionAlert
from ..monitors.network_monitor import resolve_hostname, resolve_mac_address


class EvidenceCollector:
    """Captures network, process, socket, and memory snapshots upon alert detection."""

    def __init__(self, config: Config, db: DatabaseManager):
        self.config = config
        self.db = db
        self.incident_dir = Path(config.incident_dir)
        self.incident_dir.mkdir(parents=True, exist_ok=True)

    def capture_incident_package(self, incident_id: str, alert: DetectionAlert) -> str:
        """Captures complete forensic evidence package into incidents folder."""
        date_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        ip_label = (alert.attacker_ip or "local_host").replace(".", "_").replace(":", "_")
        folder_name = f"{date_str}_{ip_label}_{incident_id[:8]}"
        out_dir = self.incident_dir / folder_name
        out_dir.mkdir(parents=True, exist_ok=True)

        # 1. Attacker LAN/Network enrichment
        mac_addr = resolve_mac_address(alert.attacker_ip) if alert.attacker_ip else None
        hostname = resolve_hostname(alert.attacker_ip) if alert.attacker_ip else None

        if alert.attacker_ip:
            self.db.upsert_attacker({
                "source_ip": alert.attacker_ip,
                "mac_address": mac_addr,
                "hostname": hostname,
            })

        # 2. Process Snapshot
        proc_snap = self._capture_processes()
        proc_file = out_dir / "process_snapshot.json"
        proc_file.write_text(json.dumps(proc_snap, indent=2), encoding="utf-8")
        self.db.record_evidence({
            "incident_id": incident_id,
            "evidence_type": "process_snapshot",
            "file_path": str(proc_file),
            "file_hash_sha256": "N/A",
            "description": f"Process table snapshot at alert time ({len(proc_snap)} processes)",
        })

        # 3. Network Connections Snapshot
        net_snap = self._capture_sockets()
        net_file = out_dir / "network_snapshot.json"
        net_file.write_text(json.dumps(net_snap, indent=2), encoding="utf-8")
        self.db.record_evidence({
            "incident_id": incident_id,
            "evidence_type": "network_snapshot",
            "file_path": str(net_file),
            "file_hash_sha256": "N/A",
            "description": f"Active network sockets at alert time ({len(net_snap)} sockets)",
        })

        # 4. Optional Short PCAP Capture (Scapy)
        pcap_path = self._capture_pcap(alert.attacker_ip, out_dir)
        if pcap_path:
            self.db.record_evidence({
                "incident_id": incident_id,
                "evidence_type": "pcap",
                "file_path": str(pcap_path),
                "file_hash_sha256": "N/A",
                "description": f"Targeted packet capture of attacker traffic",
            })

        # 5. Export JSON & CSV incident dumps
        json_file = out_dir / "incident_export.json"
        csv_file = out_dir / "events_timeline.csv"
        try:
            self.db.export_incident_json(incident_id, str(json_file))
            self.db.export_incident_csv(incident_id, str(csv_file))
        except Exception as e:
            print(f"[EvidenceCollector] Export error: {e}")

        return str(out_dir)

    def _capture_processes(self) -> List[Dict[str, Any]]:
        snapshot = []
        for p in psutil.process_iter(["pid", "name", "cmdline", "ppid", "username", "status"]):
            try:
                info = p.info
                snapshot.append({
                    "pid": info.get("pid"),
                    "name": info.get("name"),
                    "cmdline": " ".join(info.get("cmdline") or []),
                    "ppid": info.get("ppid"),
                    "username": info.get("username"),
                    "status": info.get("status"),
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return snapshot

    def _capture_sockets(self) -> List[Dict[str, Any]]:
        sockets = []
        try:
            conns = psutil.net_connections(kind="inet")
            for c in conns:
                sockets.append({
                    "pid": c.pid,
                    "local_ip": c.laddr.ip if c.laddr else None,
                    "local_port": c.laddr.port if c.laddr else None,
                    "remote_ip": c.raddr.ip if c.raddr else None,
                    "remote_port": c.raddr.port if c.raddr else None,
                    "status": c.status,
                    "type": "TCP" if c.type == 1 else "UDP",
                })
        except Exception:
            pass
        return sockets

    def _capture_pcap(self, target_ip: Optional[str], out_dir: Path) -> Optional[Path]:
        """Attempts a quick 5-packet passive capture of traffic to/from attacker IP using scapy."""
        if not target_ip:
            return None
        try:
            from scapy.all import sniff, wrpcap
            pcap_file = out_dir / f"traffic_{target_ip.replace('.', '_')}.pcap"
            # Sniff at most 10 packets or timeout after 2 seconds
            packets = sniff(filter=f"host {target_ip}", count=10, timeout=2.0)
            if packets:
                wrpcap(str(pcap_file), packets)
                return pcap_file
        except Exception:
            pass
        return None
