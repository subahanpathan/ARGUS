import hashlib
import json
import os
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from ..config import Config
from ..database.manager import DatabaseManager


def calculate_sha256(path: str) -> str:
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


class QuarantineManager:
    """Safely isolates malicious files in an ACL-restricted quarantine folder with restore capability."""

    def __init__(self, config: Config, db: DatabaseManager):
        self.config = config
        self.db = db
        self.quarantine_dir = Path(config.quarantine_dir)
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)

    def quarantine_file(self, file_path: str, reason: str = "Hostile payload",
                        incident_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        src = Path(file_path)
        if not src.exists() or not src.is_file():
            return None

        if self.config.dry_run:
            print(f"[QuarantineManager] [DRY RUN] Would quarantine: {file_path}")
            return {"original_path": file_path, "quarantine_path": "DRY_RUN", "sha256": "DRY_RUN"}

        try:
            sha256 = calculate_sha256(str(src))
            file_size = src.stat().st_size
            timestamp = datetime.now(timezone.utc).isoformat()

            # Unique quarantine destination
            safe_name = f"{sha256[:16]}_{src.name}.quarantine"
            dst = self.quarantine_dir / safe_name

            # Move file
            shutil.move(str(src), str(dst))

            # Set file as hidden and read-only via Windows attrib
            try:
                subprocess.run(["attrib", "+r", "+h", str(dst)], capture_output=True, timeout=5)
            except Exception:
                pass

            # Write forensic metadata file
            meta_path = dst.with_suffix(".json")
            metadata = {
                "original_path": str(src.resolve()),
                "quarantine_path": str(dst.resolve()),
                "sha256": sha256,
                "file_size": file_size,
                "quarantined_at": timestamp,
                "reason": reason,
                "incident_id": incident_id,
            }
            meta_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

            # Record in SQLite database
            self.db.record_quarantined_item(metadata)
            return metadata
        except Exception as e:
            print(f"[QuarantineManager] Failed to quarantine {file_path}: {e}")
            return None

    def restore_file(self, item_id: int, target_dir: Optional[str] = None) -> bool:
        """Restores a quarantined file back to its original location or a recovery folder."""
        items = self.db.list_quarantined_items()
        item = next((i for i in items if i["id"] == item_id), None)
        if not item:
            return False

        q_path = Path(item["quarantine_path"])
        if not q_path.exists():
            return False

        try:
            # Remove read-only & hidden attributes
            subprocess.run(["attrib", "-r", "-h", str(q_path)], capture_output=True, timeout=5)

            dest_path = Path(target_dir) / Path(item["original_path"]).name if target_dir else Path(item["original_path"])
            dest_path.parent.mkdir(parents=True, exist_ok=True)

            shutil.move(str(q_path), str(dest_path))

            # Clean metadata
            meta_path = q_path.with_suffix(".json")
            if meta_path.exists():
                meta_path.unlink()

            self.db.mark_item_restored(item_id)
            return True
        except Exception as e:
            print(f"[QuarantineManager] Restore error: {e}")
            return False
