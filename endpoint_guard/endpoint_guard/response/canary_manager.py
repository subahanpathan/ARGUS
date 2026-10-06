import os
import uuid
from pathlib import Path
from typing import Dict, List, Set

from ..config import Config


DECOY_CONTENTS = {
    "passwords.xlsx": (
        b"PK\x03\x04\x14\x00\x00\x00\x08\x00[CANARY_HONEYPOT_EXCEL_CREDENTIALS]\n"
        b"RootAdmin:Passw0rd2026!#\nDatabaseAdmin:ArgusKey2026$\n"
    ),
    "corporate_secrets.docx": (
        b"PK\x03\x04\x14\x00\x00\x00\x08\x00[CANARY_HONEYPOT_CONFIDENTIAL_ROADMAP]\n"
        b"CONFIDENTIAL 2026: Project Argus Defense Protocols & Master Keys.\n"
    ),
    "vpn_credentials.txt": (
        "--- CORPORATE VPN ACCOUNTS (CONFIDENTIAL) ---\n"
        "Gateway: vpn.internal.corp:443\n"
        "User: admin\n"
        "Token: ARGUS-CANARY-TOKEN-XYZ-2026\n"
    ).encode("utf-8"),
}


class CanaryManager:
    """Deploys and manages decoy honeypot files to tripwire unauthorized file theft."""

    def __init__(self, config: Config):
        self.config = config
        self.canary_paths: Set[str] = set()
        self._deployed_files: Dict[str, str] = {}
        self.deploy_canaries()

    def _resolve_target_dir(self, rel_path: str) -> Path:
        user_profile = os.environ.get("USERPROFILE", "C:\\Users\\Default")
        return Path(user_profile) / rel_path

    def deploy_canaries(self) -> None:
        """Deploys honeypot decoy files defined in config."""
        canary_defs = self.config.get("canary", "files", [])
        for item in canary_defs:
            fname = item.get("name")
            rel_path = item.get("rel_path")
            if not fname or not rel_path:
                continue

            target_path = self._resolve_target_dir(rel_path)
            try:
                target_path.parent.mkdir(parents=True, exist_ok=True)
                if not target_path.exists():
                    payload = DECOY_CONTENTS.get(fname, f"[CANARY_HONEYPOT_{uuid.uuid4().hex}]".encode("utf-8"))
                    target_path.write_bytes(payload)
                self.canary_paths.add(str(target_path).lower())
                self._deployed_files[fname] = str(target_path)
            except Exception as e:
                print(f"[CanaryManager] Note: Could not deploy canary {target_path}: {e}")

    def is_canary_file(self, file_path: str) -> bool:
        if not file_path:
            return False
        clean_path = str(Path(file_path).resolve()).lower()
        # Direct path match or filename match for canary decoys
        if clean_path in self.canary_paths:
            return True
        for cp in self.canary_paths:
            if Path(clean_path).name == Path(cp).name:
                return True
        return False

    def list_canaries(self) -> List[str]:
        return list(self.canary_paths)
