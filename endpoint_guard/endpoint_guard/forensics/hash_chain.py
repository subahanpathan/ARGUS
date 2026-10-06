from typing import Dict, List, Optional, Tuple
from ..database.manager import DatabaseManager


class HashChainVerifier:
    """Verifies cryptographic SHA-256 event chaining for forensic integrity audits."""

    def __init__(self, db: DatabaseManager):
        self.db = db

    def audit(self) -> Dict[str, any]:
        is_valid, broken_id, total = self.db.verify_hash_chain()
        return {
            "is_valid": is_valid,
            "total_events_checked": total,
            "broken_at_event_id": broken_id,
            "tamper_detected": not is_valid,
            "status": "PASS" if is_valid else "FAIL_TAMPERED",
        }
