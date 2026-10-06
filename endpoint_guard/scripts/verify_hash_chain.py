import argparse
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))

from endpoint_guard.config import Config
from endpoint_guard.database.manager import DatabaseManager
from endpoint_guard.forensics.hash_chain import HashChainVerifier


def main():
    parser = argparse.ArgumentParser(description="Endpoint Guard - Hash Chain Tamper Verification CLI")
    parser.add_argument("--db", default=None, help="Path to endpoint_guard.db")
    args = parser.parse_args()

    config = Config()
    db_path = args.db or config.db_path
    print(f"[*] Auditing SQLite Event Ledger: {db_path}")

    if not Path(db_path).exists():
        print(f"[-] Database file not found at {db_path}")
        sys.exit(1)

    db = DatabaseManager(db_path)
    verifier = HashChainVerifier(db)
    result = verifier.audit()

    print("=" * 60)
    print("ENDPOINT GUARD FORENSIC INTEGRITY AUDIT")
    print("=" * 60)
    print(f"Status:               {result['status']}")
    print(f"Total Events Checked: {result['total_events_checked']}")
    print(f"Tamper Detected:      {result['tamper_detected']}")
    if result['broken_at_event_id']:
        print(f"Broken at Event ID:   {result['broken_at_event_id']}")
    print("=" * 60)

    if result["is_valid"]:
        print("[+] SUCCESS: Hash chain is fully verified and mathematically intact.")
        sys.exit(0)
    else:
        print("[!] ALERT: Hash chain tampering or corruption detected!")
        sys.exit(2)


if __name__ == "__main__":
    main()
