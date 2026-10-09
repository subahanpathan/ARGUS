"""
Synthetic sensitive file management for ARGUS lab attack simulation.

Creates, tracks, hashes and cleans up synthetic files that look like
real sensitive data but contain clearly labelled dummy content.
Never reads or touches real user files.
"""

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path


class SyntheticFileManager:
    """
    Manages synthetic (fake) sensitive files used exclusively within the
    ARGUS lab directory. All file contents are clearly labelled with an
    ARGUS_LAB_SYNTHETIC header so they can never be mistaken for real data.
    """

    # Fixed filenames for reproducible lab runs.
    _SYNTHETIC_FILES: list[str] = [
        "lab_credentials.txt",
        "lab_pii_records.csv",
        "lab_financial_data.xlsx",
        "lab_corporate_docs.docx",
    ]

    def __init__(self, lab_dir: str) -> None:
        """
        Initialise the manager.

        Args:
            lab_dir: Absolute path to the directory where synthetic files will
                     be written. Created automatically if it does not exist.
        """
        self._lab_dir = Path(lab_dir)
        self._lab_dir.mkdir(parents=True, exist_ok=True)
        # Baseline hashes populated by record_baseline().
        self._baseline: dict[str, str] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def create_synthetic_files(self) -> dict[str, str]:
        """
        Write synthetic files to lab_dir.

        Each file contains an ARGUS_LAB_SYNTHETIC marker so it can be
        distinguished from real sensitive data by any consumer.

        Returns:
            Mapping of filename -> SHA-256 hex digest.
        """
        timestamp = datetime.now(tz=timezone.utc).isoformat()
        results: dict[str, str] = {}

        # --- lab_credentials.txt ---
        creds_content = (
            "ARGUS_LAB_SYNTHETIC - NOT REAL\n"
            "Generated: {ts}\n"
            "admin:TestPass123\n"
            "root:LabSecret456\n"
            "service_account:DummyToken789\n"
        ).format(ts=timestamp)
        results["lab_credentials.txt"] = self._write_text(
            "lab_credentials.txt", creds_content
        )

        # --- lab_pii_records.csv ---
        pii_content = (
            "ARGUS_LAB_SYNTHETIC - NOT REAL\n"
            "Name,DOB,Aadhaar,Email\n"
            "John Doe,1990-01-01,XXXX-XXXX-0001,jdoe@lab.invalid\n"
            "Jane Doe,1985-06-15,XXXX-XXXX-0002,janedoe@lab.invalid\n"
        ).format()
        results["lab_pii_records.csv"] = self._write_text(
            "lab_pii_records.csv", pii_content
        )

        # --- lab_financial_data.xlsx (binary placeholder) ---
        xlsx_marker = b"ARGUS_LAB_SYNTHETIC - NOT REAL - XLSX PLACEHOLDER\x00" + timestamp.encode()
        results["lab_financial_data.xlsx"] = self._write_bytes(
            "lab_financial_data.xlsx", xlsx_marker
        )

        # --- lab_corporate_docs.docx (binary placeholder) ---
        docx_marker = b"ARGUS_LAB_SYNTHETIC - NOT REAL - DOCX PLACEHOLDER\x00" + timestamp.encode()
        results["lab_corporate_docs.docx"] = self._write_bytes(
            "lab_corporate_docs.docx", docx_marker
        )

        return results

    def record_baseline(self) -> dict[str, str]:
        """
        SHA-256 hash every synthetic file that currently exists in lab_dir.

        Returns:
            Mapping of absolute path -> SHA-256 hex digest.  Stored
            internally so check_integrity() can compare against it later.
        """
        baseline: dict[str, str] = {}
        for name in self._SYNTHETIC_FILES:
            path = self._lab_dir / name
            if path.exists():
                baseline[str(path)] = self._sha256(path)
        self._baseline = baseline
        return dict(baseline)

    def check_integrity(self) -> list[dict]:
        """
        Compare current on-disk state to the recorded baseline.

        Returns:
            List of dicts, one per file that appears in either the baseline
            or the current directory scan.  Each dict contains:
              - path           : absolute path string
              - status         : "unchanged" | "modified" | "deleted" | "added"
              - baseline_hash  : hash at baseline time (or None)
              - current_hash   : hash now (or None if deleted)
        """
        results: list[dict] = []

        # Paths known from baseline.
        known_paths: set[str] = set(self._baseline.keys())

        # Paths present on disk now.
        current_hashes: dict[str, str] = {}
        for name in self._SYNTHETIC_FILES:
            path = self._lab_dir / name
            if path.exists():
                current_hashes[str(path)] = self._sha256(path)

        all_paths = known_paths | set(current_hashes.keys())

        for path_str in sorted(all_paths):
            baseline_hash = self._baseline.get(path_str)
            current_hash = current_hashes.get(path_str)

            if baseline_hash is not None and current_hash is not None:
                status = "unchanged" if baseline_hash == current_hash else "modified"
            elif baseline_hash is not None and current_hash is None:
                status = "deleted"
            else:
                status = "added"

            results.append(
                {
                    "path": path_str,
                    "status": status,
                    "baseline_hash": baseline_hash,
                    "current_hash": current_hash,
                }
            )

        return results

    def cleanup(self) -> None:
        """Remove all synthetic files from lab_dir."""
        for name in self._SYNTHETIC_FILES:
            path = self._lab_dir / name
            if path.exists():
                path.unlink()

    def get_file_paths(self) -> list[str]:
        """Return absolute paths of all synthetic files that currently exist."""
        return [
            str(self._lab_dir / name)
            for name in self._SYNTHETIC_FILES
            if (self._lab_dir / name).exists()
        ]

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _write_text(self, filename: str, content: str) -> str:
        """Write *content* to filename and return its SHA-256 hex digest."""
        path = self._lab_dir / filename
        path.write_text(content, encoding="utf-8")
        return self._sha256(path)

    def _write_bytes(self, filename: str, content: bytes) -> str:
        """Write binary *content* to filename and return its SHA-256 hex digest."""
        path = self._lab_dir / filename
        path.write_bytes(content)
        return self._sha256(path)

    @staticmethod
    def _sha256(path: Path) -> str:
        """Return the SHA-256 hex digest of *path*."""
        h = hashlib.sha256()
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
