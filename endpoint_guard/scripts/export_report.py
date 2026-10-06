import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from endpoint_guard.config import Config
from endpoint_guard.database.manager import DatabaseManager
from endpoint_guard.forensics.report_generator import ReportGenerator


def main():
    parser = argparse.ArgumentParser(description="Endpoint Guard - Incident Report Exporter CLI")
    parser.add_argument("incident_id", help="Incident ID to export (e.g. INC-20261006...)")
    parser.add_argument("--out", default=None, help="Output HTML file path")
    args = parser.parse_args()

    config = Config()
    db = DatabaseManager(config.db_path)
    generator = ReportGenerator(config, db)

    try:
        report_file = generator.generate_html_report(args.incident_id, args.out)
        print(f"[+] Forensic Incident Report generated successfully:")
        print(f"    {report_file}")
    except Exception as e:
        print(f"[-] Error generating report: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
