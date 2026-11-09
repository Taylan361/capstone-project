import argparse
import json
from pathlib import Path

from .scanner import scan_project


def main() -> int:
    parser = argparse.ArgumentParser(description="Run read-only security checks on a project directory.")
    parser.add_argument("project", type=Path, help="Path to the project directory to scan")
    parser.add_argument("--format", choices=("text", "json"), default="text", help="Report format")
    parser.add_argument("--output", type=Path, help="Optional path for a JSON report")
    args = parser.parse_args()

    if not args.project.is_dir():
        parser.error(f"project directory does not exist: {args.project}")

    report = scan_project(args.project)
    serialized = json.dumps(report, indent=2, ensure_ascii=False)
    if args.output:
        args.output.write_text(serialized + "\n", encoding="utf-8")

    if args.format == "json":
        print(serialized)
    else:
        print(f"Scanned: {report['project']} | files: {report['files_scanned']} | findings: {len(report['findings'])}")
        for finding in report["findings"]:
            location = f"{finding['file']}:{finding['line']}"
            print(f"[{finding['severity']}] {finding['rule_id']} {location} — {finding['title']}")
            print(f"  Evidence: {finding['evidence']}")
            print(f"  Fix: {finding['remediation']}")
        if report["dependencies"]:
            print(f"Dependency inventory: {len(report['dependencies'])} package entries (not vulnerability-checked)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
