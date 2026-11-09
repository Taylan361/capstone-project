import json
import tempfile
import unittest
from pathlib import Path
from urllib.error import HTTPError
from unittest.mock import patch

from aicodeshield import dependency_check
from aicodeshield.scanner import scan_project, scan_sources


class ScannerTests(unittest.TestCase):
    def test_detects_patterns_and_masks_secret_values(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text(
                "api_key = 'do-not-print-this-secret'\nvalue = eval(user_input)\n"
                "subprocess.run(command, shell=True)\n",
                encoding="utf-8",
            )

            report = scan_project(root)

            self.assertEqual({"SEC001", "PY001", "PY002"}, {item["rule_id"] for item in report["findings"]})
            serialized = json.dumps(report)
            self.assertNotIn("do-not-print-this-secret", serialized)
            secret = next(item for item in report["findings"] if item["rule_id"] == "SEC001")
            self.assertIn("[REDACTED]", secret["evidence"])

    def test_inventories_python_and_node_dependencies_without_claiming_vulnerability_status(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "requirements.txt").write_text("flask==3.0.0\n# comment\n", encoding="utf-8")
            (root / "package.json").write_text(
                '{"dependencies":{"express":"^4.18.0"}}', encoding="utf-8"
            )

            report = scan_project(root)

            self.assertEqual({"flask", "express"}, {item["name"] for item in report["dependencies"]})
            self.assertIn("inventory_only", report["dependency_check_status"])

    def test_skips_dependency_and_cache_directories(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ignored = root / "node_modules" / "example"
            ignored.mkdir(parents=True)
            (ignored / "index.js").write_text("eval(value)", encoding="utf-8")
            (root / "app.js").write_text("const safe = true;", encoding="utf-8")

            report = scan_project(root)

            self.assertEqual(1, report["files_scanned"])
            self.assertEqual([], report["findings"])

    def test_browser_scan_skips_unsafe_paths_and_masks_secrets(self):
        report = scan_sources("sample", [
            {"path": "sample/app.js", "content": "const token = 'should-not-appear-123';\n"},
            {"path": "../outside.js", "content": "eval(value);"},
            {"path": "sample/node_modules/lib/index.js", "content": "eval(value);"},
        ])

        self.assertEqual(1, report["files_scanned"])
        self.assertEqual("sample/app.js", report["findings"][0]["file"])
        self.assertNotIn("should-not-appear-123", json.dumps(report))

    def test_node_child_process_exec_uses_javascript_rule(self):
        report = scan_sources("sample", [
            {"path": "sample/server.js", "content": "childProcess.exec(command, callback);\n"},
        ])

        self.assertEqual("JS001", report["findings"][0]["rule_id"])
        self.assertEqual("Node.js shell command execution", report["findings"][0]["title"])

    def test_npm_lockfile_provides_exact_resolved_versions(self):
        report = scan_sources("sample", [
            {"path": "sample/package.json", "content": '{"dependencies":{"lodash":"^4.17.0"}}'},
            {"path": "sample/package-lock.json", "content": json.dumps({
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "sample"},
                    "node_modules/lodash": {"version": "4.17.20"},
                    "node_modules/@scope/tool": {"version": "2.1.0"},
                },
            })},
        ])

        dependencies = {(item["name"], item["declared_version"]) for item in report["dependencies"]}
        self.assertEqual({("lodash", "4.17.20"), ("@scope/tool", "2.1.0")}, dependencies)
        self.assertTrue(all(item["manifest"].endswith("package-lock.json") for item in report["dependencies"]))


class DependencyCheckTests(unittest.TestCase):
    def test_exact_python_pin_is_checked_for_advisories_and_latest_version(self):
        def fake_fetch(url, payload=None):
            if url == "https://pypi.org/pypi/requests/json":
                return {"info": {"version": "2.32.3"}}
            if url == "https://api.osv.dev/v1/querybatch":
                self.assertEqual("2.28.0", payload["queries"][0]["version"])
                return {"results": [{"vulns": [{"id": "GHSA-test"}]}]}
            if url == "https://api.osv.dev/v1/vulns/GHSA-test":
                return {
                    "id": "GHSA-test",
                    "aliases": ["CVE-2026-12345"],
                    "summary": "Test advisory",
                    "database_specific": {"severity": "HIGH"},
                    "affected": [{"ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.29.0"}]}]}],
                    "references": [{"type": "WEB", "url": "https://example.test/advisory"}],
                }
            self.fail(f"Unexpected external lookup in test: {url}")

        with patch.object(dependency_check, "_fetch_json", side_effect=fake_fetch):
            result, metadata = dependency_check.check_dependencies([{
                "name": "requests", "declared_version": "==2.28.0", "manifest": "requirements.txt"
            }])

        self.assertEqual("found_public", result[0]["registry_status"])
        self.assertEqual("update_available", result[0]["version_status"])
        self.assertEqual("checked_with_findings", result[0]["advisory_status"])
        self.assertEqual("high", result[0]["advisories"][0]["severity"])
        self.assertEqual(["2.29.0"], result[0]["advisories"][0]["fixed_versions"])
        self.assertEqual("https://example.test/advisory", result[0]["advisories"][0]["references"][0]["url"])
        self.assertEqual("completed", metadata["status"])

    def test_public_registry_absence_is_not_reported_as_fake_package(self):
        def fake_fetch(url, payload=None):
            if url == "https://registry.npmjs.org/%40example%2Finternal-lib":
                raise HTTPError(url, 404, "Not Found", None, None)
            self.fail(f"Unexpected external lookup in test: {url}")

        with patch.object(dependency_check, "_fetch_json", side_effect=fake_fetch):
            result, metadata = dependency_check.check_dependencies([{
                "name": "@example/internal-lib", "declared_version": "^1.2.3",
                "manifest": "package.json", "section": "dependencies"
            }])

        self.assertEqual("not_found_public", result[0]["registry_status"])
        self.assertIn("private or internal", result[0]["registry_note"])
        self.assertEqual("version_unpinned", result[0]["advisory_status"])
        self.assertEqual("no_exact_versions_to_check", metadata["status"])


if __name__ == "__main__":
    unittest.main()
