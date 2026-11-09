import json
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from aicodeshield.ai_remediation import configuration as ai_configuration, explain_findings
from aicodeshield.dependency_check import check_dependencies
from aicodeshield.intake import fetch_github_repository, inspect_website_passive
from aicodeshield.scanner import scan_sources


ROOT = Path(__file__).resolve().parent
WEB_DIST = ROOT / "web" / "dist"
MAX_REQUEST_BYTES = 12 * 1024 * 1024
MAX_FILES = 1000


def build_scan_report(project_name, files, online_lookup=False):
    report = scan_sources(project_name[:120], files)
    if online_lookup is True:
        dependencies, lookup_metadata = check_dependencies(report["dependencies"])
        report["dependencies"] = dependencies
        report["dependency_check_status"] = lookup_metadata["status"]
        report["online_lookup"] = lookup_metadata
    return report


def build_github_scan_report(repo_url, online_lookup=False):
    project_name, files, intake_metadata = fetch_github_repository(repo_url)
    report = build_scan_report(project_name, files, online_lookup=online_lookup)
    report["intake_mode"] = "github_repository_archive"
    report["github_intake"] = intake_metadata
    return report


class DashboardHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(WEB_DIST), **kwargs)

    def do_GET(self):
        if self.path == "/api/health":
            self._json_response(200, {"status": "ok", "scanner_version": "0.2.0"})
            return
        if self.path == "/api/ai/status":
            self._json_response(200, ai_configuration())
            return
        if self.path.startswith("/api/"):
            self._json_response(404, {"error": "API route not found"})
            return
        if not WEB_DIST.exists():
            self._json_response(503, {"error": "Dashboard build not found. Run npm run build in web/."})
            return
        super().do_GET()

    def do_POST(self):
        if self.path not in {"/api/scan", "/api/scan/github", "/api/scan/website", "/api/ai/remediate"}:
            self._json_response(404, {"error": "API route not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._json_response(400, {"error": "Invalid content length"})
            return
        if length <= 0 or length > MAX_REQUEST_BYTES:
            self._json_response(413, {"error": "Request must be between 1 byte and 12 MiB"})
            return
        try:
            payload = json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._json_response(400, {"error": "Request body must be valid JSON"})
            return

        if self.path == "/api/ai/remediate":
            if not isinstance(payload, dict) or not isinstance(payload.get("findings"), list):
                self._json_response(400, {"error": "Expected a findings array"})
                return
            if not ai_configuration()["configured"]:
                self._json_response(503, {"error": "DeepSeek is not configured. Add the API key to the local .env file and restart the app."})
                return
            try:
                self._json_response(200, explain_findings(payload["findings"], payload.get("dependencies")))
            except ValueError as error:
                self._json_response(400, {"error": str(error)})
            except RuntimeError as error:
                self._json_response(502, {"error": str(error)})
            return

        if self.path == "/api/scan/github":
            if not isinstance(payload, dict) or not isinstance(payload.get("repo_url"), str):
                self._json_response(400, {"error": "Expected a GitHub repository URL (repo_url)"})
                return
            try:
                report = build_github_scan_report(
                    payload["repo_url"],
                    online_lookup=payload.get("online_lookup") is True,
                )
                self._json_response(200, report)
            except ValueError as error:
                self._json_response(400, {"error": str(error)})
            except RuntimeError as error:
                self._json_response(502, {"error": str(error)})
            return

        if self.path == "/api/scan/website":
            if not isinstance(payload, dict) or not isinstance(payload.get("target_url"), str):
                self._json_response(400, {"error": "Expected a website target_url"})
                return
            try:
                allowed = payload.get("allowed_hosts") if isinstance(payload.get("allowed_hosts"), list) else None
                report = inspect_website_passive(
                    payload["target_url"],
                    authorized=payload.get("authorized") is True,
                    allowed_hosts=allowed,
                )
                self._json_response(200, report)
            except ValueError as error:
                self._json_response(400, {"error": str(error)})
            except RuntimeError as error:
                self._json_response(502, {"error": str(error)})
            return

        if not isinstance(payload, dict) or not isinstance(payload.get("files"), list):
            self._json_response(400, {"error": "Expected a files array"})
            return
        if len(payload["files"]) > MAX_FILES:
            self._json_response(413, {"error": "Select no more than 1,000 files"})
            return
        project_name = payload.get("project", "Selected project")
        if not isinstance(project_name, str):
            self._json_response(400, {"error": "Project name must be text"})
            return
        try:
            report = build_scan_report(
                project_name,
                payload["files"],
                online_lookup=payload.get("online_lookup") is True,
            )
        except (TypeError, ValueError, UnicodeError):
            self._json_response(400, {"error": "Could not scan the selected files"})
            return
        self._json_response(200, report)

    def _json_response(self, status, payload):
        encoded = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, format, *args):
        print("Local dashboard: " + format % args)


if __name__ == "__main__":
    address = ("127.0.0.1", 8765)
    server = ThreadingHTTPServer(address, DashboardHandler)
    print("AICodeShield is available at http://127.0.0.1:8765")
    print("The scanner listens only on this computer.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping local dashboard.")
        server.server_close()
