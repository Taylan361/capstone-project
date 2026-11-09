import io
import ipaddress
import re
import socket
import time
import zipfile
from pathlib import PurePosixPath
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from .scanner import (
    LOCKFILE_NAMES,
    MAX_FILE_BYTES,
    MAX_LOCKFILE_BYTES,
    SKIP_DIRECTORIES,
    SOURCE_SUFFIXES,
    redact_line_secrets,
)


MAX_ARCHIVE_BYTES = 15 * 1024 * 1024
MAX_EXTRACTED_BYTES = 25 * 1024 * 1024
MAX_REPO_FILES = 1000
MAX_WEB_RESPONSE_BYTES = 512 * 1024
NETWORK_TIMEOUT_SECONDS = 10

GITHUB_URL_PATTERN = re.compile(
    r"^https://github\.com/([A-Za-z0-9_.-]{1,100})/([A-Za-z0-9_.-]{1,100})(?:/(?:tree|commit)/([A-Za-z0-9_./-]{1,120}))?/?$"
)
INLINE_DOM_SINK_PATTERN = re.compile(r"(?:\.\s*(?:innerHTML|outerHTML)\s*=|\bdocument\.write\s*\(|\beval\s*\()")


def _is_forbidden_ip(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return True
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def validate_safe_public_url(url: str, allowed_hosts: set[str] | None = None) -> tuple[str, list[str]]:
    """Validate URL syntax, enforce HTTPS, optional host allowlist, and block SSRF private/loopback IPs."""
    if not isinstance(url, str) or len(url.strip()) > 500:
        raise ValueError("Invalid URL length or type.")
    parsed = urlsplit(url.strip())
    if parsed.scheme != "https":
        raise ValueError("Only HTTPS URLs are permitted for external security checks.")
    if parsed.username or parsed.password:
        raise ValueError("Credentials in URLs are not permitted.")
    hostname = (parsed.hostname or "").strip().lower()
    if not hostname or hostname in {"localhost", "localhost.localdomain"}:
        raise ValueError("Localhost and internal hostnames are blocked (SSRF protection).")

    if allowed_hosts is not None:
        normalized_allowed = {h.strip().lower() for h in allowed_hosts if h.strip()}
        if hostname not in normalized_allowed:
            raise ValueError(f"Host '{hostname}' is not in the authorized target allowlist.")

    try:
        addr_info = socket.getaddrinfo(hostname, parsed.port or 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise ValueError(f"Could not resolve hostname '{hostname}'.") from exc

    resolved_ips = []
    for entry in addr_info:
        ip_str = entry[4][0]
        if _is_forbidden_ip(ip_str):
            raise ValueError(f"Blocked SSRF attempt: '{hostname}' resolved to restricted address {ip_str}.")
        if ip_str not in resolved_ips:
            resolved_ips.append(ip_str)

    if not resolved_ips:
        raise ValueError(f"No public IP addresses resolved for '{hostname}'.")
    return hostname, resolved_ips


def _read_bounded_bytes(response, max_bytes: int) -> bytes:
    chunks = []
    total = 0
    while True:
        chunk = response.read(65536)
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise ValueError(f"Remote response exceeded maximum size limit ({max_bytes} bytes).")
        chunks.append(chunk)
    return b"".join(chunks)


def extract_safe_zip_entries(archive_bytes: bytes) -> list[dict]:
    """Safely extract text source files from a ZIP archive in memory with Zip-Slip and bomb protection."""
    if len(archive_bytes) > MAX_ARCHIVE_BYTES:
        raise ValueError("Archive exceeds maximum allowed size (15 MiB).")
    files = []
    total_extracted = 0
    supported_suffixes = SOURCE_SUFFIXES | {".json", ".txt"}

    try:
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as zf:
            for info in zf.infolist():
                raw_name = info.filename
                if "\\" in raw_name or raw_name.startswith("/"):
                    raise ValueError(f"Unsafe archive entry path rejected: {raw_name}")
                norm = PurePosixPath(raw_name)
                if norm.is_absolute() or ".." in norm.parts or not norm.parts:
                    raise ValueError(f"Archive path traversal (Zip-Slip) rejected: {raw_name}")

                # Reject symlinks (POSIX S_IFLNK = 0o120000)
                mode = (info.external_attr >> 16) & 0o170000
                if mode == 0o120000:
                    continue
                if info.is_dir():
                    continue

                # Strip top-level GitHub archive wrapper directory (<repo>-<sha>/)
                rel_parts = norm.parts[1:] if len(norm.parts) > 1 else norm.parts
                rel_path = PurePosixPath(*rel_parts)
                if any(part in SKIP_DIRECTORIES for part in rel_path.parts):
                    continue
                if rel_path.suffix.lower() not in supported_suffixes:
                    continue

                file_limit = MAX_LOCKFILE_BYTES if rel_path.name in LOCKFILE_NAMES else MAX_FILE_BYTES
                if info.file_size > file_limit:
                    continue
                total_extracted += info.file_size
                if total_extracted > MAX_EXTRACTED_BYTES:
                    raise ValueError("Extracted archive contents exceed maximum uncompressed budget (25 MiB).")
                if len(files) >= MAX_REPO_FILES:
                    break

                raw_content = zf.read(info)
                if len(raw_content) > file_limit:
                    continue
                try:
                    text = raw_content.decode("utf-8")
                except UnicodeDecodeError:
                    continue
                files.append({"path": rel_path.as_posix(), "content": text})
    except zipfile.BadZipFile as exc:
        raise ValueError("Downloaded archive is not a valid ZIP file.") from exc

    return files


def fetch_github_repository(repo_url: str) -> tuple[str, list[dict], dict]:
    """Download a public GitHub repository archive safely without executing any code or scripts."""
    if not isinstance(repo_url, str):
        raise ValueError("GitHub repository URL must be a string.")
    cleaned = repo_url.strip()
    if cleaned.endswith(".git"):
        cleaned = cleaned[:-4]
    match = GITHUB_URL_PATTERN.fullmatch(cleaned)
    if not match:
        raise ValueError("Provide a valid HTTPS GitHub repository URL (https://github.com/<owner>/<repo>).")

    owner, repo, ref = match.group(1), match.group(2), match.group(3) or "HEAD"
    validate_safe_public_url("https://github.com", allowed_hosts={"github.com"})
    validate_safe_public_url("https://codeload.github.com", allowed_hosts={"codeload.github.com"})

    archive_url = f"https://codeload.github.com/{owner}/{repo}/zip/{ref}"
    started = time.perf_counter()
    req = Request(
        archive_url,
        headers={"User-Agent": "AICodeShield-Capstone/0.2 (Read-Only Academic Security Scanner)"},
        method="GET",
    )
    try:
        with urlopen(req, timeout=NETWORK_TIMEOUT_SECONDS) as response:
            final_host = (urlsplit(response.geturl()).hostname or "").lower()
            if final_host not in {"codeload.github.com", "github.com"}:
                raise ValueError("Unexpected redirect host during GitHub archive fetch.")
            archive_bytes = _read_bounded_bytes(response, MAX_ARCHIVE_BYTES)
    except HTTPError as exc:
        status = exc.code
        exc.close()
        if status == 404:
            raise ValueError(f"GitHub repository '{owner}/{repo}' (ref '{ref}') was not found or is private.") from None
        raise RuntimeError(f"GitHub archive server returned HTTP {status}.") from None
    except (URLError, TimeoutError, OSError) as exc:
        raise RuntimeError("Could not download GitHub archive within timeout bounds.") from exc

    files = extract_safe_zip_entries(archive_bytes)
    elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
    metadata = {
        "intake_mode": "github_repository_archive",
        "repository": f"{owner}/{repo}",
        "ref": ref,
        "archive_bytes": len(archive_bytes),
        "files_extracted": len(files),
        "fetch_duration_ms": elapsed_ms,
        "safety_controls": [
            "https_only",
            "host_allowlist(github.com,codeload.github.com)",
            "ssrf_private_ip_block",
            "zip_slip_traversal_check",
            "symlink_rejection",
            "max_archive_15mib",
            "no_script_execution",
        ],
    }
    return f"{owner}/{repo}", files, metadata


def inspect_website_passive(target_url: str, authorized: bool = False, allowed_hosts: list[str] | None = None) -> dict:
    """Perform strictly passive, single-GET HTTP header and response security inspection on an authorized target."""
    if authorized is not True:
        raise ValueError("Explicit authorization confirmation is required before inspecting a website URL.")
    if not isinstance(target_url, str) or not target_url.strip():
        raise ValueError("Provide a valid HTTPS website URL.")

    parsed = urlsplit(target_url.strip())
    host = (parsed.hostname or "").strip().lower()
    effective_allowlist = set(allowed_hosts) if allowed_hosts else ({host} if host else set())
    validated_host, resolved_ips = validate_safe_public_url(target_url.strip(), allowed_hosts=effective_allowlist)

    started = time.perf_counter()
    req = Request(
        target_url.strip(),
        headers={
            "User-Agent": "AICodeShield-PassiveInspector/0.2 (Non-Intrusive Header Check)",
            "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1",
        },
        method="GET",
    )
    try:
        with urlopen(req, timeout=NETWORK_TIMEOUT_SECONDS) as response:
            final_url = response.geturl()
            final_host = (urlsplit(final_url).hostname or "").lower()
            validate_safe_public_url(final_url, allowed_hosts={validated_host, final_host})
            status_code = getattr(response, "status", 200)
            raw_headers = dict(response.headers.items())
            set_cookies = response.headers.get_all("Set-Cookie") or []
            body_bytes = _read_bounded_bytes(response, MAX_WEB_RESPONSE_BYTES)
    except HTTPError as exc:
        status_code = exc.code
        raw_headers = dict(exc.headers.items()) if exc.headers else {}
        set_cookies = exc.headers.get_all("Set-Cookie") if exc.headers else []
        body_bytes = b""
        exc.close()
    except (URLError, TimeoutError, OSError) as exc:
        raise RuntimeError("Passive website inspection failed or timed out.") from exc

    body_text = body_bytes.decode("utf-8", errors="replace")
    findings = evaluate_passive_web_response(target_url.strip(), raw_headers, set_cookies, body_text)
    duration_ms = round((time.perf_counter() - started) * 1000, 2)

    return {
        "scanner_version": "0.2.0",
        "project": validated_host,
        "intake_mode": "passive_website_inspection",
        "files_scanned": 1,
        "scan_duration_ms": duration_ms,
        "findings": findings,
        "dependencies": [],
        "dependency_check_status": "not_applicable_for_passive_website_inspection",
        "passive_inspection": {
            "mode": "passive_single_get_only",
            "authorized_by_user": True,
            "target_url": target_url.strip(),
            "validated_host": validated_host,
            "resolved_public_ips": resolved_ips,
            "http_status": status_code,
            "active_payloads_sent": 0,
        },
    }


def evaluate_passive_web_response(
    target_url: str,
    headers: dict[str, str],
    set_cookies: list[str] | None = None,
    body_text: str = "",
) -> list[dict]:
    """Deterministic passive evaluation of HTTP security headers, cookies, rate-limit indicators, and DOM sinks."""
    lower_headers = {k.lower(): v for k, v in headers.items()}
    findings = []

    if "content-security-policy" not in lower_headers:
        findings.append({
            "rule_id": "WEB001",
            "cwe": "CWE-693",
            "title": "Missing Content-Security-Policy (CSP) header",
            "severity": "medium",
            "confidence": "high",
            "file": target_url,
            "line": 1,
            "evidence": "HTTP response headers lack Content-Security-Policy",
            "remediation": "Configure a restrictive Content-Security-Policy header (e.g. default-src 'self'; object-src 'none') to mitigate XSS impact.",
        })

    if lower_headers.get("x-content-type-options", "").strip().lower() != "nosniff":
        findings.append({
            "rule_id": "WEB002",
            "cwe": "CWE-693",
            "title": "Missing X-Content-Type-Options: nosniff header",
            "severity": "low",
            "confidence": "high",
            "file": target_url,
            "line": 1,
            "evidence": f"X-Content-Type-Options: {lower_headers.get('x-content-type-options', '<absent>')}",
            "remediation": "Add 'X-Content-Type-Options: nosniff' to prevent MIME-sniffing attacks.",
        })

    if target_url.startswith("https://") and "strict-transport-security" not in lower_headers:
        findings.append({
            "rule_id": "WEB003",
            "cwe": "CWE-319",
            "title": "Missing Strict-Transport-Security (HSTS) header",
            "severity": "medium",
            "confidence": "high",
            "file": target_url,
            "line": 1,
            "evidence": "HTTPS response lacks Strict-Transport-Security header",
            "remediation": "Return 'Strict-Transport-Security: max-age=31536000; includeSubDomains' on HTTPS responses.",
        })

    rate_headers = ("ratelimit-limit", "x-ratelimit-limit", "x-rate-limit-limit", "retry-after")
    if not any(h in lower_headers for h in rate_headers):
        findings.append({
            "rule_id": "WEB004",
            "cwe": "CWE-770",
            "title": "No passive HTTP rate-limiting headers advertised",
            "severity": "low",
            "confidence": "low",
            "file": target_url,
            "line": 1,
            "evidence": "Response headers do not include RateLimit-Limit or X-RateLimit-Limit indicators",
            "remediation": "Enforce endpoint rate limiting (e.g. 60 req/min per IP) and expose standard RateLimit-* headers.",
        })

    for cookie in set_cookies or []:
        cookie_lower = cookie.lower()
        cookie_name = cookie.split("=", 1)[0].strip() or "cookie"
        missing_flags = [
            flag for flag in ("httponly", "secure", "samesite")
            if flag not in cookie_lower
        ]
        if missing_flags:
            findings.append({
                "rule_id": "WEB005",
                "cwe": "CWE-614",
                "title": f"Cookie '{cookie_name}' missing security flags ({', '.join(missing_flags)})",
                "severity": "medium",
                "confidence": "high",
                "file": target_url,
                "line": 1,
                "evidence": f"Set-Cookie: {cookie_name}=[REDACTED]; missing {', '.join(missing_flags)}",
                "remediation": "Set HttpOnly, Secure, and SameSite=Lax (or Strict) on session and authentication cookies.",
            })

    for line_no, line in enumerate(body_text.splitlines()[:500], start=1):
        if INLINE_DOM_SINK_PATTERN.search(line):
            findings.append({
                "rule_id": "WEB006",
                "cwe": "CWE-79",
                "title": "Inline DOM XSS sink detected in HTML response",
                "severity": "high",
                "confidence": "medium",
                "file": target_url,
                "line": line_no,
                "evidence": redact_line_secrets(line.strip())[:200],
                "remediation": "Avoid inline innerHTML/document.write/eval in page scripts; use textContent or sanitized templates.",
            })
            break

    return findings
