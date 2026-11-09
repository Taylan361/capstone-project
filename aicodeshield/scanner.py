import json
import re
from pathlib import Path, PurePosixPath


MAX_FILE_BYTES = 1_048_576
MAX_LOCKFILE_BYTES = 5_242_880
LOCKFILE_NAMES = {"package-lock.json", "npm-shrinkwrap.json"}
SKIP_DIRECTORIES = {".git", "node_modules", ".venv", "venv", "__pycache__", ".mypy_cache", ".pytest_cache"}
SOURCE_SUFFIXES = {".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}

RULES = [
    {
        "id": "PY001",
        "pattern": re.compile(r"\b(?:eval|exec)\s*\("),
        "title": "Dynamic code execution",
        "severity": "high",
        "confidence": "medium",
        "remediation": "Avoid evaluating dynamically supplied text; use explicit parsing and validation.",
        "extensions": {".py"},
    },
    {
        "id": "PY002",
        "pattern": re.compile(r"\bsubprocess\.(?:run|Popen|call|check_output)\s*\([^\n]*\bshell\s*=\s*True"),
        "title": "Subprocess invoked with shell=True",
        "severity": "high",
        "confidence": "medium",
        "remediation": "Pass an argument list with shell=False and validate untrusted arguments.",
        "extensions": {".py"},
    },
    {
        "id": "JS001",
        "pattern": re.compile(r"\b(?:child_process|childProcess)\s*\.\s*exec\s*\("),
        "title": "Node.js shell command execution",
        "severity": "high",
        "confidence": "medium",
        "remediation": "Prefer execFile or spawn with a fixed executable and validated argument list.",
        "extensions": {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"},
    },
    {
        "id": "JS002",
        "pattern": re.compile(r"\beval\s*\("),
        "title": "Dynamic JavaScript evaluation",
        "severity": "high",
        "confidence": "medium",
        "remediation": "Avoid evaluating dynamically supplied text; use explicit parsing and validation.",
        "extensions": {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"},
    },
    {
        "id": "SEC001",
        "pattern": re.compile(r"\b(api[_-]?key|secret|password|token)\b\s*[:=]\s*(['\"])([^'\"\n]{6,})\2", re.IGNORECASE),
        "title": "Possible hard-coded secret",
        "severity": "high",
        "confidence": "low",
        "remediation": "Remove the value, rotate it if real, and load secrets from a protected environment or vault.",
    },
]


def _iter_project_files(root: Path):
    for path in root.rglob("*"):
        if any(part in SKIP_DIRECTORIES for part in path.relative_to(root).parts):
            continue
        if path.is_file() and path.suffix.lower() in SOURCE_SUFFIXES | {".json", ".txt"}:
            try:
                max_bytes = MAX_LOCKFILE_BYTES if path.name in LOCKFILE_NAMES else MAX_FILE_BYTES
                if path.stat().st_size <= max_bytes:
                    yield path
            except OSError:
                continue


def _source_findings(relative_path: str, content: str):
    extension = Path(relative_path).suffix.lower()
    for line_number, line in enumerate(content.splitlines(), start=1):
        for rule in RULES:
            if extension not in rule.get("extensions", SOURCE_SUFFIXES):
                continue
            for match in rule["pattern"].finditer(line):
                evidence = line.strip()
                if rule["id"] == "SEC001":
                    secret_match = rule["pattern"].search(line)
                    evidence = f"{secret_match.group(1)} = '[REDACTED]'"
                yield {
                    "rule_id": rule["id"],
                    "title": rule["title"],
                    "severity": rule["severity"],
                    "confidence": rule["confidence"],
                    "file": relative_path,
                    "line": line_number,
                    "evidence": evidence[:240],
                    "remediation": rule["remediation"],
                }


def _inventory_dependencies(path: Path, content: str):
    packages = []
    if path.name == "requirements.txt":
        for line in content.splitlines():
            candidate = line.strip()
            if not candidate or candidate.startswith(("#", "-")):
                continue
            name = re.split(r"\s*(?:===|==|~=|!=|<=|>=|<|>|;|\[)\s*", candidate, maxsplit=1)[0].strip()
            if name:
                packages.append({"name": name, "declared_version": candidate[len(name):].strip() or None})
    elif path.name == "package.json":
        try:
            manifest = json.loads(content)
        except json.JSONDecodeError:
            return packages
        for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            entries = manifest.get(section, {})
            if isinstance(entries, dict):
                packages.extend({"name": name, "declared_version": version, "section": section}
                                for name, version in entries.items())
    elif path.name in LOCKFILE_NAMES:
        try:
            lockfile = json.loads(content)
        except json.JSONDecodeError:
            return packages
        locked_packages = lockfile.get("packages")
        if isinstance(locked_packages, dict):
            for package_path, details in locked_packages.items():
                if not package_path or not package_path.startswith("node_modules/") or not isinstance(details, dict):
                    continue
                package_parts = package_path.split("node_modules/")[-1].split("/")
                inferred_name = "/".join(package_parts[:2]) if package_parts[0].startswith("@") and len(package_parts) > 1 else package_parts[0]
                name = details.get("name") or inferred_name
                version = details.get("version")
                if isinstance(name, str) and isinstance(version, str):
                    packages.append({"name": name, "declared_version": version, "section": "lockfile"})
        else:
            def add_legacy_dependencies(entries):
                if not isinstance(entries, dict):
                    return
                for name, details in entries.items():
                    if not isinstance(details, dict):
                        continue
                    version = details.get("version")
                    if isinstance(version, str):
                        packages.append({"name": name, "declared_version": version, "section": "lockfile"})
                    add_legacy_dependencies(details.get("dependencies"))

            add_legacy_dependencies(lockfile.get("dependencies"))
    return packages


def scan_project(project: Path):
    root = project.resolve()
    findings = []
    dependencies = []
    files_scanned = 0
    for path in _iter_project_files(root):
        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        files_scanned += 1
        relative_path = path.relative_to(root).as_posix()
        if path.suffix.lower() in SOURCE_SUFFIXES:
            findings.extend(_source_findings(relative_path, content))
        if path.name in {"requirements.txt", "package.json"} | LOCKFILE_NAMES:
            for dependency in _inventory_dependencies(path, content):
                dependency["manifest"] = relative_path
                dependencies.append(dependency)

    return _report(root.name, files_scanned, findings, _prefer_npm_lock_versions(dependencies))


def scan_sources(project_name: str, files: list[dict]):
    findings = []
    dependencies = []
    files_scanned = 0
    for item in files:
        relative_path = item.get("path")
        content = item.get("content")
        if not isinstance(relative_path, str) or not isinstance(content, str):
            continue
        normalized = PurePosixPath(relative_path)
        if normalized.is_absolute() or ".." in normalized.parts or not normalized.parts:
            continue
        if any(part in SKIP_DIRECTORIES for part in normalized.parts):
            continue
        file_limit = MAX_LOCKFILE_BYTES if normalized.name in LOCKFILE_NAMES else MAX_FILE_BYTES
        if len(content.encode("utf-8")) > file_limit:
            continue
        if normalized.suffix.lower() not in SOURCE_SUFFIXES | {".json", ".txt"}:
            continue
        files_scanned += 1
        if normalized.suffix.lower() in SOURCE_SUFFIXES:
            findings.extend(_source_findings(normalized.as_posix(), content))
        if normalized.name in {"requirements.txt", "package.json"} | LOCKFILE_NAMES:
            for dependency in _inventory_dependencies(Path(normalized.name), content):
                dependency["manifest"] = normalized.as_posix()
                dependencies.append(dependency)

    return _report(project_name, files_scanned, findings, _prefer_npm_lock_versions(dependencies))


def _prefer_npm_lock_versions(dependencies):
    locked_names_by_directory = {}
    for dependency in dependencies:
        manifest = dependency.get("manifest", "")
        if Path(manifest).name in LOCKFILE_NAMES:
            directory = str(PurePosixPath(manifest).parent)
            locked_names_by_directory.setdefault(directory, set()).add(dependency.get("name", "").casefold())
    if not locked_names_by_directory:
        return dependencies
    return [
        dependency for dependency in dependencies
        if not (
            Path(dependency.get("manifest", "")).name == "package.json"
            and dependency.get("name", "").casefold() in locked_names_by_directory.get(
                str(PurePosixPath(dependency.get("manifest", "")).parent), set()
            )
        )
    ]


def _report(project_name: str, files_scanned: int, findings: list, dependencies: list):
    return {
        "scanner_version": "0.1.0",
        "project": project_name,
        "files_scanned": files_scanned,
        "findings": findings,
        "dependencies": dependencies,
        "dependency_check_status": "inventory_only; online checks were not requested",
    }
