import ast
import json
import re
import time
from pathlib import Path, PurePosixPath


MAX_FILE_BYTES = 1_048_576
MAX_LOCKFILE_BYTES = 5_242_880
LOCKFILE_NAMES = {"package-lock.json", "npm-shrinkwrap.json"}
SKIP_DIRECTORIES = {".git", "node_modules", ".venv", "venv", "__pycache__", ".mypy_cache", ".pytest_cache"}
SOURCE_SUFFIXES = {".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".html", ".htm"}

LIFECYCLE_HOOKS = {"preinstall", "install", "postinstall", "preuninstall", "postuninstall", "prepare", "prepublish"}
SUSPICIOUS_SCRIPT_PATTERN = re.compile(
    r"(?i)(?:\b(?:curl|wget|nc|netcat|ncat|bash|sh\s+-c|zsh\s+-c|powershell|pwsh|Invoke-WebRequest|iwr|eval|base64)\b"
    r"|node\s+-e|python3?\s+-c|https?://|\b(?:os\.environ|process\.env)\b)"
)

STANDALONE_TOKEN_PATTERN = re.compile(
    r"\b(sk-[A-Za-z0-9_-]{10,}|gh[pousr]_[A-Za-z0-9_]{12,}|AKIA[0-9A-Z]{16})\b"
)
SECRET_ASSIGNMENT_PATTERN = re.compile(
    r"\b([A-Za-z0-9_]*(?:api[_-]?key|secret|password|passwd|token|private[_-]?key|access[_-]?key)[A-Za-z0-9_]*)\b\s*[:=]\s*(['\"])([^'\"\n]{6,})\2",
    re.IGNORECASE,
)

SQL_KEYWORD_PATTERN = re.compile(r"(?i)\b(?:SELECT|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b")

RULES = [
    {
        "id": "PY001",
        "cwe": "CWE-95",
        "pattern": re.compile(r"\b(?:eval|exec)\s*\("),
        "title": "Dynamic code execution",
        "severity": "high",
        "confidence": "high",
        "remediation": "Avoid evaluating dynamically supplied text; use ast.literal_eval or explicit parsing and validation.",
        "extensions": {".py"},
    },
    {
        "id": "PY002",
        "cwe": "CWE-78",
        "pattern": re.compile(
            r"(?:\bsubprocess\.(?:run|Popen|call|check_output)\s*\([^\n]*\bshell\s*=\s*True|\bos\.(?:system|popen)\s*\()"
        ),
        "title": "Subprocess invoked with shell=True",
        "severity": "high",
        "confidence": "high",
        "remediation": "Pass an argument list with shell=False (e.g. subprocess.run(['cmd', arg], shell=False, check=True)) and validate untrusted arguments.",
        "extensions": {".py"},
    },
    {
        "id": "PY003",
        "cwe": "CWE-89",
        "pattern": re.compile(
            r"(?i)(?:\b(?:execute|executemany|raw)\s*\(\s*(?:f['\"]|['\"][^'\"]*['\"]\s*(?:\+|%|\.format\())"
            r"|\b(?:query|sql)\s*=\s*f['\"][^'\"]*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^'\"]*\{)"
        ),
        "title": "Potential SQL injection via dynamic query formatting",
        "severity": "high",
        "confidence": "high",
        "remediation": "Use parameterized queries with bound placeholders (e.g. cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))) instead of string formatting.",
        "extensions": {".py"},
    },
    {
        "id": "PY004",
        "cwe": "CWE-502",
        "pattern": re.compile(r"\b(?:pickle\.loads?|yaml\.unsafe_load)\s*\("),
        "title": "Unsafe deserialization of untrusted data",
        "severity": "high",
        "confidence": "high",
        "remediation": "Avoid pickle on untrusted data; use json.loads or yaml.safe_load with schema validation.",
        "extensions": {".py"},
    },
    {
        "id": "PY005",
        "cwe": "CWE-79",
        "pattern": re.compile(r"\b(?:render_template_string|mark_safe|Markup)\s*\(\s*(?:f['\"]|[A-Za-z_]\w*\s*\+)"),
        "title": "Unescaped HTML template rendering (Cross-Site Scripting)",
        "severity": "high",
        "confidence": "medium",
        "remediation": "Render static templates with auto-escaping enabled (render_template) or escape user input via html.escape().",
        "extensions": {".py"},
    },
    {
        "id": "JS001",
        "cwe": "CWE-78",
        "pattern": re.compile(r"\b(?:child_process|childProcess)\s*\.\s*exec(?:Sync)?\s*\("),
        "title": "Node.js shell command execution",
        "severity": "high",
        "confidence": "high",
        "remediation": "Prefer execFile or spawn with a fixed executable and validated argument list (shell: false).",
        "extensions": {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"},
    },
    {
        "id": "JS002",
        "cwe": "CWE-95",
        "pattern": re.compile(r"(?:\beval\s*\(|\bnew\s+Function\s*\()"),
        "title": "Dynamic JavaScript evaluation",
        "severity": "high",
        "confidence": "high",
        "remediation": "Avoid evaluating dynamically supplied text; use JSON.parse and explicit schema validation.",
        "extensions": {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".html", ".htm"},
    },
    {
        "id": "JS003",
        "cwe": "CWE-79",
        "pattern": re.compile(r"(?:\.\s*(?:innerHTML|outerHTML)\s*=|\bdocument\.write\s*\(|\bdangerouslySetInnerHTML\b)"),
        "title": "DOM Cross-Site Scripting (XSS) sink",
        "severity": "high",
        "confidence": "medium",
        "remediation": "Assign untrusted text via textContent / innerText or sanitize HTML with DOMPurify before rendering.",
        "extensions": {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".html", ".htm"},
    },
    {
        "id": "JS004",
        "cwe": "CWE-89",
        "pattern": re.compile(
            r"(?i)\.\s*(?:query|exec|execute)\s*\(\s*(?:`[^`]*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^`]*\$\{|['\"][^'\"]*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^'\"]*['\"]\s*\+)"
        ),
        "title": "SQL injection via string concatenation or template literal",
        "severity": "high",
        "confidence": "high",
        "remediation": "Use parameterized queries with placeholder arrays (e.g. db.query('SELECT * FROM users WHERE id = ?', [id])).",
        "extensions": {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"},
    },
    {
        "id": "JS005",
        "cwe": "CWE-770",
        "pattern": re.compile(
            r"\b(?:app|router)\s*\.\s*(?:get|post|put|delete)\s*\(\s*['\"][^'\"]+['\"]\s*,\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_]\w*)\s*=>"
        ),
        "title": "HTTP route handler without rate-limiting middleware",
        "severity": "medium",
        "confidence": "low",
        "remediation": "Attach rate-limiting middleware (e.g. express-rate-limit) to public or authentication/search routes to mitigate DoS bursts.",
        "extensions": {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"},
    },
    {
        "id": "SEC001",
        "cwe": "CWE-798",
        "pattern": SECRET_ASSIGNMENT_PATTERN,
        "title": "Possible hard-coded secret",
        "severity": "high",
        "confidence": "medium",
        "remediation": "Remove the value, rotate it if real, and load secrets from a protected environment variable (os.environ / process.env) or secret manager.",
    },
]

RULE_BY_ID = {rule["id"]: rule for rule in RULES}


def mask_secret_value(raw_value: str) -> str:
    if not isinstance(raw_value, str) or not raw_value:
        return "[REDACTED]"
    if raw_value.startswith(("sk-", "ghp_", "gho_", "ghs_", "AKIA")):
        prefix = raw_value[:3] if raw_value.startswith("sk-") else raw_value[:4]
        return f"{prefix}****[REDACTED]"
    return "[REDACTED]"


def redact_line_secrets(line: str) -> str:
    redacted = SECRET_ASSIGNMENT_PATTERN.sub(lambda m: f"{m.group(1)} = '[REDACTED]'", line)
    redacted = STANDALONE_TOKEN_PATTERN.sub("[REDACTED]", redacted)
    return redacted


class _PythonSecurityAstVisitor(ast.NodeVisitor):
    """Deterministic Python AST visitor that eliminates comment/docstring false positives."""

    def __init__(self, lines: list[str]):
        self.lines = lines
        self.findings_by_line_rule: dict[tuple[int, str], dict] = {}
        self.file_has_rate_limiter = any(
            token in "\n".join(lines) for token in ("limiter", "rate_limit", "RateLimiter", "slowapi", " thrott")
        )

    def _add(self, lineno: int, rule_id: str, custom_rule: dict | None = None):
        if lineno < 1 or lineno > len(self.lines):
            return
        key = (lineno, rule_id)
        if key in self.findings_by_line_rule:
            return
        rule = custom_rule or RULE_BY_ID[rule_id]
        raw_line = self.lines[lineno - 1].strip()
        evidence = redact_line_secrets(raw_line)[:240]
        self.findings_by_line_rule[key] = {
            "rule_id": rule["id"],
            "cwe": rule.get("cwe", "CWE-unknown"),
            "title": rule["title"],
            "severity": rule["severity"],
            "confidence": rule["confidence"],
            "line": lineno,
            "evidence": evidence,
            "remediation": rule["remediation"],
            "analysis_mode": "ast",
        }

    def visit_Call(self, node: ast.Call):
        lineno = getattr(node, "lineno", 0)
        func_name = self._call_name(node.func)

        if func_name in {"eval", "exec", "builtins.eval", "builtins.exec"}:
            self._add(lineno, "PY001")

        elif func_name in {"subprocess.run", "subprocess.Popen", "subprocess.call", "subprocess.check_output"}:
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self._add(lineno, "PY002")

        elif func_name in {"os.system", "os.popen"}:
            self._add(lineno, "PY002")

        elif func_name.endswith((".execute", ".executemany", ".raw")) and node.args:
            first_arg = node.args[0]
            if self._is_dynamic_sql_expr(first_arg):
                self._add(lineno, "PY003")

        elif func_name in {"pickle.loads", "pickle.load", "yaml.unsafe_load"}:
            self._add(lineno, "PY004")

        elif func_name == "yaml.load":
            has_safe_loader = any(
                kw.arg == "Loader" and "Safe" in ast.unparse(kw.value)
                for kw in node.keywords
                if kw.value is not None
            )
            if not has_safe_loader:
                self._add(lineno, "PY004")

        elif func_name.endswith(("render_template_string", "mark_safe", "Markup")) and node.args:
            first_arg = node.args[0]
            if not isinstance(first_arg, ast.Constant):
                self._add(lineno, "PY005")

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        lineno = getattr(node, "lineno", 0)
        if self._is_dynamic_sql_expr(node.value):
            raw_line = self.lines[lineno - 1] if 1 <= lineno <= len(self.lines) else ""
            if SQL_KEYWORD_PATTERN.search(raw_line):
                self._add(lineno, "PY003")
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self._check_route_rate_limit(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self._check_route_rate_limit(node)
        self.generic_visit(node)

    def _check_route_rate_limit(self, node):
        if not node.decorator_list:
            return
        decorator_texts = [ast.unparse(dec) for dec in node.decorator_list]
        is_route = any(
            re.search(r"\b(?:app|router|bp|blueprint)\.(?:route|get|post|put|delete)\b", dec)
            for dec in decorator_texts
        )
        has_limiter_decorator = any(
            re.search(r"(?i)\b(?:limit|limiter|rate_limit|throttle)\b", dec)
            for dec in decorator_texts
        )
        if is_route and not has_limiter_decorator and not self.file_has_rate_limiter:
            self._add(
                node.lineno,
                "PY006",
                {
                    "id": "PY006",
                    "cwe": "CWE-770",
                    "title": "Web route handler missing rate-limiting decorator",
                    "severity": "medium",
                    "confidence": "medium",
                    "remediation": "Add a rate-limiting decorator (e.g. @limiter.limit('60/minute')) to protect the endpoint against automated DoS bursts.",
                },
            )

    @staticmethod
    def _call_name(func_node) -> str:
        if isinstance(func_node, ast.Name):
            return func_node.id
        if isinstance(func_node, ast.Attribute):
            parts = []
            curr = func_node
            while isinstance(curr, ast.Attribute):
                parts.append(curr.attr)
                curr = curr.value
            if isinstance(curr, ast.Name):
                parts.append(curr.id)
            return ".".join(reversed(parts))
        return ""

    @staticmethod
    def _is_dynamic_sql_expr(expr_node) -> bool:
        if isinstance(expr_node, ast.JoinedStr):
            return True
        if isinstance(expr_node, ast.BinOp) and isinstance(expr_node.op, (ast.Add, ast.Mod)):
            return True
        if isinstance(expr_node, ast.Call) and isinstance(expr_node.func, ast.Attribute) and expr_node.func.attr == "format":
            return True
        return False


def _iter_project_files(root: Path):
    for path in sorted(root.rglob("*")):
        if any(part in SKIP_DIRECTORIES for part in path.relative_to(root).parts):
            continue
        if path.is_file() and path.suffix.lower() in SOURCE_SUFFIXES | {".json", ".txt"}:
            try:
                max_bytes = MAX_LOCKFILE_BYTES if path.name in LOCKFILE_NAMES else MAX_FILE_BYTES
                if path.stat().st_size <= max_bytes:
                    yield path
            except OSError:
                continue


def _is_comment_line(extension: str, stripped_line: str) -> bool:
    if extension == ".py":
        return stripped_line.startswith("#")
    if extension in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}:
        return stripped_line.startswith(("//", "/*", "*"))
    return False


def _source_findings(relative_path: str, content: str):
    extension = Path(relative_path).suffix.lower()
    lines = content.splitlines()
    emitted_keys: set[tuple[int, str]] = set()
    ast_parsed_cleanly = False

    if extension == ".py":
        try:
            tree = ast.parse(content, filename=relative_path)
            visitor = _PythonSecurityAstVisitor(lines)
            visitor.visit(tree)
            ast_parsed_cleanly = True
            for (lineno, rule_id), item in sorted(visitor.findings_by_line_rule.items()):
                emitted_keys.add((lineno, rule_id))
                yield {
                    "rule_id": item["rule_id"],
                    "cwe": item["cwe"],
                    "title": item["title"],
                    "severity": item["severity"],
                    "confidence": item["confidence"],
                    "file": relative_path,
                    "line": item["line"],
                    "evidence": item["evidence"],
                    "remediation": item["remediation"],
                }
        except SyntaxError:
            ast_parsed_cleanly = False

    js_file_has_rate_limit = extension in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"} and any(
        token in content for token in ("rateLimit", "express-rate-limit", "rateLimiter", "slowDown")
    )
    js_cp_aliases = set(
        re.findall(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\(\s*['\"](?:node:)?child_process['\"]\s*\)", content)
    ) if extension in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"} else set()

    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or _is_comment_line(extension, stripped):
            continue
        for rule in RULES:
            if extension not in rule.get("extensions", SOURCE_SUFFIXES):
                continue
            rule_id = rule["id"]
            if ast_parsed_cleanly and rule_id in {"PY001", "PY002", "PY003", "PY004", "PY005"}:
                continue
            if rule_id == "JS005" and js_file_has_rate_limit:
                continue
            if (line_number, rule_id) in emitted_keys:
                continue
            matched = bool(rule["pattern"].search(line))
            if not matched and rule_id == "JS001" and js_cp_aliases:
                alias_pat = r"\b(?:" + "|".join(re.escape(a) for a in js_cp_aliases) + r")\s*\.\s*exec(?:Sync)?\s*\("
                matched = bool(re.search(alias_pat, line))
            if matched:
                evidence = stripped
                if rule_id == "SEC001":
                    secret_match = rule["pattern"].search(line)
                    evidence = f"{secret_match.group(1)} = '[REDACTED]'"
                else:
                    evidence = redact_line_secrets(stripped)
                emitted_keys.add((line_number, rule_id))
                yield {
                    "rule_id": rule_id,
                    "cwe": rule.get("cwe", "CWE-unknown"),
                    "title": rule["title"],
                    "severity": rule["severity"],
                    "confidence": rule["confidence"],
                    "file": relative_path,
                    "line": line_number,
                    "evidence": evidence[:240],
                    "remediation": rule["remediation"],
                }


def _lifecycle_script_findings(relative_path: str, content: str):
    if Path(relative_path).name != "package.json":
        return
    try:
        manifest = json.loads(content)
    except json.JSONDecodeError:
        return
    scripts = manifest.get("scripts")
    if not isinstance(scripts, dict):
        return
    lines = content.splitlines()
    for hook_name, command in scripts.items():
        if hook_name not in LIFECYCLE_HOOKS or not isinstance(command, str):
            continue
        line_number = next(
            (idx for idx, raw in enumerate(lines, start=1) if f'"{hook_name}"' in raw),
            1,
        )
        safe_cmd = redact_line_secrets(command.strip())[:180]
        if SUSPICIOUS_SCRIPT_PATTERN.search(command):
            yield {
                "rule_id": "PKG001",
                "cwe": "CWE-506",
                "title": f"Suspicious npm lifecycle script ({hook_name})",
                "severity": "high",
                "confidence": "high",
                "file": relative_path,
                "line": line_number,
                "evidence": f'"{hook_name}": "{safe_cmd}"',
                "remediation": "Inspect and remove network or shell execution commands from package lifecycle hooks; install packages with --ignore-scripts in untrusted environments.",
            }
        else:
            yield {
                "rule_id": "PKG002",
                "cwe": "CWE-829",
                "title": f"Package lifecycle hook declared ({hook_name})",
                "severity": "low",
                "confidence": "medium",
                "file": relative_path,
                "line": line_number,
                "evidence": f'"{hook_name}": "{safe_cmd}"',
                "remediation": "Verify that the lifecycle build hook only runs trusted local build tools.",
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
    started = time.perf_counter()
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
        if path.name == "package.json":
            findings.extend(_lifecycle_script_findings(relative_path, content))
        if path.name in {"requirements.txt", "package.json"} | LOCKFILE_NAMES:
            for dependency in _inventory_dependencies(path, content):
                dependency["manifest"] = relative_path
                dependencies.append(dependency)

    duration_ms = round((time.perf_counter() - started) * 1000, 2)
    return _report(root.name, files_scanned, findings, _prefer_npm_lock_versions(dependencies), duration_ms)


def scan_sources(project_name: str, files: list[dict]):
    started = time.perf_counter()
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
        if normalized.name == "package.json":
            findings.extend(_lifecycle_script_findings(normalized.as_posix(), content))
        if normalized.name in {"requirements.txt", "package.json"} | LOCKFILE_NAMES:
            for dependency in _inventory_dependencies(Path(normalized.name), content):
                dependency["manifest"] = normalized.as_posix()
                dependencies.append(dependency)

    duration_ms = round((time.perf_counter() - started) * 1000, 2)
    return _report(project_name, files_scanned, findings, _prefer_npm_lock_versions(dependencies), duration_ms)


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


def _report(project_name: str, files_scanned: int, findings: list, dependencies: list, scan_duration_ms: float = 0.0):
    return {
        "scanner_version": "0.2.0",
        "project": project_name,
        "files_scanned": files_scanned,
        "scan_duration_ms": scan_duration_ms,
        "findings": findings,
        "dependencies": dependencies,
        "dependency_check_status": "inventory_only; online checks were not requested",
    }
