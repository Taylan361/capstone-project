# AICodeShield (v0.2) — AI-Powered Automated Software Security Analysis Platform

A local-first, read-only security analysis platform for Python and Node.js repositories and authorized web endpoints. The scanner never executes submitted project code or package lifecycle scripts. It combines deterministic Python AST (`ast.NodeVisitor`) and JavaScript static rules, secret masking (`[REDACTED]` / `sk-****`), npm/PyPI dependency inventory and live OSV.dev advisory queries, SSRF-guarded GitHub repository archive intake, passive single-`GET` website header inspection, and human-gated Side-by-Side Red/Green AI candidate code diffs powered by DeepSeek (`deepseek-chat`).

## Module Structure

- `aicodeshield/scanner.py` — Hybrid Python AST (`_PythonSecurityAstVisitor`) & JavaScript/TypeScript static rules (`PY001`–`PY006`, `JS001`–`JS005`, `SEC001`, `PKG001`–`PKG002`), secret masking, and manifest/lockfile parser (`requirements.txt`, `package.json`, `package-lock.json`, `npm-shrinkwrap.json`).
- `aicodeshield/dependency_check.py` — Public registry lookups (npm, PyPI) and batch CVE/GHSA queries via `https://api.osv.dev/v1/querybatch` and `/v1/vulns/<id>`.
- `aicodeshield/intake.py` — SSRF validator (`validate_safe_public_url`), bounded in-memory GitHub ZIP archive extractor (`fetch_github_repository` with Zip-Slip & symlink protection), and explicit-authorization passive HTTP header inspector (`inspect_website_passive`, `WEB001`–`WEB006`).
- `aicodeshield/ai_remediation.py` — DeepSeek API (`deepseek-chat`, `temperature=0.1`) integration with outbound secret redaction, side-by-side `vulnerable_red` / `hardened_green` candidate diff generation, untrusted patch validation (`validate_candidate_patch`: syntax parse + security rule re-scan), and latency/token/cost telemetry.
- `server.py` — Local HTTP backend (`http://127.0.0.1:8765`) serving `/api/scan`, `/api/scan/github`, `/api/scan/website`, `/api/ai/remediate`, `/api/ai/status`, and `/api/health`.
- `web/src/App.jsx` & `web/src/styles.css` — React 19 + Vite 7 workbench with dual-mode intake tabs, OSV supply-chain panel, telemetry bar, side-by-side Red/Green diff viewer, validation badges, and mandatory human approval checkbox.
- `tests/` & `scripts/run_benchmark.py` — 19 unit/security tests and a 24-case positive/negative benchmark measuring Precision, Recall, F1, False-Positive Rate, Secret Masking Accuracy, and Patch Validation Pass Rate.

## Run

Install frontend dependencies once and build or start development mode:

```bash
npm --prefix web install
npm run build
npm run dev
```

Run CLI scanner, unit tests, and the quantitative benchmark:

```bash
python3 -m aicodeshield ./examples/demo-project --format text
python3 -m unittest discover -s tests -v
python3 scripts/run_benchmark.py
```
