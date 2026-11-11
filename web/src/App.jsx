import { useEffect, useMemo, useRef, useState } from 'react';

const SOURCE_SUFFIXES = new Set(['.py', '.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx', '.html', '.htm', '.json', '.txt']);
const SKIP_DIRECTORIES = new Set(['.git', 'node_modules', '.venv', 'venv', '__pycache__', '.mypy_cache', '.pytest_cache']);
const MAX_FILE_BYTES = 1024 * 1024;
const MAX_LOCKFILE_BYTES = 5 * 1024 * 1024;
const MAX_TOTAL_BYTES = 11 * 1024 * 1024;

function fileSizeLimit(file) {
  return ['package-lock.json', 'npm-shrinkwrap.json'].includes(file.name) ? MAX_LOCKFILE_BYTES : MAX_FILE_BYTES;
}

function Icon({ name, size = 18 }) {
  const paths = {
    shield: <><path d="M12 3 20 6v5c0 5-3.4 8.3-8 10-4.6-1.7-8-5-8-10V6l8-3Z"/><path d="m8.5 12 2.2 2.2 4.8-5"/></>,
    grid: <><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></>,
    scan: <><circle cx="10.8" cy="10.8" r="6.3"/><path d="m16 16 4 4M8 10.8h5.6M10.8 8v5.6"/></>,
    report: <><path d="M6 3h8l4 4v14H6z"/><path d="M14 3v5h5M9 13h6M9 17h6"/></>,
    settings: <><circle cx="12" cy="12" r="3"/><path d="m19.4 15 .1.1a1.7 1.7 0 0 1-2.4 2.4l-.1-.1a1.7 1.7 0 0 0-2.9 1.2v.2a1.7 1.7 0 0 1-3.4 0v-.2a1.7 1.7 0 0 0-2.9-1.2l-.1.1a1.7 1.7 0 0 1-2.4-2.4l.1-.1a1.7 1.7 0 0 0-1.2-2.9H4a1.7 1.7 0 0 1 0-3.4h.2a1.7 1.7 0 0 0 1.2-2.9l-.1-.1a1.7 1.7 0 0 1 2.4-2.4l.1.1a1.7 1.7 0 0 0 2.9-1.2V4a1.7 1.7 0 0 1 3.4 0v.2a1.7 1.7 0 0 0 2.9 1.2l.1-.1a1.7 1.7 0 0 1 2.4 2.4l-.1.1a1.7 1.7 0 0 0 1.2 2.9h.2a1.7 1.7 0 0 1 0 3.4h-.2a1.7 1.7 0 0 0-1.2 2.9Z"/></>,
    folder: <><path d="M3 6.5A1.5 1.5 0 0 1 4.5 5h5l2 2H19a2 2 0 1 1 2 2v8.5a1.5 1.5 0 0 1-1.5 1.5h-15A1.5 1.5 0 0 1 3 17.5z"/></>,
    arrow: <><path d="M5 12h14M13 6l6 6-6 6"/></>,
    lock: <><rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 1 1 8 0v3M12 14v3"/></>,
    clock: <><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></>,
    close: <><path d="m6 6 12 12M18 6 6 18"/></>,
    chevron: <path d="m9 18 6-6-6-6"/>,
    check: <path d="m5 12 4 4L19 6"/>,
  };
  return <svg aria-hidden="true" width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">{paths[name]}</svg>;
}

function fileIsSupported(file) {
  const path = file.webkitRelativePath || file.name;
  const parts = path.split('/');
  const suffix = `.${file.name.split('.').pop()}`.toLowerCase();
  return !parts.some((part) => SKIP_DIRECTORIES.has(part)) && SOURCE_SUFFIXES.has(suffix);
}

function App() {
  const fileInput = useRef(null);
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [filter, setFilter] = useState('all');
  const [onlineLookup, setOnlineLookup] = useState(false);
  const [aiConsent, setAiConsent] = useState(false);
  const [aiStatus, setAiStatus] = useState({ configured: false, model: 'deepseek-chat', api_model: 'deepseek-chat', temperature: 0.1 });
  const [aiReviews, setAiReviews] = useState({});
  const [aiDependencyReviews, setAiDependencyReviews] = useState({});
  const [aiTelemetry, setAiTelemetry] = useState(null);
  const [aiLoading, setAiLoading] = useState(false);
  const [activeNav, setActiveNav] = useState('Overview');
  const [intakeTab, setIntakeTab] = useState('folder');
  const [githubUrl, setGithubUrl] = useState('');
  const [websiteUrl, setWebsiteUrl] = useState('');
  const [websiteAuthorized, setWebsiteAuthorized] = useState(false);
  const [approvedPatches, setApprovedPatches] = useState({});
  const [copiedIndex, setCopiedIndex] = useState(null);

  const findings = report?.findings ?? [];
  const dependencies = report?.dependencies ?? [];
  const advisoryCount = dependencies.reduce((total, dependency) => total + (dependency.advisory_count ?? dependency.advisories?.length ?? 0), 0);
  const advisorySeverityRank = { critical: 4, high: 3, medium: 2, low: 1, unknown: 0 };
  const orderedDependencies = [...dependencies].sort((left, right) => {
    const leftSeverity = Math.max(0, ...(left.advisories || []).map((advisory) => advisorySeverityRank[advisory.severity] || 0));
    const rightSeverity = Math.max(0, ...(right.advisories || []).map((advisory) => advisorySeverityRank[advisory.severity] || 0));
    const countDifference = (right.advisory_count ?? right.advisories?.length ?? 0) - (left.advisory_count ?? left.advisories?.length ?? 0);
    return rightSeverity - leftSeverity || countDifference || left.name.localeCompare(right.name);
  });
  const counts = useMemo(() => ({
    all: findings.length,
    high: findings.filter((finding) => finding.severity === 'high').length,
    medium: findings.filter((finding) => finding.severity === 'medium').length,
    low: findings.filter((finding) => finding.severity === 'low').length,
  }), [findings]);
  const filteredFindings = filter === 'all' ? findings : findings.filter((finding) => finding.severity === filter);

  useEffect(() => {
    fetch('/api/ai/status')
      .then((response) => response.json())
      .then((status) => setAiStatus(status))
      .catch(() => setAiStatus({ configured: false, model: 'deepseek-chat', api_model: 'deepseek-chat', temperature: 0.1 }));
  }, []);

  function resetScanState() {
    setError('');
    setReport(null);
    setAiReviews({});
    setAiDependencyReviews({});
    setAiTelemetry(null);
    setApprovedPatches({});
  }

  async function scanSelectedFolder(event) {
    const selected = Array.from(event.target.files ?? []);
    event.target.value = '';
    resetScanState();
    if (!selected.length) return;

    const eligible = selected.filter(fileIsSupported).filter((file) => file.size <= fileSizeLimit(file));
    const tooLarge = selected.filter(fileIsSupported).filter((file) => file.size > fileSizeLimit(file)).length;
    const totalBytes = eligible.reduce((sum, file) => sum + file.size, 0);
    if (!eligible.length) {
      setError('No supported source or dependency manifest files were found in the selected folder.');
      return;
    }
    if (eligible.length > 1000) {
      setError('Please select a project with no more than 1,000 supported files.');
      return;
    }
    if (totalBytes > MAX_TOTAL_BYTES) {
      setError('The selected text files exceed the 11 MiB local scan limit.');
      return;
    }

    setLoading(true);
    try {
      const files = await Promise.all(eligible.map(async (file) => ({
        path: file.webkitRelativePath || file.name,
        content: await file.text(),
      })));
      const firstPath = files[0]?.path ?? 'Selected project';
      const projectName = firstPath.includes('/') ? firstPath.split('/')[0] : 'Selected project';
      const response = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ project: projectName, files, online_lookup: onlineLookup }),
      });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.error || 'The local scanner could not analyze this folder.');
      setReport({ ...payload, uploadedFiles: eligible.length, skippedLargeFiles: tooLarge, scanTime: new Date() });
      setFilter('all');
      setActiveNav('Overview');
    } catch (scanError) {
      setError(scanError.message || 'Unable to connect to the local scanner. Start the backend and try again.');
    } finally {
      setLoading(false);
    }
  }

  async function scanGithubRepo(event) {
    event.preventDefault();
    if (!githubUrl.trim()) return;
    resetScanState();
    setLoading(true);
    try {
      const response = await fetch('/api/scan/github', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ repo_url: githubUrl.trim(), online_lookup: onlineLookup }),
      });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.error || 'Could not scan the GitHub repository.');
      setReport({ ...payload, uploadedFiles: payload.files_scanned, skippedLargeFiles: 0, scanTime: new Date() });
      setFilter('all');
      setActiveNav('Overview');
    } catch (scanError) {
      setError(scanError.message || 'GitHub repository scan failed.');
    } finally {
      setLoading(false);
    }
  }

  async function scanWebsitePassive(event) {
    event.preventDefault();
    if (!websiteUrl.trim() || !websiteAuthorized) return;
    resetScanState();
    setLoading(true);
    try {
      const response = await fetch('/api/scan/website', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target_url: websiteUrl.trim(), authorized: websiteAuthorized }),
      });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.error || 'Passive website inspection failed.');
      setReport({ ...payload, uploadedFiles: 1, skippedLargeFiles: 0, scanTime: new Date() });
      setFilter('all');
      setActiveNav('Overview');
    } catch (scanError) {
      setError(scanError.message || 'Passive website inspection failed.');
    } finally {
      setLoading(false);
    }
  }

  async function requestAiRemediation() {
    if (!report || !aiConsent || !aiStatus.configured) return;
    setError('');
    setAiLoading(true);
    try {
      const response = await fetch('/api/ai/remediate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ findings: findings.slice(0, 20), dependencies }),
      });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.error || 'DeepSeek could not review these findings.');
      setAiReviews(Object.fromEntries((payload.reviews || []).filter((review) => review.item_type === 'finding').map((review) => [review.item_index, review])));
      setAiDependencyReviews(Object.fromEntries((payload.reviews || []).filter((review) => review.item_type === 'dependency').map((review) => [review.item_index, review])));
      setAiTelemetry(payload.telemetry || null);
    } catch (aiError) {
      setError(aiError.message || 'Could not connect to DeepSeek.');
    } finally {
      setAiLoading(false);
    }
  }

  function copyApprovedPatch(findingIndex, codeText) {
    if (!approvedPatches[findingIndex] || !codeText) return;
    navigator.clipboard?.writeText(codeText);
    setCopiedIndex(findingIndex);
    setTimeout(() => setCopiedIndex(null), 1800);
  }

  function downloadReport() {
    if (!report) return;
    const exportPayload = {
      ...report,
      ai_telemetry: aiTelemetry,
      ai_finding_reviews: aiReviews,
      ai_dependency_reviews: aiDependencyReviews,
    };
    const blob = new Blob([JSON.stringify(exportPayload, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `${(report.project || 'aicodeshield').replace(/[^a-zA-Z0-9_-]/g, '_')}-security-report.json`;
    link.click();
    URL.revokeObjectURL(url);
  }

  function navigate(label, target) {
    setActiveNav(label);
    document.getElementById(target)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand-lockup">
          <div className="brand-mark"><Icon name="shield" size={23} /></div>
          <div><div className="brand-name">AICodeShield</div><div className="brand-caption">SECURITY WORKBENCH</div></div>
        </div>
        <div className="nav-label">WORKSPACE</div>
        <nav className="main-nav" aria-label="Main navigation">
          <button className={`nav-item ${activeNav === 'Overview' ? 'active' : ''}`} onClick={() => navigate('Overview', 'overview')}><Icon name="grid" />Overview</button>
          <button className={`nav-item ${activeNav === 'Project scan' ? 'active' : ''}`} onClick={() => { setActiveNav('Project scan'); fileInput.current?.click(); }}><Icon name="scan" />Project scan</button>
          <button className={`nav-item ${activeNav === 'Findings' ? 'active' : ''}`} onClick={() => navigate('Findings', 'findings')}><Icon name="report" />Findings <span className="nav-count">{findings.length}</span></button>
          <button className={`nav-item ${activeNav === 'Dependencies' ? 'active' : ''}`} onClick={() => navigate('Dependencies', 'dependencies')}><Icon name="folder" />Dependencies</button>
        </nav>
        <div className="sidebar-bottom">
          <div className="local-card"><div className="local-card-icon"><Icon name="lock" size={17} /></div><div><strong>Read-only &amp; Safe</strong><p>Never executes repository code or lifecycle scripts.</p></div></div>
          <div className="profile-row"><div className="avatar">TC</div><div className="profile-text"><strong>Taylan Alp Çakı</strong><span>SE 401 Capstone · v0.2</span></div><span className="profile-dot" /></div>
        </div>
      </aside>

      <main className="main-content" id="overview">
        <header className="topbar">
          <div className="breadcrumb">Workspace <Icon name="chevron" size={14} /><span>{report?.project || 'Overview'}</span></div>
          <div className="topbar-right"><span className="privacy-pill"><span className="privacy-dot" />AST + OSV + AI DIFF</span><span className="topbar-divider" /><button className="icon-button" title="Settings" aria-label="Settings"><Icon name="settings" size={18} /></button></div>
        </header>

        <div className="page-wrap">
          <section className="hero-row">
            <div>
              <div className="eyebrow"><span className="eyebrow-line" />DUAL-MODE SECURITY ANALYSIS</div>
              <h1>Project security,<br /><span>made verifiable.</span></h1>
              <p className="hero-copy">Deterministic Python AST &amp; JS checks, OSV.dev supply-chain advisories, passive HTTP header inspection, and human-reviewed Red/Green AI remediation diffs.</p>
            </div>
            <div className="hero-actions">
              {report && <button className="button button-secondary" onClick={downloadReport}><Icon name="report" size={16} />Export JSON</button>}
              <button className="button button-primary" onClick={() => fileInput.current?.click()} disabled={loading}>
                {loading ? <span className="spinner" /> : <Icon name="scan" size={17} />}{loading ? 'Scanning…' : 'Scan local folder'}<Icon name="arrow" size={16} />
              </button>
              <input ref={fileInput} className="visually-hidden" type="file" webkitdirectory="" directory="" multiple onChange={scanSelectedFolder} aria-label="Choose a project folder" />
            </div>
          </section>

          <section className="intake-panel">
            <div className="intake-tabs" role="tablist">
              <button className={`intake-tab ${intakeTab === 'folder' ? 'active' : ''}`} onClick={() => setIntakeTab('folder')}>1. Local Project Folder</button>
              <button className={`intake-tab ${intakeTab === 'github' ? 'active' : ''}`} onClick={() => setIntakeTab('github')}>2. GitHub Repository URL</button>
              <button className={`intake-tab ${intakeTab === 'website' ? 'active' : ''}`} onClick={() => setIntakeTab('website')}>3. Passive Website Inspection</button>
            </div>
            {intakeTab === 'folder' && (
              <div className="intake-body">
                <span>Select a local Python/Node.js directory (`examples/demo-project`). Files are analyzed as UTF-8 text; `.git`, `node_modules`, and files over 1 MiB are skipped.</span>
                <button className="button button-secondary" onClick={() => fileInput.current?.click()} disabled={loading}>Choose Folder</button>
              </div>
            )}
            {intakeTab === 'github' && (
              <form className="intake-form" onSubmit={scanGithubRepo}>
                <input className="intake-input" type="url" placeholder="https://github.com/owner/repository" value={githubUrl} onChange={(e) => setGithubUrl(e.target.value)} required />
                <button className="button button-primary" type="submit" disabled={loading || !githubUrl.trim()}>Scan GitHub Repo</button>
                <small className="intake-hint">Safety controls: HTTPS allowlist (`github.com`/`codeload.github.com`), SSRF private-IP block, 15 MiB archive cap, Zip-Slip path traversal &amp; symlink rejection, zero script execution.</small>
              </form>
            )}
            {intakeTab === 'website' && (
              <form className="intake-form" onSubmit={scanWebsitePassive}>
                <input className="intake-input" type="url" placeholder="https://example.com (Authorized target only)" value={websiteUrl} onChange={(e) => setWebsiteUrl(e.target.value)} required />
                <label className="auth-check">
                  <input type="checkbox" checked={websiteAuthorized} onChange={(e) => setWebsiteAuthorized(e.target.checked)} />
                  <span>I confirm explicit authorization to inspect this host (Passive single-GET header check only; 0 active payloads)</span>
                </label>
                <button className="button button-primary" type="submit" disabled={loading || !websiteUrl.trim() || !websiteAuthorized}>Run Passive Check</button>
              </form>
            )}
          </section>

          <section className="lookup-control"><label className="lookup-choice"><input type="checkbox" checked={onlineLookup} onChange={(event) => setOnlineLookup(event.target.checked)} /><span className="lookup-copy"><strong>Check public registries and OSV.dev advisories</strong><small>Optional · sends declared package names and exact pinned versions to npm, PyPI, and OSV.dev (`/v1/querybatch`). Takes effect on the next scan.</small></span></label><span className={`lookup-state ${onlineLookup ? 'lookup-enabled' : ''}`}>{onlineLookup ? 'ONLINE CHECK ON' : 'OFF BY DEFAULT'}</span></section>
          <section className="ai-control"><div className="ai-control-copy"><strong>DeepSeek AI explanation and Untrusted Red/Green Patch Diff</strong><small>{aiStatus.configured ? `Connected model: ${aiStatus.api_model || aiStatus.model} (temp=${aiStatus.temperature ?? 0.1}). All AI patches are untrusted candidates validated via AST/syntax + security re-scan.` : 'Not configured yet. Add your key to the local .env file and restart the app.'}</small><small className="ai-data-note">With consent, up to 20 secret-masked (`[REDACTED]`) finding snippets and vulnerable dependency advisories are sent to DeepSeek. Requires human review before copying any patch.</small></div><label className="ai-consent"><input type="checkbox" checked={aiConsent} onChange={(event) => setAiConsent(event.target.checked)} /><span>I agree to send masked finding details to DeepSeek</span></label><button className="button button-secondary ai-button" onClick={requestAiRemediation} disabled={!report || (!findings.length && !advisoryCount) || !aiConsent || !aiStatus.configured || aiLoading}>{aiLoading ? 'Validating AI diffs…' : Object.keys(aiReviews).length || Object.keys(aiDependencyReviews).length ? 'Refresh AI recommendations' : 'Get AI recommendations'}</button></section>

          {aiTelemetry && (
            <section className="telemetry-bar" aria-label="LLM telemetry metrics">
              <span><strong>Model:</strong> <code>{aiTelemetry.model}</code></span>
              <span><strong>Temp:</strong> <code>{aiTelemetry.temperature}</code></span>
              <span><strong>API Latency:</strong> <code>{aiTelemetry.latency_ms} ms</code></span>
              <span><strong>Tokens:</strong> <code>{aiTelemetry.prompt_tokens} in / {aiTelemetry.completion_tokens} out ({aiTelemetry.total_tokens} total)</code></span>
              <span><strong>Est. Cost:</strong> <code>${aiTelemetry.estimated_cost_usd} USD</code></span>
            </section>
          )}

          {error && <div className="error-banner" role="alert"><span>{error}</span><button onClick={() => setError('')} aria-label="Dismiss error"><Icon name="close" size={16} /></button></div>}

          <section className="metrics-grid" aria-label="Scan summary">
            <article className="metric-card metric-total"><div className="metric-top"><span>FINDINGS</span><span className="metric-icon"><Icon name="report" /></span></div><div className="metric-value">{report ? counts.all : '—'}</div><div className="metric-foot">{report ? `Across ${report.files_scanned} scanned files (${report.scan_duration_ms ?? 0} ms)` : 'Run a scan to see results'}</div></article>
            <article className="metric-card"><div className="metric-top"><span>HIGH SEVERITY</span><span className="metric-signal signal-high" /></div><div className="metric-value">{report ? counts.high : '—'}</div><div className="metric-foot">Immediate review required</div></article>
            <article className="metric-card"><div className="metric-top"><span>MEDIUM SEVERITY</span><span className="metric-signal signal-medium" /></div><div className="metric-value">{report ? counts.medium : '—'}</div><div className="metric-foot">Defense-in-depth hardening</div></article>
            <article className="metric-card"><div className="metric-top"><span>DECLARED PACKAGES</span><span className="metric-icon"><Icon name="folder" /></span></div><div className="metric-value">{report ? dependencies.length : '—'}</div><div className="metric-foot">{report?.online_lookup ? `${advisoryCount} known OSV advisories` : 'Registry lookup is optional'}</div></article>
          </section>

          <section className="content-grid">
            <article className="panel findings-panel" id="findings">
              <div className="panel-heading"><div><div className="panel-kicker">ANALYSIS OUTPUT</div><h2>Security findings &amp; Red/Green Patch Diffs</h2><p>Evidence-linked AST, regex, supply-chain script, and passive HTTP checks.</p></div><button className="text-button" onClick={() => { setFilter('all'); navigate('Findings', 'findings'); }}>View all <Icon name="arrow" size={15} /></button></div>
              {report ? <>
                <div className="filter-row" role="group" aria-label="Filter findings by severity">
                  {[['all', 'All', counts.all], ['high', 'High', counts.high], ['medium', 'Medium', counts.medium], ['low', 'Low', counts.low]].map(([value, label, count]) => <button key={value} className={`filter-chip ${filter === value ? 'selected' : ''}`} onClick={() => setFilter(value)}>{label}<span>{count}</span></button>)}
                </div>
                {filteredFindings.length ? <div className="finding-list">{filteredFindings.map((finding, index) => {
                  const findingIndex = findings.indexOf(finding);
                  const aiReview = aiReviews[findingIndex];
                  const pv = aiReview?.patch_validation;
                  return (
                    <article className="finding-row" key={`${finding.rule_id}-${finding.file}-${finding.line}-${index}`}>
                      <span className={`severity-mark severity-${finding.severity}`} />
                      <div className="finding-main">
                        <div className="finding-title-row"><strong>{finding.title}</strong><span className={`severity-label label-${finding.severity}`}>{finding.severity}</span></div>
                        <div className="finding-location"><code>{finding.file}:{finding.line}</code><span>·</span><span>{finding.rule_id}</span>{finding.cwe && <><span>·</span><code>{finding.cwe}</code></>}<span>·</span><span>{finding.confidence} confidence</span></div>
                        <div className="finding-evidence">{finding.evidence}</div>
                        <div className="finding-fix"><span>STATIC RULE SUGGESTION</span>{finding.remediation}</div>
                        {aiReview && (
                          <div className="ai-review">
                            <div className="ai-review-heading">
                              <strong>DeepSeek Security Analysis</strong>
                              <span>{aiReview.priority} priority</span>
                              {aiReview.cwe !== 'unknown' && <code>{aiReview.cwe}</code>}
                              <span className="untrusted-badge">UNTRUSTED AI CANDIDATE</span>
                            </div>
                            {aiReview.explanation && <p>{aiReview.explanation}</p>}
                            {aiReview.remediation && <div><span>DEFENSIVE REMEDIATION</span>{aiReview.remediation}</div>}
                            {aiReview.vulnerable_red && aiReview.hardened_green && (
                              <div className="diff-container">
                                <div className="diff-box diff-red">
                                  <div className="diff-header">[-] Vulnerable Code (Red)</div>
                                  <pre><code>{aiReview.vulnerable_red}</code></pre>
                                </div>
                                <div className="diff-box diff-green">
                                  <div className="diff-header">[+] AI Hardened Candidate Fix (Green)</div>
                                  <pre><code>{aiReview.hardened_green}</code></pre>
                                </div>
                              </div>
                            )}
                            {pv && (
                              <div className="patch-validation-bar">
                                <div className="validation-badges">
                                  <span className={`v-badge ${pv.syntax_valid ? 'v-pass' : 'v-fail'}`}>Syntax Check: {pv.syntax_valid ? 'PASS' : 'FAIL'}</span>
                                  <span className={`v-badge ${pv.security_rescan_passed ? 'v-pass' : 'v-fail'}`}>Security Re-Scan: {pv.security_rescan_passed ? 'PASS (0 findings)' : 'FAIL'}</span>
                                </div>
                                <div className="human-gate">
                                  <label className="human-approve-label">
                                    <input
                                      type="checkbox"
                                      checked={!!approvedPatches[findingIndex]}
                                      onChange={(e) => setApprovedPatches((prev) => ({ ...prev, [findingIndex]: e.target.checked }))}
                                    />
                                    <span>Human review: I verified this untrusted candidate patch</span>
                                  </label>
                                  <button
                                    className="button button-secondary copy-patch-btn"
                                    disabled={!approvedPatches[findingIndex] || !pv.accepted_for_review}
                                    onClick={() => copyApprovedPatch(findingIndex, aiReview.hardened_green)}
                                  >
                                    {copiedIndex === findingIndex ? 'Copied!' : 'Copy Approved Patch'}
                                  </button>
                                </div>
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    </article>
                  );
                })}</div> : <div className="empty-findings"><div className="empty-icon"><Icon name="check" size={20} /></div><strong>{filter === 'all' ? 'No findings in the selected checks' : `No ${filter} findings`}</strong><span>This result covers only the rules currently implemented in the prototype.</span></div>}
              </> : <div className="scan-empty"><div className="scan-empty-art"><div className="scan-ring ring-one" /><div className="scan-ring ring-two" /><div className="scan-center"><Icon name="shield" size={29} /></div><span className="scan-spark spark-one" /><span className="scan-spark spark-two" /><span className="scan-spark spark-three" /></div><strong>No project scanned yet</strong><span>Select a project folder, enter a GitHub URL, or run a passive website header check.</span><button className="text-button" onClick={() => fileInput.current?.click()}>Choose folder <Icon name="arrow" size={15} /></button></div>}
              {report && <div className="panel-foot"><Icon name="clock" size={14} />Last scan {report.scanTime.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}<span className="foot-separator">·</span>{report.uploadedFiles} files ({report.scan_duration_ms ?? 0} ms){report.skippedLargeFiles > 0 && <><span className="foot-separator">·</span>{report.skippedLargeFiles} large files skipped</>}</div>}
            </article>

            <div className="right-column">
              <article className="panel project-panel"><div className="panel-heading compact-heading"><div><div className="panel-kicker">CURRENT TARGET</div><h2>{report?.project || 'No project selected'}</h2></div><span className={`project-status ${report ? 'status-complete' : ''}`}><span />{report ? 'Scanned' : 'Waiting'}</span></div>
                {report ? <div className="project-stats"><div><span>Intake mode</span><strong>{report.intake_mode || 'local_folder'}</strong></div><div><span>Files analyzed</span><strong>{report.files_scanned}</strong></div><div><span>Scan duration</span><strong>{report.scan_duration_ms ?? 0} ms</strong></div><div><span>Dependencies found</span><strong>{dependencies.length}</strong></div><div><span>Scanner version</span><strong>{report.scanner_version}</strong></div></div> : <div className="project-placeholder"><Icon name="folder" size={17} /><span>Project details appear after the first scan.</span></div>}
                <button className="project-scan-link" onClick={() => fileInput.current?.click()}><span>{report ? 'Scan another project' : 'Select project folder'}</span><Icon name="arrow" size={16} /></button>
              </article>

              <article className="panel dependencies-panel" id="dependencies"><div className="panel-heading compact-heading"><div><div className="panel-kicker">SUPPLY CHAIN</div><h2>Dependencies</h2></div><span className="inventory-badge">{report?.online_lookup ? 'LOOKUP COMPLETE' : 'INVENTORY'}</span></div><div className={`dependency-note ${report?.online_lookup?.status === 'unavailable' ? 'dependency-note-warning' : ''}`}><span className="note-dot" /><span>{!report?.online_lookup ? <>Online checks are off. No package names are sent to public services.</> : report.online_lookup.status === 'unavailable' ? <>The advisory service could not complete the check. Results may be partial.</> : <>Checked against public registries and OSV.dev. A package absent publicly may still be private or internal.</>}</span></div>
                {dependencies.length ? <div className="dependency-list">{orderedDependencies.slice(0, 8).map((dependency, index) => <div className={`dependency-row ${dependency.advisory_count ? 'dependency-row-vulnerable' : ''}`} key={`${dependency.name}-${index}`}><div className="package-glyph">{dependency.name.slice(0, 1).toUpperCase()}</div><div className="package-detail"><div className="package-line"><div className="package-name"><strong>{dependency.name}</strong><span>{dependency.manifest}{dependency.section ? ` · ${dependency.section}` : ''}</span></div><code>{dependency.declared_version || 'version not pinned'}</code></div>{report?.online_lookup && <div className="package-checks"><span className={`check-status check-${dependency.registry_status || 'not_checked'}`}>{dependency.registry_status === 'found_public' ? 'Public package found' : dependency.registry_status === 'not_found_public' ? 'Not found publicly' : dependency.registry_status === 'lookup_unavailable' ? 'Registry unavailable' : dependency.registry_status === 'not_checked_limit' ? 'Lookup limit reached' : 'Not checked'}</span>{dependency.version_status === 'update_available' && <span className="check-status check-update">Latest: {dependency.latest_version}</span>}{dependency.version_status === 'current' && <span className="check-status check-safe">Latest: {dependency.latest_version}</span>}{dependency.pinned_version && <span className={`check-status ${dependency.advisory_count ? 'check-vulnerable' : dependency.advisory_status === 'checked_no_known_advisories' ? 'check-safe' : 'check-pending'}`}>{dependency.advisory_count ? `${dependency.advisory_count} known ${dependency.advisory_count === 1 ? 'advisory' : 'advisories'}` : dependency.advisory_status === 'checked_no_known_advisories' ? 'No known advisory found' : dependency.advisory_status === 'lookup_unavailable' ? 'Advisory lookup unavailable' : 'Advisory status unknown'}</span>}{!dependency.pinned_version && <span className="check-status check-pending">Exact version needed for advisory check</span>}</div>}{dependency.advisories?.map((advisory) => <div className="advisory-item" key={advisory.id}><span className={`advisory-severity advisory-${advisory.severity}`}>{advisory.severity}</span><strong>{advisory.id}</strong>{advisory.aliases?.find((alias) => alias.startsWith('CVE-')) && <span>{advisory.aliases.find((alias) => alias.startsWith('CVE-'))}</span>}<p>{advisory.summary}</p>{advisory.fixed_versions?.length > 0 && <p>Known fixed version(s): {advisory.fixed_versions.join(', ')}</p>}{advisory.references?.[0]?.url && <a href={advisory.references[0].url} target="_blank" rel="noreferrer">Open advisory source</a>}</div>)}{dependency.advisory_details_truncated && <div className="dependency-caveat">More matching advisories exist; details are limited in this prototype.</div>}{dependency.registry_note && <div className="dependency-caveat">{dependency.registry_note}</div>}</div></div>)}{dependencies.length > 8 && <div className="more-packages">+ {dependencies.length - 8} more dependencies in the JSON report</div>}</div> : <div className="dependency-empty">{report ? 'No supported dependency manifest was found.' : 'No dependency inventory yet.'}</div>}
                {Object.keys(aiDependencyReviews).length > 0 && <div className="ai-dependency-list">{dependencies.map((dependency, index) => { const suggestion = aiDependencyReviews[index]; return suggestion ? <div className="ai-dependency-review" key={`${dependency.name}-${index}`}><strong>{dependency.name} · {dependency.pinned_version || dependency.declared_version}</strong>{suggestion.explanation && <p>{suggestion.explanation}</p>}{suggestion.remediation && <div><span>RECOMMENDED ACTION</span>{suggestion.remediation}</div>}</div> : null; })}</div>}
              </article>
            </div>
          </section>

          <footer className="page-footer"><span>AI-CODE-SHIELD v0.2 <span className="footer-separator">/</span> SE 401 CAPSTONE PROTOTYPE</span><span>Read-only AST &amp; passive checks · No script execution · Human-gated AI diffs</span></footer>
        </div>
      </main>
    </div>
  );
}

export default App;
