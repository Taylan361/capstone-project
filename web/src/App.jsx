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
    folder: <><path d="M3 6.5A1.5 1.5 0 0 1 4.5 5h5l2 2H19a2 2 0 0 1 2 2v8.5a1.5 1.5 0 0 1-1.5 1.5h-15A1.5 1.5 0 0 1 3 17.5z"/></>,
    globe: <><circle cx="12" cy="12" r="9"/><path d="M3.6 9h16.8M3.6 15h16.8M12 3a14.5 14.5 0 0 0 0 18M12 3a14.5 14.5 0 0 1 0 18"/></>,
    git: <><circle cx="6" cy="6" r="2.5"/><circle cx="18" cy="6" r="2.5"/><circle cx="6" cy="18" r="2.5"/><path d="M6 8.5v7M18 8.5c0 4.5-12 2.5-12 7"/></>,
    spark: <><path d="m12 3 1.9 5.1L19 10l-5.1 1.9L12 17l-1.9-5.1L5 10l5.1-1.9L12 3Z"/></>,
    arrow: <><path d="M5 12h14M13 6l6 6-6 6"/></>,
    lock: <><rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 1 1 8 0v3M12 14v3"/></>,
    clock: <><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></>,
    close: <><path d="m6 6 12 12M18 6 6 18"/></>,
    chevronDown: <path d="m6 9 6 6 6-6"/>,
    chevronRight: <path d="m9 18 6-6-6-6"/>,
    check: <path d="m5 12 4 4L19 6"/>,
  };
  return <svg aria-hidden="true" width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">{paths[name]}</svg>;
}

function fileIsSupported(file) {
  const path = file.webkitRelativePath || file.name;
  const parts = path.split('/');
  const suffix = `.${file.name.split('.').pop()}`.toLowerCase();
  return !parts.some((part) => SKIP_DIRECTORIES.has(part)) && SOURCE_SUFFIXES.has(suffix);
}

function categoryForFinding(finding) {
  const rule = finding.rule_id || '';
  if (rule === 'PY005' || rule === 'JS003' || rule === 'WEB006') return 'Cross-Site Scripting (XSS)';
  if (rule === 'PY001' || rule === 'PY002' || rule === 'PY003' || rule === 'PY004' || rule === 'JS001' || rule === 'JS002' || rule === 'JS004') {
    return 'Code & SQL / Command Injection';
  }
  if (rule === 'SEC001') return 'Hardcoded Secrets & Keys';
  if (rule === 'PKG001' || rule === 'PKG002') return 'Supply-Chain & Lifecycle Scripts';
  return 'Rate-Limiting & Security Headers';
}

function App() {
  const fileInput = useRef(null);
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [filter, setFilter] = useState('all');
  const [groupByCategory, setGroupByCategory] = useState(true);
  const [onlineLookup, setOnlineLookup] = useState(true);
  const [aiConsent, setAiConsent] = useState(true);
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
  const [expandedFindings, setExpandedFindings] = useState({});
  const [expandedDeps, setExpandedDeps] = useState({});
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

  const filteredFindings = useMemo(
    () => (filter === 'all' ? findings : findings.filter((finding) => finding.severity === filter)),
    [findings, filter]
  );

  const groupedFindings = useMemo(() => {
    if (!groupByCategory) {
      return [['All Detected Findings', filteredFindings]];
    }
    const groups = new Map();
    for (const item of filteredFindings) {
      const cat = categoryForFinding(item);
      if (!groups.has(cat)) groups.set(cat, []);
      groups.get(cat).push(item);
    }
    return Array.from(groups.entries());
  }, [filteredFindings, groupByCategory]);

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
    setExpandedFindings({});
    setExpandedDeps({});
    setApprovedPatches({});
  }

  function toggleFinding(idx) {
    setExpandedFindings((prev) => ({ ...prev, [idx]: !prev[idx] }));
  }

  function toggleAllFindings() {
    const anyOpen = Object.values(expandedFindings).some(Boolean);
    if (anyOpen) {
      setExpandedFindings({});
    } else {
      const next = {};
      findings.forEach((_, idx) => { next[idx] = true; });
      setExpandedFindings(next);
    }
  }

  function toggleDep(idx) {
    setExpandedDeps((prev) => ({ ...prev, [idx]: !prev[idx] }));
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
      setError('No supported source or manifest files were found in the selected folder.');
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
    } catch (scanError) {
      setError(scanError.message || 'Unable to connect to the local scanner.');
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
      const findingMap = Object.fromEntries((payload.reviews || []).filter((review) => review.item_type === 'finding').map((review) => [review.item_index, review]));
      setAiReviews(findingMap);
      setAiDependencyReviews(Object.fromEntries((payload.reviews || []).filter((review) => review.item_type === 'dependency').map((review) => [review.item_index, review])));
      setAiTelemetry(payload.telemetry || null);
      // Automatically expand the first finding so the user sees the Red/Green diff immediately
      if (Object.keys(findingMap).length > 0) {
        const firstKey = Object.keys(findingMap)[0];
        setExpandedFindings((prev) => ({ ...prev, [firstKey]: true }));
      }
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
          <div><div className="brand-name">AICodeShield</div><div className="brand-caption">SECURITY PLATFORM</div></div>
        </div>
        <div className="nav-label">MENÜ</div>
        <nav className="main-nav" aria-label="Main navigation">
          <button className={`nav-item ${activeNav === 'Overview' ? 'active' : ''}`} onClick={() => navigate('Overview', 'overview')}><Icon name="grid" />Genel Bakış</button>
          <button className={`nav-item ${activeNav === 'Project scan' ? 'active' : ''}`} onClick={() => { setActiveNav('Project scan'); fileInput.current?.click(); }}><Icon name="scan" />Klasör Seç &amp; Tara</button>
          <button className={`nav-item ${activeNav === 'Findings' ? 'active' : ''}`} onClick={() => navigate('Findings', 'findings')}><Icon name="report" />Güvenlik Bulguları <span className="nav-count">{findings.length}</span></button>
          <button className={`nav-item ${activeNav === 'Dependencies' ? 'active' : ''}`} onClick={() => navigate('Dependencies', 'dependencies')}><Icon name="folder" />Kütüphaneler (CVE) <span className="nav-count">{dependencies.length}</span></button>
        </nav>
        <div className="sidebar-bottom">
          <div className="local-card">
            <div className="local-card-icon"><Icon name="lock" size={17} /></div>
            <div>
              <strong>Güvenli &amp; Salt-Okunur</strong>
              <p>Kodlar çalıştırılmaz; gizli anahtarlar ([REDACTED]) maskelenir.</p>
            </div>
          </div>
          <div className="profile-row">
            <div className="avatar">TC</div>
            <div className="profile-text">
              <strong>Taylan Alp Çakı</strong>
              <span>SE 401 Capstone · v0.2</span>
            </div>
            <span className="profile-dot" />
          </div>
        </div>
      </aside>

      <main className="main-content" id="overview">
        <header className="topbar">
          <div className="breadcrumb">
            Workspace <Icon name="chevronRight" size={14} />
            <span>{report?.project || 'Tarama Bekleniyor'}</span>
          </div>
          <div className="topbar-right">
            <span className="privacy-pill"><span className="privacy-dot" />AST + OSV.DEV + AI AUTO-FIX</span>
            {report && (
              <button className="button button-secondary btn-sm" onClick={downloadReport}>
                <Icon name="report" size={14} /> JSON İndir
              </button>
            )}
          </div>
        </header>

        <div className="page-wrap">
          {/* ÜST KONTROL PANELİ: 2 NET VE DÜZENLİ KART */}
          <section className="control-dock">
            {/* SOL KART: TARAMA HEDEFİ SEÇİMİ */}
            <div className="dock-card">
              <div className="dock-header">
                <div>
                  <span className="dock-kicker">ADIM 1 · TARAMA HEDEFİ</span>
                  <h2>Proje veya Site Analizi Başlat</h2>
                </div>
                <label className="osv-toggle" title="Paket sürümlerini npm, PyPI ve Google OSV.dev üzerinde sorgular">
                  <input type="checkbox" checked={onlineLookup} onChange={(e) => setOnlineLookup(e.target.checked)} />
                  <span>OSV.dev CVE Kontrolü {onlineLookup ? 'Açık' : 'Kapalı'}</span>
                </label>
              </div>

              <div className="intake-tabs" role="tablist">
                <button type="button" className={`intake-tab ${intakeTab === 'folder' ? 'active' : ''}`} onClick={() => setIntakeTab('folder')}>
                  <Icon name="folder" size={15} /> Klasör Yükle
                </button>
                <button type="button" className={`intake-tab ${intakeTab === 'github' ? 'active' : ''}`} onClick={() => setIntakeTab('github')}>
                  <Icon name="git" size={15} /> GitHub Repo URL
                </button>
                <button type="button" className={`intake-tab ${intakeTab === 'website' ? 'active' : ''}`} onClick={() => setIntakeTab('website')}>
                  <Icon name="globe" size={15} /> Website URL (Pasif)
                </button>
              </div>

              <div className="dock-body">
                {intakeTab === 'folder' && (
                  <div className="folder-action-row">
                    <div className="folder-desc">
                      <strong>Yerel Proje Klasörü Tara</strong>
                      <span>Python, JS/TS, HTML ve `package.json` / `requirements.txt` dosyalarını inceler.</span>
                    </div>
                    <button className="button button-primary" onClick={() => fileInput.current?.click()} disabled={loading}>
                      {loading ? <span className="spinner" /> : <Icon name="scan" size={16} />}
                      {loading ? 'Taranıyor…' : 'Klasör Seç ve Tara'}
                    </button>
                    <input ref={fileInput} className="visually-hidden" type="file" webkitdirectory="" directory="" multiple onChange={scanSelectedFolder} aria-label="Choose a project folder" />
                  </div>
                )}

                {intakeTab === 'github' && (
                  <form className="intake-form" onSubmit={scanGithubRepo}>
                    <input className="intake-input" type="url" placeholder="https://github.com/kullanici/proje" value={githubUrl} onChange={(e) => setGithubUrl(e.target.value)} required />
                    <button className="button button-primary" type="submit" disabled={loading || !githubUrl.trim()}>
                      {loading ? 'İndiriliyor…' : 'GitHub Reposunu Tara'}
                    </button>
                    <small className="intake-hint">SSRF ve Zip-Slip korumalı; arşiv bellekte açılır, hiçbir script çalıştırılmaz.</small>
                  </form>
                )}

                {intakeTab === 'website' && (
                  <form className="intake-form" onSubmit={scanWebsitePassive}>
                    <input className="intake-input" type="url" placeholder="https://ornek-site.com" value={websiteUrl} onChange={(e) => setWebsiteUrl(e.target.value)} required />
                    <button className="button button-primary" type="submit" disabled={loading || !websiteUrl.trim() || !websiteAuthorized}>
                      {loading ? 'Kontrol Ediliyor…' : 'Pasif Kontrol Başlat'}
                    </button>
                    <label className="auth-check">
                      <input type="checkbox" checked={websiteAuthorized} onChange={(e) => setWebsiteAuthorized(e.target.checked)} />
                      <span>Bu hedefi denetlemek için yetkim olduğunu onaylıyorum (Sadece tekil GET başlık kontrolü yapılır).</span>
                    </label>
                  </form>
                )}
              </div>
            </div>

            {/* SAĞ KART: DEEPSEEK AI ÇÖZÜM VE DIFF MOTORU */}
            <div className="dock-card ai-dock-card">
              <div className="dock-header">
                <div>
                  <span className="dock-kicker">ADIM 2 · YAPAY ZEKA YAMA MOTORU</span>
                  <h2>DeepSeek Kırmızı / Yeşil Kod Yaması</h2>
                </div>
                <span className={`ai-badge ${aiStatus.configured ? 'ai-ready' : ''}`}>
                  {aiStatus.configured ? `Model: ${aiStatus.api_model || aiStatus.model}` : 'API Anahtarı Yok'}
                </span>
              </div>

              <p className="ai-dock-desc">
                Tespit edilen güvenlik açıkları için <strong>Kırmızı (Zafiyetli Kod)</strong> ve <strong>Yeşil (Güvenli Kod Önerisi)</strong> karşılaştırması üretir. Üretilen her kod otomatik <em>Syntax Check</em> ve <em>Security Re-Scan</em> kontrolünden geçer.
              </p>

              <div className="ai-dock-Footer">
                <label className="ai-consent">
                  <input type="checkbox" checked={aiConsent} onChange={(e) => setAiConsent(e.target.checked)} />
                  <span>Maskelenmiş (`[REDACTED]`) bulguların DeepSeek API&apos;ye gönderilmesini onaylıyorum</span>
                </label>
                <button
                  className="button button-primary ai-trigger-btn"
                  onClick={requestAiRemediation}
                  disabled={!report || (!findings.length && !advisoryCount) || !aiConsent || !aiStatus.configured || aiLoading}
                >
                  <Icon name="spark" size={16} />
                  {aiLoading ? 'AI Yamaları Hazırlanıyor…' : Object.keys(aiReviews).length ? 'AI Çözümlerini Yenile' : 'AI Çözüm ve Kod Yaması Üret'}
                </button>
              </div>

              {aiTelemetry && (
                <div className="telemetry-strip">
                  <span>Süre: <strong>{aiTelemetry.latency_ms} ms</strong></span>
                  <span>Token: <strong>{aiTelemetry.total_tokens}</strong> ({aiTelemetry.prompt_tokens} in / {aiTelemetry.completion_tokens} out)</span>
                  <span>Maliyet: <strong>${aiTelemetry.estimated_cost_usd}</strong></span>
                </div>
              )}
            </div>
          </section>

          {error && (
            <div className="error-banner" role="alert">
              <span>{error}</span>
              <button onClick={() => setError('')} aria-label="Dismiss error"><Icon name="close" size={16} /></button>
            </div>
          )}

          {/* ÖZET METRİK KARTLARI */}
          <section className="metrics-grid" aria-label="Scan summary">
            <article className="metric-card metric-total">
              <div className="metric-top"><span>TOPLAM BULGU</span><span className="metric-icon"><Icon name="report" /></span></div>
              <div className="metric-value">{report ? counts.all : '—'}</div>
              <div className="metric-foot">{report ? `${report.files_scanned} dosya tarandı (${report.scan_duration_ms ?? 0} ms)` : 'Henüz tarama yapılmadı'}</div>
            </article>
            <article className="metric-card">
              <div className="metric-top"><span>YÜKSEK RİSK (HIGH)</span><span className="metric-signal signal-high" /></div>
              <div className="metric-value">{report ? counts.high : '—'}</div>
              <div className="metric-foot">Öncelikli düzeltilmeli</div>
            </article>
            <article className="metric-card">
              <div className="metric-top"><span>ORTA RİSK (MEDIUM)</span><span className="metric-signal signal-medium" /></div>
              <div className="metric-value">{report ? counts.medium : '—'}</div>
              <div className="metric-foot">Savunma derinliği</div>
            </article>
            <article className="metric-card">
              <div className="metric-top"><span>PAKET &amp; CVE (OSV)</span><span className="metric-icon"><Icon name="folder" /></span></div>
              <div className="metric-value">{report ? dependencies.length : '—'}</div>
              <div className="metric-foot">{report?.online_lookup ? `${advisoryCount} bilinen CVE/GHSA açığı` : 'Sadece envanter listelendi'}</div>
            </article>
          </section>

          {/* ANA İÇERİK: SOLDA GRUPLU VE AÇILIR/KAPANIR BULGULAR, SAĞDA KÜTÜPHANELER */}
          <section className="content-grid">
            <article className="panel findings-panel" id="findings">
              <div className="panel-heading">
                <div>
                  <div className="panel-kicker">GÜVENLİK RAPORU</div>
                  <h2>Tespit Edilen Güvenlik Açıkları</h2>
                  <p>Başlığa tıklayarak kod detayını ve Kırmızı/Yeşil AI yamasını açıp kapatabilirsiniz.</p>
                </div>
                {report && findings.length > 0 && (
                  <div className="heading-controls">
                    <button type="button" className={`chip-toggle ${groupByCategory ? 'active' : ''}`} onClick={() => setGroupByCategory(!groupByCategory)}>
                      {groupByCategory ? 'Kategoriye Göre Gruplu' : 'Düz Liste'}
                    </button>
                    <button type="button" className="chip-toggle" onClick={toggleAllFindings}>
                      {Object.values(expandedFindings).some(Boolean) ? 'Tümünü Daralt' : 'Tümünü Aç'}
                    </button>
                  </div>
                )}
              </div>

              {report ? (
                <>
                  <div className="filter-row" role="group" aria-label="Filter findings by severity">
                    {[
                      ['all', 'Tümü', counts.all],
                      ['high', 'Yüksek (High)', counts.high],
                      ['medium', 'Orta (Medium)', counts.medium],
                      ['low', 'Düşük (Low)', counts.low],
                    ].map(([value, label, count]) => (
                      <button key={value} className={`filter-chip ${filter === value ? 'selected' : ''}`} onClick={() => setFilter(value)}>
                        {label}<span>{count}</span>
                      </button>
                    ))}
                  </div>

                  {filteredFindings.length ? (
                    <div className="finding-groups">
                      {groupedFindings.map(([groupName, groupItems]) => (
                        <div className="finding-group" key={groupName}>
                          <div className="group-header">
                            <strong>{groupName}</strong>
                            <span className="group-count">{groupItems.length} bulgu</span>
                          </div>

                          <div className="finding-list">
                            {groupItems.map((finding, idx) => {
                              const findingIndex = findings.indexOf(finding);
                              const isExpanded = !!expandedFindings[findingIndex];
                              const aiReview = aiReviews[findingIndex];
                              const pv = aiReview?.patch_validation;

                              return (
                                <article className={`finding-card ${isExpanded ? 'is-open' : ''}`} key={`${finding.rule_id}-${finding.file}-${finding.line}-${idx}`}>
                                  {/* SADE BAŞLIK SATIRI (COLLAPSED VIEW) */}
                                  <button type="button" className="finding-summary-bar" onClick={() => toggleFinding(findingIndex)}>
                                    <span className={`severity-pill label-${finding.severity}`}>{finding.severity}</span>
                                    <div className="summary-title-wrap">
                                      <strong className="summary-title">{finding.title}</strong>
                                      <span className="summary-meta">
                                        <code>{finding.file}:{finding.line}</code>
                                        <span>·</span>
                                        <span>{finding.rule_id}</span>
                                        {finding.cwe && <><span>·</span><code>{finding.cwe}</code></>}
                                      </span>
                                    </div>
                                    <div className="summary-right">
                                      {aiReview && <span className="ai-ready-pill">AI Yaması Hazır</span>}
                                      <span className="expand-label">{isExpanded ? 'Gizle' : 'Detay'}</span>
                                      <span className={`chevron-icon ${isExpanded ? 'rotated' : ''}`}>
                                        <Icon name="chevronDown" size={16} />
                                      </span>
                                    </div>
                                  </button>

                                  {/* AÇILIR DETAY ALANI (EXPANDED VIEW) */}
                                  {isExpanded && (
                                    <div className="finding-details-body">
                                      <div className="detail-grid">
                                        <div className="detail-box">
                                          <span className="detail-label">TESPİT EDİLEN KOD SATIRI ({finding.file}:{finding.line})</span>
                                          <div className="finding-evidence">{finding.evidence}</div>
                                        </div>
                                        <div className="detail-box">
                                          <span className="detail-label">HIZLI ÇÖZÜM ÖNERİSİ ({finding.confidence} güven)</span>
                                          <p className="static-remediation">{finding.remediation}</p>
                                        </div>
                                      </div>

                                      {aiReview ? (
                                        <div className="ai-review">
                                          <div className="ai-review-heading">
                                            <strong>✨ DeepSeek AI Analizi ve Otomatik Kod Yaması</strong>
                                            <span>{aiReview.priority} öncelik</span>
                                            {aiReview.cwe !== 'unknown' && <code>{aiReview.cwe}</code>}
                                            <span className="untrusted-badge">ADAY YAMA (İNSAN ONAYI GEREKLİ)</span>
                                          </div>

                                          {aiReview.explanation && <p className="ai-explanation">{aiReview.explanation}</p>}

                                          {aiReview.vulnerable_red && aiReview.hardened_green && (
                                            <div className="diff-container">
                                              <div className="diff-box diff-red">
                                                <div className="diff-header">[-] Zafiyetli Kod (Kırmızı)</div>
                                                <pre><code>{aiReview.vulnerable_red}</code></pre>
                                              </div>
                                              <div className="diff-box diff-green">
                                                <div className="diff-header">[+] Güçlendirilmiş Güvenli Kod (Yeşil)</div>
                                                <pre><code>{aiReview.hardened_green}</code></pre>
                                              </div>
                                            </div>
                                          )}

                                          {aiReview.remediation && (
                                            <div className="ai-remediation-note">
                                              <span>UYGULAMA NOTU</span>
                                              {aiReview.remediation}
                                            </div>
                                          )}

                                          {pv && (
                                            <div className="patch-validation-bar">
                                              <div className="validation-badges">
                                                <span className={`v-badge ${pv.syntax_valid ? 'v-pass' : 'v-fail'}`}>
                                                  Syntax Kontrolü: {pv.syntax_valid ? 'GEÇTİ (PASS)' : 'HATA'}
                                                </span>
                                                <span className={`v-badge ${pv.security_rescan_passed ? 'v-pass' : 'v-fail'}`}>
                                                  Güvenlik Tekrar Taraması: {pv.security_rescan_passed ? 'TEMİZ (0 açık)' : 'UYARI'}
                                                </span>
                                              </div>
                                              <div className="human-gate">
                                                <label className="human-approve-label">
                                                  <input
                                                    type="checkbox"
                                                    checked={!!approvedPatches[findingIndex]}
                                                    onChange={(e) => setApprovedPatches((prev) => ({ ...prev, [findingIndex]: e.target.checked }))}
                                                  />
                                                  <span>Yeşil kodu inceledim ve onaylıyorum</span>
                                                </label>
                                                <button
                                                  type="button"
                                                  className="button button-primary copy-patch-btn"
                                                  disabled={!approvedPatches[findingIndex] || !pv.accepted_for_review}
                                                  onClick={() => copyApprovedPatch(findingIndex, aiReview.hardened_green)}
                                                >
                                                  {copiedIndex === findingIndex ? '✓ Kopyalandı!' : 'Onaylı Yamayı Kopyala'}
                                                </button>
                                              </div>
                                            </div>
                                          )}
                                        </div>
                                      ) : (
                                        <div className="ai-prompt-hint">
                                          <span>Bu bulgu için Kırmızı/Yeşil kod yaması görmek isterseniz üstteki <strong>&ldquo;AI Çözüm ve Kod Yaması Üret&rdquo;</strong> butonuna tıklayın.</span>
                                        </div>
                                      )}
                                    </div>
                                  )}
                                </article>
                              );
                            })}
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="empty-findings">
                      <div className="empty-icon"><Icon name="check" size={20} /></div>
                      <strong>Seçili filtrede güvenlik açığı bulunmadı</strong>
                      <span>Farklı bir filtre seçebilir veya yeni bir proje tarayabilirsiniz.</span>
                    </div>
                  )}
                </>
              ) : (
                <div className="scan-empty">
                  <div className="scan-empty-art">
                    <div className="scan-ring ring-one" />
                    <div className="scan-ring ring-two" />
                    <div className="scan-center"><Icon name="shield" size={29} /></div>
                  </div>
                  <strong>Henüz bir proje taranmadı</strong>
                  <span>Üstteki panelden bir klasör seçin (`acikli-site` veya `demo-project`), GitHub URL girin ya da Website kontrolü başlatın.</span>
                  <button className="text-button" onClick={() => fileInput.current?.click()}>Klasör Seç <Icon name="arrow" size={15} /></button>
                </div>
              )}

              {report && (
                <div className="panel-foot">
                  <Icon name="clock" size={14} />
                  Son tarama: {report.scanTime.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                  <span className="foot-separator">·</span>
                  {report.uploadedFiles} dosya ({report.scan_duration_ms ?? 0} ms)
                </div>
              )}
            </article>

            {/* SAĞ SÜTUN: HEDEF ÖZETİ & KÜTÜPHANE / CVE LİSTESİ */}
            <div className="right-column">
              <article className="panel project-panel">
                <div className="panel-heading compact-heading">
                  <div>
                    <div className="panel-kicker">AKTİF HEDEF</div>
                    <h2>{report?.project || 'Hedef Seçilmedi'}</h2>
                  </div>
                  <span className={`project-status ${report ? 'status-complete' : ''}`}>
                    <span />{report ? 'Tamamlandı' : 'Bekliyor'}
                  </span>
                </div>
                {report ? (
                  <div className="project-stats">
                    <div><span>Tarama Modu</span><strong>{report.intake_mode || 'local_folder'}</strong></div>
                    <div><span>İncelenen Dosya</span><strong>{report.files_scanned}</strong></div>
                    <div><span>Analiz Süresi</span><strong>{report.scan_duration_ms ?? 0} ms</strong></div>
                    <div><span>Tespit Edilen Paket</span><strong>{dependencies.length}</strong></div>
                  </div>
                ) : (
                  <div className="project-placeholder">
                    <Icon name="folder" size={17} />
                    <span>İlk taramadan sonra proje özeti burada görünür.</span>
                  </div>
                )}
              </article>

              <article className="panel dependencies-panel" id="dependencies">
                <div className="panel-heading compact-heading">
                  <div>
                    <div className="panel-kicker">TEDARİK ZİNCİRİ (OSV.DEV)</div>
                    <h2>Kütüphaneler &amp; CVE</h2>
                  </div>
                  <span className="inventory-badge">{report?.online_lookup ? 'OSV AKTİF' : 'ENVANTER'}</span>
                </div>

                {dependencies.length ? (
                  <div className="dependency-list">
                    {orderedDependencies.slice(0, 12).map((dependency, index) => {
                      const hasVuln = (dependency.advisory_count ?? 0) > 0;
                      const isDepOpen = !!expandedDeps[index];
                      const aiDep = aiDependencyReviews[dependencies.indexOf(dependency)];

                      return (
                        <div className={`dep-card ${hasVuln ? 'dep-vulnerable' : ''}`} key={`${dependency.name}-${index}`}>
                          <button type="button" className="dep-summary-row" onClick={() => toggleDep(index)}>
                            <div className="package-glyph">{dependency.name.slice(0, 1).toUpperCase()}</div>
                            <div className="dep-name-wrap">
                              <strong>{dependency.name}</strong>
                              <span>{dependency.declared_version || 'sürüm sabitlenmemiş'} · {dependency.manifest}</span>
                            </div>
                            <div className="dep-badges">
                              {hasVuln ? (
                                <span className="dep-badge-Red">{dependency.advisory_count} CVE</span>
                              ) : dependency.advisory_status === 'checked_no_known_advisories' ? (
                                <span className="dep-badge-green">Temiz</span>
                              ) : (
                                <span className="dep-badge-muted">Envanter</span>
                              )}
                              <span className={`chevron-icon ${isDepOpen ? 'rotated' : ''}`}>
                                <Icon name="chevronDown" size={14} />
                              </span>
                            </div>
                          </button>

                          {isDepOpen && (
                            <div className="dep-details">
                              {dependency.latest_version && (
                                <div className="dep-meta-line">
                                  Güncel Sürüm: <code>{dependency.latest_version}</code> ({dependency.version_status === 'update_available' ? 'Güncelleme Mevcut' : 'Güncel'})
                                </div>
                              )}
                              {dependency.advisories?.length ? (
                                dependency.advisories.map((advisory) => (
                                  <div className="advisory-item" key={advisory.id}>
                                    <span className={`advisory-severity advisory-${advisory.severity}`}>{advisory.severity}</span>
                                    <strong>{advisory.id}</strong>
                                    {advisory.aliases?.find((a) => a.startsWith('CVE-')) && (
                                      <span>{advisory.aliases.find((a) => a.startsWith('CVE-'))}</span>
                                    )}
                                    <p>{advisory.summary}</p>
                                    {advisory.fixed_versions?.length > 0 && (
                                      <p className="fixed-ver">Çözülen sürüm: <strong>{advisory.fixed_versions.join(', ')}</strong></p>
                                    )}
                                  </div>
                                ))
                              ) : (
                                <div className="dep-clean-note">Bu paket sürümü için bilinen bir OSV kaydı bulunmadı.</div>
                              )}
                              {aiDep && (
                                <div className="ai-dependency-review">
                                  <strong>✨ DeepSeek Önerisi</strong>
                                  <p>{aiDep.explanation}</p>
                                  {aiDep.remediation && <div><span>ÖNERİLEN AKSİYON:</span> {aiDep.remediation}</div>}
                                </div>
                              )}
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                ) : (
                  <div className="dependency-empty">
                    {report ? 'Bağımlılık dosyası bulunamadı.' : 'Henüz paket taraması yapılmadı.'}
                  </div>
                )}
              </article>
            </div>
          </section>

          <footer className="page-footer">
            <span>AICODESHIELD v0.2 <span className="footer-separator">/</span> SE 401 BİTİRME PROJESİ</span>
            <span>Salt-okunur AST &amp; Pasif Analiz · İnsan Onaylı Kırmızı/Yeşil AI Yamaları</span>
          </footer>
        </div>
      </main>
    </div>
  );
}

export default App;
