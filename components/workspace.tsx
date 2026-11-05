"use client";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Activity, ArrowDown, ArrowDownToLine, ArrowRight, ArrowUpRight, BookOpen, Check, ChevronDown, ChevronRight, CircleHelp, Code2, Download, ExternalLink, FileCode2, FileText, FolderGit2, GitBranch, GitCommitHorizontal, Github, LayoutDashboard, Loader2, LockKeyhole, Moon, Plus, RefreshCw, Search, Settings2, ShieldCheck, ShieldAlert, Sparkles, Sun, Upload, X } from "lucide-react";
import { api, download } from "@/lib/api";
import { severityOrder, type Comparison, type Demo, type Finding, type Repository, type Scan } from "@/lib/types";
import { FindingTable, Mark, SeverityBadge } from "./ui";
import TrendChart from "./trend-chart";
import Review from "./review";

type View = "overview" | "review" | "repositories" | "reports" | "settings";
type Capabilities = {github: boolean; llm: boolean; checks: boolean; demo_login: boolean; repository_writes: boolean; scanner_mode: string};
type Identity = {login: string; csrf_token: string};
type GitRepo = {id: number; full_name: string; private: boolean; branch: string; installation_id: number};
const NAV = [{id: "overview", label: "Overview", icon: LayoutDashboard}, {id: "review", label: "Code review", icon: Code2}, {id: "repositories", label: "Repositories", icon: FolderGit2}, {id: "reports", label: "Reports", icon: Activity}] as const;
const date = (value: string) => new Date(value).toLocaleDateString("en-GB", {day: "numeric", month: "short", year: "numeric", timeZone: "UTC"});
const count = (scan: {summary: Record<string, number>}) => Object.values(scan.summary).reduce((a, b) => a + b, 0);

export default function Workspace({initial, backendConfigured}: {initial: Demo; backendConfigured: boolean}) {
  const [view, setView] = useState<View>("overview");
  const [theme, setTheme] = useState("dark");
  const [scan, setScan] = useState<Scan>(initial.scan);
  const [repository, setRepository] = useState<Repository>(initial.repository);
  const [repos, setRepos] = useState<Repository[]>([]);
  const [selectedId, setSelectedId] = useState(initial.scan.findings.find(f => f.rule_id === "javascript-sql-injection")?.fingerprint || initial.scan.findings[0]?.fingerprint);
  const [comparison, setComparison] = useState<Comparison | undefined>(initial.comparison);
  const [user, setUser] = useState<Identity | null>(null);
  const [caps, setCaps] = useState<Capabilities | null>(null);
  const [toast, setToast] = useState<{message: string; error: boolean} | null>(null);
  const [busy, setBusy] = useState("");
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("all");
  const [importTab, setImportTab] = useState<"github" | "upload">("github");
  const [gitRepos, setGitRepos] = useState<GitRepo[]>([]);
  const [authorized, setAuthorized] = useState(false);
  const [file, setFile] = useState<File | null>(null);
  const dialog = useRef<HTMLDialogElement>(null);
  const searchRef = useRef<HTMLInputElement>(null);
  const isDemo = scan.id.startsWith("fixture-");
  const selected = scan.findings.find(f => f.fingerprint === selectedId) || scan.findings[0];
  const openFindings = scan.findings.filter(f => f.status !== "dismissed");
  const high = openFindings.filter(f => f.severity === "high" || f.severity === "critical").length;
  const history = isDemo ? initial.history : (repos.find(r => r.id === repository.id)?.scans || [scan]).filter(s => s.status === "completed").slice(0, 8).reverse();
  const chartValues = useMemo(() => history.map(count), [history]);
  const chartLabels = useMemo(() => history.map((s, i) => isDemo ? i === 0 ? "Baseline" : "Current" : s.commit_sha.slice(0, 7)), [history, isDemo]);
  const filtered = scan.findings.filter(f => (severity === "all" || f.severity === severity) && `${f.title} ${f.path} ${f.cwe} ${f.engine}`.toLowerCase().includes(search.toLowerCase()));
  const notify = useCallback((message: string, error = false) => setToast({message, error}), []);

  useEffect(() => {setTheme(document.documentElement.dataset.theme || "dark"); const hash = location.hash.slice(1); if (["overview", "review", "repositories", "reports", "settings"].includes(hash)) setView(hash as View);}, []);
  useEffect(() => {if (!toast) return; const timer = setTimeout(() => setToast(null), 6500); return () => clearTimeout(timer);}, [toast]);
  useEffect(() => {const key = (event: KeyboardEvent) => {if (event.key === "/" && !(event.target instanceof HTMLInputElement || event.target instanceof HTMLTextAreaElement)) {event.preventDefault(); setView("overview"); searchRef.current?.focus();}}; window.addEventListener("keydown", key); return () => window.removeEventListener("keydown", key);}, []);
  useEffect(() => {
    if (!backendConfigured) return;
    let cancel = false;
    Promise.allSettled([api<Capabilities>("/capabilities"), api<Identity>("/auth/me")]).then(async results => {
      if (cancel) return;
      if (results[0].status === "fulfilled") setCaps(results[0].value);
      if (results[1].status === "fulfilled") {
        setUser(results[1].value);
        try {const items = await api<Repository[]>("/repositories"); if (!cancel) setRepos(items);} catch {}
      }
    });
    return () => {cancel = true;};
  }, [backendConfigured]);
  function navigate(next: View) {setView(next); historyReplace(next);}
  function historyReplace(next: View) {window.history.replaceState(null, "", `#${next}`);}
  function changeTheme(next: string) {setTheme(next); document.documentElement.dataset.theme = next; try {localStorage.setItem("cg-theme", next);} catch {}}
  function selectFinding(f: Finding) {setSelectedId(f.fingerprint); navigate("review");}
  async function loadScan(id: string) {
    const result = await api<Scan & {repository: Repository}>(`/scans/${id}`);
    if (result.status === "failed") throw new Error(result.error || "This scan failed. Retry after checking worker health.");
    if (["queued", "running"].includes(result.status)) {notify("This scan is still processing. Check back shortly."); return;}
    setScan(result); setRepository(result.repository); setSelectedId(result.findings[0]?.fingerprint); setComparison(result.comparison);
  }
  function showFixture() {setScan(initial.scan); setRepository(initial.repository); setComparison(initial.comparison); setSelectedId(initial.scan.findings[0]?.fingerprint);}
  async function refreshRepos() {const items = await api<Repository[]>("/repositories"); setRepos(items); return items;}
  async function pollScan(id: string) {
    for (let i = 0; i < 125; i++) {
      const current = await api<Scan & {repository: Repository}>(`/scans/${id}`);
      if (!["queued", "running"].includes(current.status)) {
        if (current.status === "failed") throw new Error(current.error || "Scan failed; check worker health and try again.");
        setScan(current); setRepository(current.repository); setComparison(current.comparison); setSelectedId(current.findings[0]?.fingerprint);
        await refreshRepos();
        notify(current.status === "partial" ? "Scan finished with incomplete coverage. Review the scanner errors." : "Scan complete. The latest analyzer evidence is ready.", current.status === "partial");
        return;
      }
      await new Promise(resolve => setTimeout(resolve, 2000));
    }
    throw new Error("The scan is still processing. Check back in Repositories.");
  }
  async function startScan() {
    if (!backendConfigured) {dialog.current?.showModal(); return;}
    setBusy("scan");
    try {
      const available = caps || await api<Capabilities>("/capabilities");
      if (!caps) setCaps(available);
      if (!user && !available.demo_login) {dialog.current?.showModal(); return;}
      let identity = user;
      if (!identity && available.demo_login) {await api("/auth/demo", {method: "POST"}); identity = await api<Identity>("/auth/me"); setUser(identity);}
      const result = isDemo ? await api<{scan_id: string}>("/repositories/fixture", {method: "POST"}, identity?.csrf_token) : await api<{scan_id: string}>(`/repositories/${repository.id}/scans`, {method: "POST"}, identity?.csrf_token);
      await pollScan(result.scan_id);
    } catch (error) {notify((error as Error).message, true);} finally {setBusy("");}
  }
  async function openImport() {
    dialog.current?.showModal();
    if (user && caps?.github) {
      setBusy("repositories");
      try {setGitRepos((await api<{repositories: GitRepo[]}>("/github/repositories")).repositories);} catch (error) {notify((error as Error).message, true);} finally {setBusy("");}
    }
  }
  async function importRepo(repo: GitRepo) {
    if (!user) return;
    setBusy("import");
    try {const result = await api<{scan_id: string}>("/repositories/github", {method: "POST", body: JSON.stringify({full_name: repo.full_name, installation_id: repo.installation_id})}, user.csrf_token); dialog.current?.close(); navigate("overview"); await pollScan(result.scan_id);} catch (error) {notify((error as Error).message, true);} finally {setBusy("");}
  }
  async function importArchive() {
    if (!user || !file || !authorized) return;
    setBusy("import");
    try {const form = new FormData(); form.append("file", file); form.append("authorized", "true"); const result = await api<{scan_id: string}>("/repositories/upload", {method: "POST", body: form}, user.csrf_token); dialog.current?.close(); await pollScan(result.scan_id);} catch (error) {notify((error as Error).message, true);} finally {setBusy("");}
  }
  async function onReview(finding: Finding, status: string, note: string) {
    try {
      if (!isDemo) await api(`/scans/${scan.id}/findings/${finding.fingerprint}/review`, {method: "PATCH", body: JSON.stringify({status, note})}, user?.csrf_token);
      setScan(current => ({...current, findings: current.findings.map(f => f.fingerprint === finding.fingerprint ? {...f, status, review_note: note} : f)}));
      notify(`Finding ${status === "open" ? "reopened" : status}.${isDemo ? " Demo session only." : " Review saved."}`);
    } catch (error) {notify((error as Error).message, true);}
  }
  async function exportReport(format: "json" | "sarif" | "md") {
    if (!isDemo && format !== "md") {try {download(`codeguardian.${format}`, JSON.stringify(await api(`/scans/${scan.id}/report?format=${format}`), null, 2));} catch (error) {notify((error as Error).message, true);} return;}
    const safe = (s: string) => s.replace(/[\r\n|]/g, " ");
    if (format === "md") {
      const content = `# CodeGuardian security review\n\nRepository: ${repository.full_name}\nSnapshot: ${scan.commit_sha}\nScan: ${scan.created_at}\nFixture: ${isDemo}\nCoverage complete: ${scan.coverage.complete}\n\nAnalyzer evidence requires human review; it is not proof of exploitability.\n\n| Finding | Severity | Location | Evidence | Review |\n|---|---|---|---|---|\n` + scan.findings.map(f => `| ${safe(f.title)} | ${f.severity} | ${safe(f.path)}:${f.line} | ${f.engine} ${f.rule_id} / ${f.cwe} | ${f.status} |`).join("\n");
      download("codeguardian-report.md", content, "text/markdown");
    } else if (format === "sarif") {
      download("codeguardian.sarif", JSON.stringify({version: "2.1.0", $schema: "https://json.schemastore.org/sarif-2.1.0.json", runs: [{tool: {driver: {name: "CodeGuardian AI", version: "0.1.0"}}, results: scan.findings.map(f => ({ruleId: f.rule_id, level: ["high", "critical"].includes(f.severity) ? "error" : "warning", message: {text: f.message}, locations: [{physicalLocation: {artifactLocation: {uri: f.path}, region: {startLine: f.line}}}]}))}]}, null, 2));
    } else {const {files: _files, ...report} = scan; download("codeguardian-report.json", JSON.stringify({fixture: isDemo, repository, ...report}, null, 2));}
    notify("Security report exported with redacted evidence.");
  }
  const repoName = repository.full_name.split("/").pop();
  return <div className="app-shell">
    <a className="skip-link" href="#main">Skip to content</a>
    <aside className="nav-rail"><button className="brand-mark" aria-label="CodeGuardian home" onClick={() => navigate("overview")}><Mark/></button><nav aria-label="Main navigation">{NAV.map(({id, label, icon: Icon}) => <button key={id} title={label} aria-label={label} aria-current={view === id ? "page" : undefined} className={`nav-item ${view === id ? "active" : ""}`} onClick={() => navigate(id)}><Icon size={20} strokeWidth={1.6}/><span>{label}</span></button>)}</nav><div className="nav-bottom"><a className="nav-item" href="https://github.com/aashleshshet/CodeGuardian#readme" target="_blank" rel="noreferrer" title="Documentation" aria-label="Documentation"><BookOpen size={19}/></a><button title="Settings" aria-label="Settings" className={`nav-item ${view === "settings" ? "active" : ""}`} onClick={() => navigate("settings")}><Settings2 size={19}/><span>Settings</span></button><button className="user-avatar" title={user?.login || "Demo workspace"} onClick={() => navigate("settings")}>{user?.login.slice(0, 2).toUpperCase() || "CG"}</button></div></aside>
    <div className="app-body"><header className="topbar"><div className="wordmark">CodeGuardian<span>AI</span></div><span className="topbar-divider"/><div className="workspace-name"><span className="workspace-dot"/>{user?.login || "Demo workspace"}<ChevronDown size={13}/></div><div className="topbar-right"><span className="protected-label"><LockKeyhole size={13}/>Human-reviewed security</span><button className="icon-button" aria-label={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"} onClick={() => changeTheme(theme === "dark" ? "light" : "dark")}>{theme === "dark" ? <Sun size={18}/> : <Moon size={18}/>}</button><a className="icon-button" href="https://github.com/aashleshshet/CodeGuardian" target="_blank" rel="noreferrer" aria-label="View GitHub repository"><Github size={18}/></a></div></header>
    <main id="main" className={view === "review" ? "main review-main" : "main"}>
      <div className="breadcrumbs"><span>Workspace</span><ChevronRight size={13}/><span>{view === "overview" ? "Overview" : view === "review" ? "Code review" : view.charAt(0).toUpperCase() + view.slice(1)}</span>{view === "review" && <><ChevronRight size={13}/><span>{repoName}</span></>}</div>
      <div className="page-heading"><div><h1>{view === "overview" ? "Security overview" : view === "review" ? "Review the evidence" : view === "repositories" ? "Your repositories" : view === "reports" ? "Security reports" : "Workspace settings"}</h1><p>{view === "overview" ? `${high} high-priority findings need your attention in ${repoName}.` : view === "review" ? "From analyzer evidence to a change you can trust." : view === "repositories" ? "Bring authorized source into a controlled review environment." : view === "reports" ? "Track changes and share evidence your team can act on." : "Connections, review policy, and your preferred working environment."}</p></div><div className="heading-actions">{view === "overview" || view === "review" ? <><button className="button secondary" onClick={() => exportReport("json")}><Download size={15}/><span>Export report</span></button><button className="button primary" onClick={startScan} disabled={busy === "scan" || busy === "import"}>{busy === "scan" || busy === "import" ? <Loader2 size={15} className="spin"/> : <RefreshCw size={15}/>}<span>{busy === "scan" || busy === "import" ? "Scanning…" : "Run scan"}</span></button></> : view === "repositories" ? <button className="button primary" onClick={openImport}><Plus size={16}/>Import repository</button> : null}</div></div>
      {isDemo && <div className="demo-banner"><span><span className="demo-dot"/>Live evidence. Sample repository.<span className="demo-description"> Real Semgrep & Bandit results from the included test fixture.</span></span><button onClick={openImport}>Connect your repository<ArrowRight size={14}/></button></div>}
      {!scan.coverage.complete && <div className="warning-banner"><ShieldAlert size={17}/><span>Coverage is incomplete. A clean result cannot be inferred from this scan. {scan.coverage.errors?.join(" ")}</span></div>}

      {view === "overview" && <>
        <section className="repository-strip"><div className="repo-identity"><FolderGit2 size={22}/><div><div className="repo-name">{repoName}<span className="neutral-tag">{isDemo ? "Fixture" : "Authorized"}</span></div><span>{repository.full_name}</span></div></div><div className="repo-context"><span><GitBranch size={14}/>{repository.branch}</span><span className="mono"><GitCommitHorizontal size={15}/>{scan.commit_sha.slice(0, 7)}</span></div><div className="repo-status"><span className="success-dot"/>Scan {scan.status}<small>{date(scan.completed_at || scan.created_at)} · UTC</small></div><button className="icon-button" aria-label="Browse repositories" onClick={() => navigate("repositories")}><ChevronRight size={18}/></button></section>
        <section className="metrics-strip" aria-label="Security summary"><div className="metric"><span>Open findings<InfoTip text="Findings that have not been dismissed. Counts do not certify exploitability."/></span><strong>{openFindings.length}<span className="metric-unit">to review</span></strong><div className="severity-track">{severityOrder.filter(s => scan.summary[s] > 0).map(s => <span key={s} className={s} style={{width: `${scan.summary[s] / scan.findings.length * 100}%`}} title={`${scan.summary[s]} ${s}`}/>)}</div></div><div className="metric"><span>High priority<span className="status-dot high"/></span><strong>{high}<span className="metric-unit">findings</span></strong><small>{scan.summary.critical} critical · {scan.summary.high} high</small></div><div className="metric"><span>Source coverage<FileCode2 size={14}/></span><strong>{scan.coverage.files}<span className="metric-unit">files</span></strong><small>{scan.coverage.languages.filter(l => l !== "Configuration").join(" · ")}</small></div><div className="metric"><span>Resolved since baseline<GitCommitHorizontal size={15}/></span><strong>{comparison?.reliable ? comparison.resolved.length : "—"}<span className="metric-unit">findings</span></strong><small className={comparison?.resolved.length ? "positive" : ""}>{comparison?.reliable ? <><ArrowDown size={12}/>{comparison.new.length} new · {comparison.unchanged.length} unchanged</> : "Run another complete scan to compare"}</small></div></section>
        <div className="overview-grid"><section className="panel priority-panel"><div className="panel-heading"><div><h2>Findings to prioritize<span className="count">{scan.findings.length}</span></h2><p>Start with the evidence that matters most.</p></div><button className="text-button" onClick={() => navigate("review")}>Review all<ArrowUpRight size={14}/></button></div><div className="table-toolbar"><label className="search-field"><Search size={15}/><input ref={searchRef} value={search} onChange={e => setSearch(e.target.value)} placeholder="Search findings, files, or CWE…" aria-label="Search all findings"/><kbd>/</kbd></label><label className="sr-only" htmlFor="overview-severity">Filter severity</label><select id="overview-severity" value={severity} onChange={e => setSeverity(e.target.value)}><option value="all">All severities</option>{severityOrder.map(s => <option key={s} value={s}>{s}</option>)}</select></div><FindingTable findings={filtered.slice(0, 5)} onSelect={selectFinding} compact/><div className="table-pagination"><span>Showing {Math.min(filtered.length, 5)} of {filtered.length} findings</span><button className="text-button" onClick={() => navigate("review")}>Open code review<ArrowRight size={14}/></button></div></section>
        <div className="overview-aside"><section className="panel trend-panel"><div className="panel-heading"><div><h2>Finding trend</h2><p>{isDemo ? "Two reproducible source snapshots" : "Recent complete scans"}</p></div><Activity size={17}/></div><div className="trend-stat"><strong>{count(scan)}</strong><span>analyzer findings</span>{comparison?.reliable && <span className="trend-change"><ArrowDown size={13}/>{comparison.resolved.length} resolved</span>}</div>{history.length > 1 ? <TrendChart values={chartValues} labels={chartLabels} theme={theme}/> : <div className="chart-empty">A trend appears after two complete scans.</div>}<div className="trend-caption"><span className="chart-dot"/>Findings per snapshot<span>{isDemo ? "Fixture history" : "Commit history"}</span></div></section>
        <section className="panel engine-panel"><div className="panel-heading"><div><h2>Analysis coverage</h2><p>Evidence you can trace to its source.</p></div><ShieldCheck size={18}/></div>{scan.coverage.engines.map(engine => <div className="engine-row" key={engine.name}><div className="engine-symbol">{engine.name === "Semgrep" ? <Code2 size={17}/> : engine.name === "Bandit" ? <FileCode2 size={17}/> : <LockKeyhole size={17}/>}</div><div><strong>{engine.name}</strong><small>{engine.name === "Semgrep" ? "Python, JavaScript & TypeScript" : engine.name === "Bandit" ? "Python security analysis" : "Credential pattern detection"}</small></div><span className={engine.status === "completed" ? "engine-ok" : "warning"}>{engine.status === "completed" ? <Check size={15}/> : <ShieldAlert size={15}/>}<span>{engine.status === "completed" ? "Complete" : engine.status}</span></span></div>)}<div className="engine-note"><LockKeyhole size={13}/>Source code is never executed.</div></section></div></div>
        <section className="review-callout"><div className="callout-mark"><Mark small/></div><div><strong>Evidence first. Your judgment, always.</strong><p>AI helps explain the finding. You decide whether the code should change.</p></div><button className="text-button" onClick={() => navigate("settings")}>Review policy<ArrowRight size={14}/></button></section>
      </>}

      {view === "review" && <Review scan={scan} initial={initial} selected={selected} select={f => setSelectedId(f.fingerprint)} theme={theme} isDemo={isDemo} csrf={user?.csrf_token} llm={Boolean(caps?.llm)} notify={notify} onReview={onReview}/>}

      {view === "repositories" && <div className="repository-page"><section className="panel"><div className="panel-heading"><div><h2>Review workspace</h2><p>{repos.length} connected repositories · 1 reproducible fixture</p></div><span className="neutral-tag">Read-only access</span></div>{[initial.repository, ...repos].map(repo => <div className="repository-row" key={repo.id}><FolderGit2 size={23}/><div><strong>{repo.full_name}</strong><p><GitBranch size={13}/>{repo.branch}<span>·</span>{repo.is_fixture ? "Reproducible test fixture" : "Authorized source"}</p></div><span className="neutral-tag">{repo.scans?.[0]?.status || "Ready"}</span><button className="button" onClick={async () => {if (repo.id === initial.repository.id) {showFixture(); navigate("overview");} else if (repo.scans?.[0]) {try {await loadScan(repo.scans[0].id); navigate("overview");} catch (error) {notify((error as Error).message, true);}}}}>Open review<ArrowUpRight size={14}/></button></div>)}</section><section className="connection-explainer"><div><Github size={24}/><h2>Your code. Your permission.</h2><p>Install the GitHub App on selected repositories. CodeGuardian checks your access before every import and snapshots the exact commit for review.</p><button className="button" onClick={openImport}>Connect GitHub<ArrowRight size={14}/></button></div><ol><li><span>01</span><div><strong>Authorize selected repositories</strong><p>Contents and metadata read access. Optional checks write permission.</p></div></li><li><span>02</span><div><strong>Scan an isolated snapshot</strong><p>No dependency installation, repository scripts, or code execution.</p></div></li><li><span>03</span><div><strong>Review the evidence</strong><p>Source, context, and a proposed diff stay together.</p></div></li></ol></section></div>}

      {view === "reports" && <div className="reports-page"><section className="panel report-summary"><div className="panel-heading"><div><h2>{repoName} security review</h2><p>{date(scan.created_at)} · {scan.commit_sha.slice(0, 7)}{isDemo ? " · Fixture snapshot" : ""}</p></div><FileText size={22}/></div><div className="report-numbers"><div><strong>{scan.findings.length}</strong><span>Reported findings</span></div><div><strong>{high}</strong><span>High priority</span></div><div><strong>{comparison?.reliable ? comparison.resolved.length : "—"}</strong><span>Resolved vs baseline</span></div></div><p className="report-notice">{scan.coverage.complete ? "All configured analyzers completed." : "Scanner coverage is incomplete."} This report records static evidence and reviewer decisions. It does not certify that the repository is vulnerability-free.</p><div className="report-actions"><button className="button primary" onClick={() => exportReport("md")}><Download size={15}/>Markdown report</button><button className="button" onClick={() => exportReport("json")}>JSON</button><button className="button" onClick={() => exportReport("sarif")}>SARIF</button></div></section><section className="panel history-panel"><div className="panel-heading"><div><h2>Snapshot comparison</h2><p>Only complete scans establish a reliable baseline.</p></div><GitBranch size={19}/></div><div className="comparison-summary"><span className="positive">{comparison?.resolved.length ?? "—"} resolved</span><span>{comparison?.new.length ?? "—"} new</span><span>{comparison?.unchanged.length ?? "—"} unchanged</span></div>{history.map((s, i) => <div className="history-row" key={s.id}><GitCommitHorizontal size={19}/><div><strong className="mono">{s.commit_sha.slice(0, 7)}</strong><small>{isDemo ? i === 0 ? "Baseline fixture" : "Current fixture" : date(s.created_at)}</small></div><span>{count(s)} findings</span><span className="neutral-tag">{s.status}</span></div>)}{isDemo && <p className="small muted report-footnote">Fixture identifiers are source content hashes, not Git commits. Reproduce both scans using the script in the repository.</p>}</section><section className="panel report-findings"><div className="panel-heading"><h2>Evidence included in this report</h2><span className="neutral-tag">Values redacted</span></div><FindingTable findings={scan.findings} onSelect={selectFinding}/></section></div>}

      {view === "settings" && <div className="settings-page"><SettingsRow title="Appearance" description="A comfortable workspace for long review sessions."><div className="theme-options"><button className={`theme-option ${theme === "dark" ? "selected" : ""}`} onClick={() => changeTheme("dark")}><Moon size={19}/><span>Dark</span>{theme === "dark" && <Check size={15}/>}</button><button className={`theme-option ${theme === "light" ? "selected" : ""}`} onClick={() => changeTheme("light")}><Sun size={19}/><span>Light</span>{theme === "light" && <Check size={15}/>}</button></div></SettingsRow><SettingsRow title="GitHub connection" description="Import only repositories you have authorized through the GitHub App."><div className="settings-status"><Github size={21}/><div><strong>{user ? `Connected as ${user.login}` : "No GitHub account connected"}</strong><p>{caps?.github ? "GitHub App authorization is available." : "Configure the GitHub App on your backend to enable private imports."}</p></div></div><button className="button" onClick={openImport}>{user ? "Manage repository imports" : "Connect GitHub"}<ArrowUpRight size={14}/></button></SettingsRow><SettingsRow title="AI explanations" description="Ground explanations in analyzer output and trusted CWE guidance."><div className="settings-status"><Sparkles size={21}/><div><strong>{caps?.llm ? "Configured provider available" : "Curated guidance active"}</strong><p>{caps?.llm ? "Generate AI explanations on demand in the finding panel." : "CWE-backed explanations work without an API key. Enable your LLM provider on the server."}</p></div><span className="neutral-tag">{caps?.llm ? "Connected" : "Local knowledge"}</span></div><p className="small muted">Only redacted evidence excerpts are sent on an explicit AI request. Repository text is treated as untrusted data.</p></SettingsRow><SettingsRow title="Review policy" description="The boundaries that stay in place throughout a review."><ul className="policy-list"><li><ShieldCheck size={17}/><span>Analyzer evidence and AI suggestions remain distinct.</span></li><li><LockKeyhole size={17}/><span>No automatic commits, pull requests, or merges.</span></li><li><FileCode2 size={17}/><span>Diffs require a human review before export.</span></li><li><Code2 size={17}/><span>Untrusted source is scanned in isolated workers.</span></li></ul></SettingsRow><SettingsRow title="Service connection" description="The frontend connects to your privately operated review service."><div className="settings-status"><Activity size={21}/><div><strong>{backendConfigured ? caps ? "Review service connected" : "Review service unavailable" : "Fixture exploration mode"}</strong><p>{backendConfigured ? caps ? `Scanner mode: ${caps.scanner_mode}. Queued scans require healthy workers.` : "Check the configured API host and its health endpoint." : "Deploy the included backend containers, then configure API_URL in Vercel."}</p></div></div><a href="https://github.com/aashleshshet/CodeGuardian/blob/main/docs/deployment.md" className="text-button" target="_blank" rel="noreferrer">Deployment guide<ExternalLink size={14}/></a></SettingsRow></div>}
      <footer className="app-footer"><span><Mark small/>CodeGuardian AI<span className="footer-dot">·</span>Evidence before inference.</span><span>{isDemo ? "Reproducible fixture" : "Authorized review"}<span className="footer-dot">·</span>Rule set {scan.coverage.rule_version}</span></footer>
    </main></div>
    <dialog ref={dialog} className="import-dialog"><div className="dialog-heading"><div><h2>Bring your code into view</h2><p>Start with a repository you are authorized to review.</p></div><button className="icon-button" aria-label="Close import dialog" onClick={() => dialog.current?.close()}><X size={20}/></button></div><div className="dialog-tabs"><button className={importTab === "github" ? "active" : ""} onClick={() => setImportTab("github")}><Github size={16}/>GitHub App</button><button className={importTab === "upload" ? "active" : ""} onClick={() => setImportTab("upload")}><Upload size={16}/>Source archive</button></div>{!backendConfigured ? <div className="connection-needed"><div className="connection-symbol"><FolderGit2 size={30}/></div><h3>Connect the review service</h3><p>This deployment lets you explore real scanner results from the included fixture. Connect the backend to import your repositories and run new scans.</p><a className="button primary" href="https://github.com/aashleshshet/CodeGuardian/blob/main/docs/deployment.md" target="_blank" rel="noreferrer">Open deployment guide<ArrowUpRight size={15}/></a><button className="text-button" onClick={() => {dialog.current?.close(); navigate("review");}}>Explore fixture findings<ArrowRight size={14}/></button></div> : !user ? <div className="connection-needed"><Github size={32}/><h3>Authorize repository access</h3><p>{caps?.github ? "Sign in through your GitHub App. Choose exactly which repositories CodeGuardian can read." : "GitHub App credentials have not been configured on this service."}</p>{caps?.github && <a href="/api/backend/auth/github/start" className="button primary"><Github size={16}/>Continue with GitHub</a>}{caps?.demo_login && <button className="button" onClick={async () => {try {await api("/auth/demo", {method: "POST"}); setUser(await api<Identity>("/auth/me")); notify("Local development session started.");} catch (error) {notify((error as Error).message, true);}}}>Start local development session</button>}</div> : importTab === "github" ? <div className="import-content">{busy === "repositories" ? <p className="muted">Loading authorized repositories…</p> : gitRepos.length ? gitRepos.map(r => <div className="import-repo" key={r.id}><FolderGit2 size={19}/><div><strong>{r.full_name}</strong><small>{r.private ? "Private" : "Public"} · {r.branch}</small></div><button className="button" disabled={Boolean(busy)} onClick={() => importRepo(r)}>Import<Plus size={14}/></button></div>) : <div className="empty compact"><FolderGit2 size={27}/><h3>No authorized repositories</h3><p>Install your configured GitHub App on selected repositories, then reopen this dialog.</p></div>}</div> : <div className="import-content"><label className="upload-field"><Upload size={24}/><strong>{file?.name || "Select a source ZIP archive"}</strong><span>Up to 4 MB in the web interface</span><input type="file" accept=".zip,application/zip" onChange={e => setFile(e.target.files?.[0] || null)} aria-label="Select source ZIP archive"/></label><label className="authorization-check"><input type="checkbox" checked={authorized} onChange={e => setAuthorized(e.target.checked)}/>I am authorized to review this repository.</label><button className="button primary full" disabled={!file || !authorized || Boolean(busy)} onClick={importArchive}>Import and scan<ArrowRight size={15}/></button></div>}<div className="dialog-footer"><LockKeyhole size={13}/>Read access only. No repository code is executed.</div></dialog>
    {toast && <div className={`toast ${toast.error ? "toast-error" : ""}`} role={toast.error ? "alert" : "status"}>{toast.error ? <ShieldAlert size={19}/> : <Check size={19}/>}<span>{toast.message}</span><button className="icon-button" aria-label="Dismiss notification" onClick={() => setToast(null)}><X size={15}/></button></div>}
  </div>;
}

function InfoTip({text}: {text: string}) {return <span className="info-tip" title={text} aria-label={text}><CircleHelp size={13}/></span>;}
function SettingsRow({title, description, children}: {title: string; description: string; children: React.ReactNode}) {return <section className="settings-row"><div><h2>{title}</h2><p>{description}</p></div><div className="settings-content">{children}</div></section>;}
