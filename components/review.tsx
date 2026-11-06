"use client";
import { useEffect, useState } from "react";
import dynamic from "next/dynamic";
import { ArrowLeft, Check, CheckCheck, ChevronRight, Code2, Download, FileCode2, GitCompareArrows, Info, Loader2, LockKeyhole, Search, ShieldCheck, Sparkles, X } from "lucide-react";
import type { Explanation, Finding, Patch, Scan, Severity } from "@/lib/types";
import { severityOrder } from "@/lib/types";
import { api, download } from "@/lib/api";
import { SeverityBadge, EvidenceBadge } from "./ui";
const CodeViewer = dynamic(() => import("./code-viewer"), {ssr: false, loading: () => <div className="editor-loading"><Loader2 size={18} className="spin"/> Loading code viewer…</div>});

type Props = {scan: Scan; selected: Finding | undefined; select: (f: Finding) => void; theme: string; csrf?: string; llm: boolean; notify: (message: string, error?: boolean) => void; onReview: (f: Finding, status: string, note: string) => Promise<void>};
export default function Review({scan, selected, select, theme, csrf, llm, notify, onReview}: Props) {
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("all");
  const [engine, setEngine] = useState("all");
  const [status, setStatus] = useState("all");
  const [after, setAfter] = useState("");
  const [tab, setTab] = useState<"source" | "patch">("source");
  const [explanation, setExplanation] = useState<Explanation | null>(null);
  const [patch, setPatch] = useState<Patch | null>(null);
  const [patchError, setPatchError] = useState("");
  const [busy, setBusy] = useState("");
  const [reviewed, setReviewed] = useState(false);
  const [note, setNote] = useState("");
  const [dismiss, setDismiss] = useState(false);
  const fingerprint = selected?.fingerprint;
  useEffect(() => {
    let cancel = false;
    setTab("source"); setPatch(null); setPatchError(""); setReviewed(false); setDismiss(false); setNote("");
    if (!fingerprint) {setExplanation(null); return;}
    {
      setExplanation(null);
      api<Explanation>(`/scans/${scan.id}/findings/${fingerprint}/explanation`, {method: "POST", body: JSON.stringify({use_llm: false})}, csrf).then(data => {if (!cancel) setExplanation(data);}).catch(() => {});
    }
    return () => {cancel = true;};
  }, [fingerprint, scan.id, csrf]);
  const filtered = scan.findings.filter(f => (severity === "all" || f.severity === severity) && (engine === "all" || f.engine === engine) && (status === "all" || f.status === status) && (!after || (f.first_seen || scan.created_at) >= after) && `${f.title} ${f.path} ${f.rule_id} ${f.cwe}`.toLowerCase().includes(query.toLowerCase()));
  const source = selected ? scan.files[selected.path] || "" : "";
  async function getPatch() {
    if (!selected) return;
    setTab("patch"); setBusy("patch"); setPatchError("");
    try {
      const data = await api<Patch>(`/scans/${scan.id}/findings/${selected.fingerprint}/patch`, {method: "POST"}, csrf);
      if (!data) throw new Error(source.includes("[REDACTED]") ? "This file contains redacted credentials. Remediate secrets locally before proposing a patch." : "This finding needs a context-aware fix. Use the remediation guidance to author and test a change locally.");
      setPatch(data);
    } catch (error) {setPatchError((error as Error).message);} finally {setBusy("");}
  }
  async function generateAI() {
    if (!selected) return;
    setBusy("ai");
    try {setExplanation(await api<Explanation>(`/scans/${scan.id}/findings/${selected.fingerprint}/explanation`, {method: "POST", body: JSON.stringify({use_llm: true})}, csrf));}
    catch (error) {notify((error as Error).message, true);} finally {setBusy("");}
  }
  async function exportPatch() {
    if (!patch || !selected || !reviewed) return;
    {
      const response = await fetch(`/api/backend/scans/${scan.id}/findings/${selected.fingerprint}/patch/export`, {method: "POST", headers: {"Content-Type": "application/json", "X-CSRF-Token": csrf || ""}, body: JSON.stringify({digest: patch.digest, reviewed: true})});
      if (!response.ok) {notify("Patch export failed. Reload and review the current patch.", true); return;}
    }
    download("codeguardian.patch", patch.diff, "text/plain");
    notify("Reviewed patch exported. Apply and test it locally before opening a pull request.");
  }
  async function saveReview(status: string) {
    if (!selected) return;
    setBusy("review");
    try {await onReview(selected, status, note); setDismiss(false);} catch { /* Parent presents the actionable API error. */ } finally {setBusy("");}
  }
  return <div className="review-grid">
    <section className="finding-inbox" aria-label="Finding list">
      <div className="inbox-heading"><strong>Findings</strong><span className="count">{scan.findings.length}</span></div>
      <label className="search-field"><Search size={15}/><input value={query} onChange={e => setQuery(e.target.value)} placeholder="Search findings…" aria-label="Search findings"/></label>
      <label className="filter-label">Severity<select value={severity} onChange={e => setSeverity(e.target.value)}><option value="all">All severities</option>{severityOrder.map(s => <option key={s}>{s}</option>)}</select></label>
      <details className="advanced-filters"><summary>More filters</summary><label>Scanner<select aria-label="Filter scanner" value={engine} onChange={e=>setEngine(e.target.value)}><option value="all">All scanners</option>{Array.from(new Set(scan.findings.map(f=>f.engine))).map(x=><option key={x}>{x}</option>)}</select></label><label>Status<select aria-label="Filter status" value={status} onChange={e=>setStatus(e.target.value)}><option value="all">All statuses</option>{["open","confirmed","dismissed"].map(x=><option key={x}>{x}</option>)}</select></label><label>First seen from<input type="date" value={after} onChange={e=>setAfter(e.target.value)}/></label></details>
      <div className="inbox-list">{filtered.map(f => <button key={f.fingerprint} className={`inbox-finding ${selected?.fingerprint === f.fingerprint ? "selected" : ""}`} onClick={() => select(f)}><span className="inbox-meta"><SeverityBadge severity={f.severity}/><span className="mono">{f.cwe}</span></span><strong>{f.title}</strong><span className="file-label">{f.path.split("/").pop()}<span>:{f.line}</span></span><span className="inbox-engine">{f.engine}{f.status !== "open" && <span className="reviewed-mark"><Check size={12}/>{f.status}</span>}</span></button>)}{!filtered.length && <p className="empty-text">No findings match this filter.</p>}</div>
      <div className="inbox-footer"><LockKeyhole size={13}/> Source values are redacted</div>
    </section>
    {selected ? <><section className="code-panel" aria-label="Source review">
      <div className="code-panel-header"><FileCode2 size={16}/><span>{selected.path}</span><span className="language-label">{selected.path.endsWith("py") ? "Python" : selected.path.endsWith("ts") ? "TypeScript" : "JavaScript"}</span></div>
      <div className="code-tabs"><button className={tab === "source" ? "active" : ""} onClick={() => setTab("source")}><Code2 size={14}/>Source</button><button className={tab === "patch" ? "active" : ""} onClick={getPatch}><GitCompareArrows size={14}/>Proposed patch</button><span className="mono">{scan.commit_sha.slice(0, 7)}</span></div>
      {tab === "source" ? <>{source ? <CodeViewer source={source} path={selected.path} finding={selected} theme={theme}/> : <div className="empty compact"><LockKeyhole size={28}/><h3>Source is no longer retained</h3><p>Finding evidence remains available. Rescan this commit for a fresh source view.</p></div>}</> : patch ? <><div className="diff-labels"><span>Original</span><span>Suggested · not tested</span></div><CodeViewer source={source} path={selected.path} theme={theme} patch={patch}/><div className="patch-review"><p><Info size={15}/>{patch.caveat}</p><label><input type="checkbox" checked={reviewed} onChange={e => setReviewed(e.target.checked)}/>I reviewed this diff and will test it before use.</label><button className="button primary" disabled={!reviewed} onClick={exportPatch}><Download size={15}/>Export reviewed patch</button></div></> : <div className="patch-empty"><GitCompareArrows size={30}/><h3>{busy === "patch" ? "Preparing the diff…" : "This fix needs your context"}</h3><p>{patchError || "Checking the analyzer rule for a bounded suggestion."}</p><button className="button" onClick={() => setTab("source")}><ArrowLeft size={14}/>Back to source</button></div>}
      <div className="code-footer"><span><span className={`status-dot ${selected.severity}`}/>Finding at line {selected.line}</span><span>Read-only snapshot <LockKeyhole size={12}/></span></div>
    </section>
    <aside className="explanation-panel" aria-label="Finding details">
      <div className="detail-heading"><span className="section-icon"><ShieldCheck size={17}/>Evidence &amp; guidance</span><span className="neutral-tag">{selected.rule_id}</span></div>
      <div className="detail-content"><div className="detail-title"><SeverityBadge severity={selected.severity}/><h2>{selected.title}</h2><EvidenceBadge finding={selected}/></div>
      <p className="detail-message">{explanation?.explanation || selected.message}</p>
      <dl className="evidence-facts"><div><dt>Analyzer</dt><dd>{selected.engine}</dd></div><div><dt>Confidence</dt><dd className="capitalize">{selected.confidence}</dd></div><div><dt>Weakness</dt><dd>{/^CWE-\d+$/.test(selected.cwe) ? <a href={`https://cwe.mitre.org/data/definitions/${selected.cwe.replace("CWE-", "")}.html`} target="_blank" rel="noreferrer">{selected.cwe} ↗</a> : selected.cwe}</dd></div><div><dt>OWASP</dt><dd>{selected.owasp}</dd></div></dl>
      {selected.package && <div className="dependency-evidence"><strong>{selected.package}</strong><p>Fixed versions: {selected.fixed_version || "No published fix in this evidence"}</p>{selected.advisory_ids?.map(id=><span className="neutral-tag" key={id}>{id}</span>)}</div>}
      {selected.first_seen && <p className="small muted">First seen {new Date(selected.first_seen).toLocaleDateString()} · Last seen {new Date(selected.last_seen || selected.first_seen).toLocaleDateString()}</p>}
      {selected.references?.filter(u=>u.startsWith("https://")).slice(0,4).map((u,i)=><a className="advisory-link" key={u} href={u} target="_blank" rel="noreferrer">Advisory reference {i+1} ↗</a>)}
      <div className="guidance-heading"><Sparkles size={16}/><h3>{explanation?.provider === "llm" ? "AI explanation" : "Grounded guidance"}</h3></div>
      <p className="muted small">{explanation?.provider === "llm" ? `Generated with ${explanation.model}. Review for accuracy.` : "Curated from CWE references. No AI claim of exploitability."}</p>
      {explanation && <><p>{explanation.remediation}</p>{explanation.impact&&<details><summary>Potential impact <ChevronRight size={14}/></summary><p>{explanation.impact}</p></details>}{explanation.false_positive_considerations?.length ? <details><summary>False-positive considerations <ChevronRight size={14}/></summary><ul>{explanation.false_positive_considerations.map((x,i)=><li key={i}>{x}</li>)}</ul></details>:null}<details><summary>What to verify <ChevronRight size={14}/></summary><ul>{explanation.conditions_to_verify.map((x, i) => <li key={i}>{x}</li>)}</ul></details><details><summary>Suggested regression tests <ChevronRight size={14}/></summary><ul>{explanation.tests.map((x, i) => <li key={i}>{x}</li>)}</ul></details><div className="citations">{explanation.citations.map(c => <a key={c.id} href={c.url} target="_blank" rel="noreferrer">{c.id}<span>↗</span></a>)}</div></>}
      {llm && <button className="button full" disabled={busy === "ai"} onClick={generateAI}>{busy === "ai" ? <Loader2 size={15} className="spin"/> : <Sparkles size={15}/>}Explain with configured AI</button>}
      <div className="review-actions"><button className="button primary full" onClick={getPatch}><GitCompareArrows size={15}/>Review suggested patch</button><div className="button-pair"><button className="button" disabled={busy === "review"} onClick={() => saveReview(selected.status === "confirmed" ? "open" : "confirmed")}><CheckCheck size={14}/>{selected.status === "confirmed" ? "Reopen" : "Confirm"}</button><button className="button" onClick={() => setDismiss(!dismiss)}><X size={14}/>Dismiss</button></div>{dismiss && <div className="dismiss-form"><label>Reason for dismissal<textarea value={note} onChange={e => setNote(e.target.value)} placeholder="Explain why this finding does not apply…" maxLength={2000}/></label><button className="button full" disabled={!note.trim() || busy === "review"} onClick={() => saveReview("dismissed")}>Save review</button></div>}<p className="review-footnote">Reviews are saved with an audit event. Repository changes always stay in your hands.</p></div></div>
    </aside></> : <div className="empty"><ShieldCheck size={34}/><h2>No findings to review</h2><p>Check scan coverage before treating this repository as safe.</p></div>}
  </div>;
}
