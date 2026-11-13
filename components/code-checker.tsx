"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import dynamic from "next/dynamic";
import { ArrowDown, ArrowRight, ArrowUpRight, Check, CheckCheck, ChevronDown, Code2, Download, FileCode2, Fingerprint, Info, Loader2, LockKeyhole, Moon, ScanLine, ShieldCheck, Sun, Upload, X } from "lucide-react";
import type { BrowserAnalysis, BrowserFinding, BrowserLanguage } from "@/lib/browser-analysis";
import type { Finding } from "@/lib/types";
import styles from "./checker.module.css";

const CodeViewer = dynamic(() => import("./code-viewer"), {ssr:false, loading:()=> <div className={styles.editorLoading}>Opening the source viewer…</div>});
const EXAMPLE = `// Example only — intentionally unsafe patterns for review.\n// This code is inspected, never executed.\n\nexport function showMessage(message: string) {\n  const preview = document.getElementById("preview");\n  if (preview) {\n    preview.innerHTML = message;\n  }\n}\n\nexport function calculate(expression: string) {\n  return eval(expression);\n}\n`;
const maxBytes = 200 * 1024;

function saveFile(name:string, value:string, type:string) {
  const url=URL.createObjectURL(new Blob([value],{type}));
  const link=document.createElement("a");link.href=url;link.download=name;link.click();
  setTimeout(()=>URL.revokeObjectURL(url),1000);
}
function asFinding(f:BrowserFinding, path:string): Finding {
  return {fingerprint:f.id,path,line:f.line,end_line:f.endLine,rule_id:f.ruleId,title:f.title,message:f.message,severity:f.severity,confidence:"Requires review",cwe:f.cwe,owasp:"Unmapped",engine:"Browser pattern checks",classification:f.classification,snippet:"",status:"open"};
}

export default function CodeChecker() {
  const [source,setSource]=useState("");
  const [language,setLanguage]=useState<BrowserLanguage>("typescript");
  const [filename,setFilename]=useState("untitled.ts");
  const [result,setResult]=useState<BrowserAnalysis|null>(null);
  const [selected,setSelected]=useState<BrowserFinding|null>(null);
  const [filter,setFilter]=useState("all");
  const [busy,setBusy]=useState(false);
  const [error,setError]=useState("");
  const [theme,setTheme]=useState("dark");
  const [dragging,setDragging]=useState(false);
  const [patchOpen,setPatchOpen]=useState(false);
  const [reviewed,setReviewed]=useState(false);
  const fileInput=useRef<HTMLInputElement>(null);
  const textarea=useRef<HTMLTextAreaElement>(null);
  const gutter=useRef<HTMLDivElement>(null);
  const worker=useRef<Worker|null>(null);
  const revision=useRef(0);
  useEffect(()=>{setTheme(document.documentElement.dataset.theme||"dark");return ()=>worker.current?.terminate();},[]);
  function invalidate() {revision.current++;worker.current?.terminate();worker.current=null;setBusy(false);setResult(null);setSelected(null);setPatchOpen(false);setReviewed(false);setError("");}
  function changeSource(value:string) {invalidate();if(new TextEncoder().encode(value).byteLength>maxBytes){setError("Code is limited to 200 KiB. Paste a smaller portion or choose a smaller file.");return;}setSource(value);}
  function toggleTheme() {const next=theme==="dark"?"light":"dark";setTheme(next);document.documentElement.dataset.theme=next;try{localStorage.setItem("cg-theme",next);}catch{}}
  function selectFinding(f:BrowserFinding) {setSelected(f);setPatchOpen(false);setReviewed(false);}
  function checkCode() {
    if(!source.trim()||busy)return;
    invalidate();
    if(new TextEncoder().encode(source).byteLength>maxBytes){setError("This file is too large. Use a source file up to 200 KiB.");return;}
    setBusy(true);const current=revision.current;
    try {
      const task=new Worker(new URL("../lib/checker.worker.ts",import.meta.url));worker.current=task;
      task.onmessage=(event:MessageEvent<{result?:BrowserAnalysis;error?:string}>)=>{
        if(current!==revision.current)return;
        setBusy(false);task.terminate();worker.current=null;
        if(event.data.error){setError(event.data.error);return;}
        if(event.data.result){setResult(event.data.result);setSelected(event.data.result.findings[0]||null);setFilter("all");}
      };
      task.onerror=()=>{if(current===revision.current){setBusy(false);setError("The browser checker could not start. Reload the page and try again.");task.terminate();}};
      task.postMessage({source,language,filename});
    } catch {setBusy(false);setError("This browser could not start the checker. Try a browser with Web Worker support.");}
  }
  async function upload(file?:File) {
    if(!file)return;
    invalidate();
    const ext=file.name.split(".").pop()?.toLowerCase();
    if(!ext||!["py","js","jsx","ts","tsx"].includes(ext)){setError("Choose a Python, JavaScript or TypeScript source file (.py, .js, .jsx, .ts, .tsx).");return;}
    if(file.size>maxBytes){setError("This file is too large. Choose a source file up to 200 KiB.");return;}
    const current=revision.current;
    try {const text=await file.text();if(current!==revision.current)return;if(text.includes("\0")){setError("This looks like a binary file. Choose a plain-text source file.");return;}
      setSource(text);setFilename(file.name.replace(/[^\w. -]/g,"_").slice(0,100));setLanguage(ext==="py"?"python":ext.startsWith("js")?"javascript":"typescript");
    } catch {setError("The file could not be read. Try choosing it again.");}
  }
  const shown=result?.findings.filter(f=>filter==="all"||f.severity===filter)||[];
  const lineCount=source?source.split("\n").length:1;
  const selectedViewer=useMemo(()=>selected&&result?asFinding(selected,result.filename):undefined,[selected,result]);
  return <div className={styles.app} onKeyDown={event=>{if((event.metaKey||event.ctrlKey)&&event.key==="Enter"){event.preventDefault();checkCode();}}}>
    <a className={styles.skip} href="#code-input">Skip to code editor</a>
    <header className={styles.header}>
      <a className={styles.brand} href="/" aria-label="CodeGuardian home"><span className={styles.brandMark}><ShieldCheck size={24} strokeWidth={1.4}/></span><span>CodeGuardian<span className={styles.ai}>AI</span></span></a>
      <nav aria-label="Main navigation"><a href="#code-input" aria-current="page">Code checker</a><a href="#how-it-works">How it works</a></nav>
      <div className={styles.headerEnd}><span><LockKeyhole size={13}/> Private by design</span><button className={styles.iconButton} onClick={toggleTheme} aria-label={`Switch to ${theme==="dark"?"light":"dark"} theme`}>{theme==="dark"?<Sun size={18}/>:<Moon size={18}/>}</button></div>
    </header>
    <main className={styles.main}>
      <section className={styles.intro} aria-labelledby="checker-title"><div><h1 id="checker-title">Good code deserves<br/>a second look.</h1><p>Find risky patterns. Understand the fix.<br className={styles.desktopBreak}/> Just your code, without the setup.</p></div><div className={styles.introAside}><span className={styles.privateMark}><Fingerprint size={30} strokeWidth={1.1}/></span><div><strong>Your code stays yours.</strong><p>Checks run in your browser.<br/>No account. No source uploads.</p></div></div></section>
      <section className={styles.workbench} id="code-input" aria-label="Code checking workspace">
        <div className={styles.editorPane} onDragOver={e=>{e.preventDefault();setDragging(true);}} onDragLeave={e=>{if(!e.currentTarget.contains(e.relatedTarget as Node))setDragging(false);}} onDrop={e=>{e.preventDefault();setDragging(false);if(e.dataTransfer.files.length!==1){setError("Choose one source file at a time.");return;}void upload(e.dataTransfer.files[0]);}}>
          <div className={styles.paneHeader}><div className={styles.fileIdentity}><FileCode2 size={16}/><span>{result?.filename||filename}</span>{source&&!result&&<span className={styles.unsaved} title="Not yet checked"/>}</div><label className={styles.language}><span className={styles.srOnly}>Language</span><select aria-label="Language" value={language} onChange={e=>{invalidate();const next=e.target.value as BrowserLanguage;setLanguage(next);setFilename(`untitled.${next==="python"?"py":next==="javascript"?"js":"ts"}`);}}><option value="typescript">TypeScript</option><option value="javascript">JavaScript</option><option value="python">Python</option></select><ChevronDown size={12}/></label></div>
          <div className={styles.editorToolbar}><span><Code2 size={14}/>{result?"Redacted source":"Source code"}</span><div>{result?<button onClick={()=>{invalidate();requestAnimationFrame(()=>textarea.current?.focus());}}>Edit code <ArrowUpRight size={13}/></button>:<button onClick={()=>{invalidate();setSource(EXAMPLE);setLanguage("typescript");setFilename("example.ts");}}>Load example <ArrowUpRight size={13}/></button>}<button onClick={()=>{invalidate();setSource("");setFilename("untitled."+(language==="python"?"py":language==="javascript"?"js":"ts"));}} disabled={!source} aria-label="Clear code"><X size={15}/></button></div></div>
          <div className={`${styles.editorBody} ${dragging?styles.dragging:""}`}>
            {result?<CodeViewer source={result.redactedSource} path={result.filename} theme={theme} finding={selectedViewer}/>:<><div className={styles.lineNumbers} ref={gutter} aria-hidden="true">{Array.from({length:lineCount},(_,i)=>i+1).join("\n")}</div><textarea ref={textarea} className={styles.codeInput} aria-label="Source code" aria-describedby="source-help" value={source} onChange={e=>changeSource(e.target.value)} onScroll={e=>{if(gutter.current)gutter.current.scrollTop=e.currentTarget.scrollTop;}} placeholder={"// Paste your code here\n// or drop a source file to get started"} spellCheck={false} autoCapitalize="off" autoComplete="off" autoCorrect="off" wrap="off"/></>}
            {dragging&&<div className={styles.dropOverlay}><Upload size={28}/><strong>Drop your source file</strong><span>Python, JavaScript or TypeScript · Up to 200 KiB</span></div>}
          </div>
          <div className={styles.editorFooter}><span id="source-help">{lineCount} {lineCount===1?"line":"lines"}<span>UTF-8</span></span><span>{result?<><LockKeyhole size={12}/> Detected secrets masked</>:".py · .js · .ts · Up to 200 KiB"}</span></div>
          <div className={styles.actions}><input ref={fileInput} type="file" accept=".py,.js,.jsx,.ts,.tsx" aria-label="Upload source file" className={styles.fileInput} onChange={e=>{void upload(e.target.files?.[0]);e.target.value="";}}/><button className={styles.uploadButton} onClick={()=>fileInput.current?.click()}><Upload size={16}/>Choose file</button><button className={styles.checkButton} disabled={!source.trim()||busy} onClick={checkCode}>{busy?<Loader2 size={17} className={styles.spin}/>:<ScanLine size={17}/>}<span>{busy?"Checking code…":"Check code"}</span><kbd aria-hidden="true">⌘ ↵</kbd></button></div>
          {error&&<p className={styles.error} role="alert"><Info size={15}/>{error}</p>}
        </div>
        <aside className={styles.resultsPane} aria-label="Code check results" aria-busy={busy}>
          <div className={styles.paneHeader}><span className={styles.resultsLabel}><ScanLine size={16}/>Review findings</span><span className={styles.engineLabel}>Browser checks</span></div>
          {!result?<div className={styles.readyState}><div className={styles.inspectionGraphic} aria-hidden="true"><div className={styles.scanBrackets}/><Code2 size={48} strokeWidth={.9}/><span className={styles.scanBeam}/></div><h2>{busy?"Reading the patterns…":"Ready for a closer look."}</h2><p>{busy?"Inspecting your source on this device. Your code is never executed.":"Add your code and run a check. Findings will appear here, with the context to act on them."}</p><div className={styles.checkScope}><span><Check size={14}/>Injection & unsafe execution</span><span><Check size={14}/>Potential exposed credentials</span><span><Check size={14}/>Risky security configuration</span></div><p className={styles.emptyNote}>Pattern matches are starting points for review,<br/>not proof of exploitability.</p></div>:<div className={styles.resultContent} data-testid="checker-results">
            <div className={styles.resultSummary} aria-live="polite"><span className={styles.resultCount}>{result.findings.length}</span><div><h2>Review findings</h2><p>{result.findings.length?"Potential issues. Your context matters.":"No patterns matched. This is not a security clearance."}</p></div><button className={styles.iconButton} aria-label="Export report" title="Export redacted JSON report" onClick={()=>saveFile("codeguardian-report.json",JSON.stringify({engine:"CodeGuardian browser pattern checks",...result},null,2),"application/json")}><Download size={17}/></button></div>
            {result.limitations.filter(item=>item.includes("100")).map(item=><p className={styles.capNotice} key={item}>{item}</p>)}
            {result.findings.length>0&&<><div className={styles.findingFilters}><span>{result.linesAnalyzed} lines checked</span><select aria-label="Filter severity" value={filter} onChange={e=>{setFilter(e.target.value);const next=result.findings.find(f=>e.target.value==="all"||f.severity===e.target.value);setSelected(next||null);setPatchOpen(false);setReviewed(false);}}><option value="all">All severities</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></div><div className={styles.findingList}>{shown.map(f=><button className={`${styles.finding} ${selected?.id===f.id?styles.selected:""}`} key={f.id} onClick={()=>selectFinding(f)}><span className={`${styles.severity} ${styles[f.severity]}`}>{f.severity}</span><strong>{f.title}</strong><span className={styles.findingLine}>L{f.line}<ArrowRight size={13}/></span></button>)}{!shown.length&&<p className={styles.noMatch}>No findings at this severity.</p>}</div></>}
            {selected&&<div className={styles.findingDetail} key={selected.id}><div className={styles.detailMeta}><span>{selected.cwe}</span><span>{selected.classification==="secure_coding_suggestion"?"Secure-coding suggestion":"Potential vulnerability"}</span></div><h3>{selected.title}</h3><p>{selected.message}</p><h4>Recommended change</h4><p>{selected.remediation}</p><details><summary>What to verify<ChevronDown size={14}/></summary><ul>{selected.conditions.map((item,i)=><li key={i}>{item}</li>)}</ul></details>{selected.patch&&<><button className={styles.patchButton} onClick={()=>setPatchOpen(!patchOpen)}><Code2 size={15}/>{patchOpen?"Hide proposed change":"Review proposed change"}<ChevronDown size={14}/></button>{patchOpen&&<div className={styles.patch}><div><span>Original</span><pre>{selected.patch.original}</pre></div><div><span>Proposed</span><pre>{selected.patch.modified}</pre></div><p>{selected.patch.caveat}</p><label><input type="checkbox" checked={reviewed} onChange={e=>setReviewed(e.target.checked)}/>I reviewed this change and will test it before use.</label><button disabled={!reviewed} onClick={()=>saveFile("codeguardian.patch",selected.patch!.diff,"text/plain")}><Download size={14}/>Export reviewed patch</button></div>}</>}</div>}
            {!result.findings.length&&<div className={styles.noFindings}><CheckCheck size={40} strokeWidth={1.1}/><h3>Keep looking beyond patterns.</h3><p>Review authorization, data flow and dependencies with the full context of your application.</p></div>}
          </div>}
          <div className={styles.reviewFooter}><LockKeyhole size={13}/><span>Never executed. Never sent to a server.</span></div>
        </aside>
      </section>
      <div className={styles.belowWorkbench}><span><ShieldCheck size={15}/>Your code stays in this tab. We don’t store it.</span><a href="#how-it-works">What these checks cover<ArrowDown size={13}/></a></div>
      <section className={styles.method} id="how-it-works"><div><h2>A useful first pass.<br/>An informed next step.</h2><p>Fast feedback without handing over your source.</p></div><div className={styles.methodRows}><div><Code2 size={18}/><div><h3>Bring the code, skip the connections.</h3><p>Paste a snippet or choose a source file. Python, JavaScript and TypeScript work without an account.</p></div></div><div><ScanLine size={18}/><div><h3>Inspect patterns, then verify context.</h3><p>Local lexical rules flag potential risks and redact detected credentials. They do not trace data flow, resolve dependencies or prove vulnerabilities. These are not Semgrep, Bandit or AI model results.</p></div></div><div><CheckCheck size={18}/><div><h3>Every change stays in your hands.</h3><p>Read the evidence, review a proposed change where available, and export a redacted report. Nothing is applied to your files.</p></div></div></div></section>
      <footer className={styles.footer}><a className={styles.brand} href="#checker-title"><ShieldCheck size={20} strokeWidth={1.3}/><span>CodeGuardian</span></a><span>Evidence before inference.</span><a href="#how-it-works">About these checks <ArrowUpRight size={14}/></a></footer>
    </main>
  </div>;
}
