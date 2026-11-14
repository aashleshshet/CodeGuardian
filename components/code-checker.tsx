"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import dynamic from "next/dynamic";
import { ArrowDown, ArrowRight, ArrowUpRight, Check, CheckCheck, ChevronDown, Code2, Download, FileCode2, Fingerprint, Info, Loader2, LockKeyhole, Moon, ScanLine, ShieldCheck, Sun, Upload, X } from "lucide-react";
import type { BrowserAnalysis, BrowserFinding, BrowserLanguage } from "@/lib/browser-analysis";
import type { Finding } from "@/lib/types";
import styles from "./checker.module.css";
import { MotionSelection, MotionReveal, SpringButton } from "./parallel-motion";

const CodeViewer = dynamic(() => import("./code-viewer"), {ssr:false, loading:()=> <div className={styles.editorLoading}>Opening the source viewer…</div>});
const EXAMPLE = `// Example only — intentionally unsafe patterns for review.\n// Source is inspected, never executed.\n\nconst message = location.hash.slice(1);\nconst markup = "<p>" + message + "</p>";\nconst preview = document.getElementById("preview");\n\nif (preview) {\n  preview.innerHTML = markup;\n}\n\neval(message);\n`;
const maxBytes = 200 * 1024;

function saveFile(name:string, value:string, type:string) {
  const url=URL.createObjectURL(new Blob([value],{type}));
  const link=document.createElement("a");link.href=url;link.download=name;link.click();
  setTimeout(()=>URL.revokeObjectURL(url),1000);
}
function asFinding(f:BrowserFinding, path:string): Finding {
  return {fingerprint:f.id,path,line:f.line,end_line:f.endLine,rule_id:f.ruleId,title:f.title,message:f.message,severity:f.severity,confidence:"Requires review",cwe:f.cwe,owasp:f.owasp,engine:"Local syntax and flow checks",classification:f.classification,snippet:"",status:"open"};
}

export default function CodeChecker() {
  const [source,setSource]=useState("");
  const [language,setLanguage]=useState<BrowserLanguage>("typescript");
  const [filename,setFilename]=useState("untitled.ts");
  const [result,setResult]=useState<BrowserAnalysis|null>(null);
  const [selected,setSelected]=useState<BrowserFinding|null>(null);
  const [focusLine,setFocusLine]=useState<number|null>(null);
  const [filter,setFilter]=useState("all");
  const [busy,setBusy]=useState(false);
  const [error,setError]=useState("");
  const [theme,setTheme]=useState("dark");
  const [activeSection,setActiveSection]=useState("code-input");
  const [dragging,setDragging]=useState(false);
  const [patchOpen,setPatchOpen]=useState(false);
  const [reviewed,setReviewed]=useState(false);
  const fileInput=useRef<HTMLInputElement>(null);
  const textarea=useRef<HTMLTextAreaElement>(null);
  const gutter=useRef<HTMLDivElement>(null);
  const worker=useRef<Worker|null>(null);
  const revision=useRef(0);
  const deadline=useRef<ReturnType<typeof setTimeout>|null>(null);
  function clearDeadline(){if(deadline.current)clearTimeout(deadline.current);deadline.current=null;}
  useEffect(()=>{setTheme(document.documentElement.dataset.theme||"dark");return ()=>{worker.current?.terminate();clearDeadline();};},[]);
  useEffect(()=>{
    let frame=0;
    const syncSection=()=>{frame=0;const top=document.getElementById("how-it-works")?.getBoundingClientRect().top;setActiveSection(top!==undefined&&top<window.innerHeight*.55?"how-it-works":"code-input");};
    const schedule=()=>{if(!frame)frame=requestAnimationFrame(syncSection);};
    syncSection();window.addEventListener("scroll",schedule,{passive:true});window.addEventListener("resize",schedule);
    return ()=>{cancelAnimationFrame(frame);window.removeEventListener("scroll",schedule);window.removeEventListener("resize",schedule);};
  },[]);
  function chooseSeverity(value:string){setFilter(value);setSelected(result?.findings.find(f=>value==="all"||f.severity===value)||null);setFocusLine(null);setPatchOpen(false);setReviewed(false);}
  function invalidate() {revision.current++;clearDeadline();setFocusLine(null);worker.current?.terminate();worker.current=null;setBusy(false);setResult(null);setSelected(null);setPatchOpen(false);setReviewed(false);setError("");}
  function changeSource(value:string) {invalidate();if(new TextEncoder().encode(value).byteLength>maxBytes){setError("Code is limited to 200 KiB. Paste a smaller portion or choose a smaller file.");return;}setSource(value);}
  function changeTheme(next:"dark"|"light") {setTheme(next);document.documentElement.dataset.theme=next;try{localStorage.setItem("cg-theme",next);}catch{}}
  function selectFinding(f:BrowserFinding) {setSelected(f);setFocusLine(null);setPatchOpen(false);setReviewed(false);}
  function checkCode() {
    if(!source.trim()||busy)return;
    invalidate();
    if(new TextEncoder().encode(source).byteLength>maxBytes){setError("This file is too large. Use a source file up to 200 KiB.");return;}
    setBusy(true);const current=revision.current;
    try {
      const task=new Worker(new URL("../lib/checker.worker.ts",import.meta.url));worker.current=task;
      deadline.current=setTimeout(()=>{if(current!==revision.current)return;task.terminate();worker.current=null;deadline.current=null;setBusy(false);setError("Analysis reached its 15-second limit. Check a smaller, complete source file. No security conclusion is available.");},15000);
      task.onmessage=(event:MessageEvent<{result?:BrowserAnalysis;error?:string}>)=>{
        if(current!==revision.current)return;
        clearDeadline();setBusy(false);task.terminate();worker.current=null;
        if(event.data.error){setError(event.data.error);return;}
        if(event.data.result){setResult(event.data.result);setSelected(event.data.result.findings[0]||null);setFilter("all");}
      };
      task.onerror=()=>{if(current===revision.current){clearDeadline();setBusy(false);setError("The browser checker could not start. Reload the page and try again.");task.terminate();}};
      task.postMessage({source,language,filename});
    } catch {clearDeadline();worker.current?.terminate();worker.current=null;setBusy(false);setError("This browser could not start the checker. Try a browser with Web Worker support.");}
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
  const selectedViewer=useMemo(()=>selected&&result?asFinding(focusLine?{...selected,line:focusLine,endLine:focusLine}:selected,result.filename):undefined,[selected,result,focusLine]);
  return <div className={styles.app} onKeyDown={event=>{if((event.metaKey||event.ctrlKey)&&event.key==="Enter"){event.preventDefault();checkCode();}}}>
    <a className={styles.skip} href="#code-input">Skip to code editor</a>
    <header className={styles.header}>
      <a className={styles.brand} href="/" aria-label="CodeGuardian home"><span className={styles.brandMark}><ShieldCheck size={24} strokeWidth={1.4}/></span><span>CodeGuardian<span className={styles.ai}>AI</span></span></a>
      <MotionSelection as="nav" activeKey={activeSection} className={styles.navigation} aria-label="Main navigation" data-active={activeSection==="how-it-works"?"1":"0"}><a data-motion-item href="#code-input" aria-current={activeSection==="code-input"?"location":undefined} onClick={()=>setActiveSection("code-input")}><Code2 size={15}/>Code checker</a><a data-motion-item href="#how-it-works" aria-current={activeSection==="how-it-works"?"location":undefined} onClick={()=>setActiveSection("how-it-works")}><Info size={15}/>How it works</a></MotionSelection>
      <div className={styles.headerEnd}><span><LockKeyhole size={13}/> Private by design</span><MotionSelection activeKey={theme} className={styles.themeSwitch} role="group" aria-label="Appearance" data-active={theme==="light"?"1":"0"}><button data-motion-item onClick={()=>changeTheme("dark")} aria-label="Switch to dark theme" aria-pressed={theme==="dark"}><Moon size={16}/></button><button data-motion-item onClick={()=>changeTheme("light")} aria-label="Switch to light theme" aria-pressed={theme==="light"}><Sun size={16}/></button></MotionSelection></div>
    </header>
    <main className={styles.main}>
      <section className={styles.intro} aria-labelledby="checker-title"><div><h1 id="checker-title">Good code deserves<br/>{" "}a second look.</h1><p>Trace risky code. Understand the fix.<br className={styles.desktopBreak}/> Just your code, without the setup.</p></div><div className={styles.introAside}><span className={styles.privateMark}><Fingerprint size={20} strokeWidth={1.1}/></span><div><strong>Your code stays yours.</strong><p>Checks run in your browser.<br/>{" "}No account. No source uploads.</p></div></div></section>
      <section className={styles.workbench} id="code-input" tabIndex={-1} aria-label="Code checking workspace">
        <div className={styles.editorPane} onDragOver={e=>{e.preventDefault();setDragging(true);}} onDragLeave={e=>{if(!e.currentTarget.contains(e.relatedTarget as Node))setDragging(false);}} onDrop={e=>{e.preventDefault();setDragging(false);if(e.dataTransfer.files.length!==1){setError("Choose one source file at a time.");return;}void upload(e.dataTransfer.files[0]);}}>
          <div className={styles.paneHeader}><div className={styles.fileIdentity}><FileCode2 size={16}/><span>{result?.filename||filename}</span>{source&&!result&&<span className={styles.unsaved} title="Not yet checked"/>}</div><label className={styles.language}><span className={styles.srOnly}>Language</span><select aria-label="Language" value={language} onChange={e=>{invalidate();const next=e.target.value as BrowserLanguage;setLanguage(next);setFilename(`untitled.${next==="python"?"py":next==="javascript"?"js":"ts"}`);}}><option value="typescript">TypeScript</option><option value="javascript">JavaScript</option><option value="python">Python</option></select><ChevronDown size={12}/></label></div>
          <div className={styles.editorToolbar}><span><Code2 size={14}/>{result?"Redacted source":"Source code"}</span><div>{result?<button onClick={()=>{invalidate();requestAnimationFrame(()=>textarea.current?.focus());}}>Edit code <ArrowUpRight size={13}/></button>:<button onClick={()=>{invalidate();setSource(EXAMPLE);setLanguage("typescript");setFilename("example.ts");}}>Load example <ArrowUpRight size={13}/></button>}<button onClick={()=>{invalidate();setSource("");setFilename("untitled."+(language==="python"?"py":language==="javascript"?"js":"ts"));}} disabled={!source} aria-label="Clear code"><X size={15}/></button></div></div>
          <div className={`${styles.editorBody} ${dragging?styles.dragging:""}`}>
            {result?<CodeViewer source={result.redactedSource} path={result.filename} theme={theme} finding={selectedViewer}/>:<><div className={styles.lineNumbers} ref={gutter} aria-hidden="true">{Array.from({length:lineCount},(_,i)=>i+1).join("\n")}</div><textarea ref={textarea} className={styles.codeInput} aria-label="Source code" aria-describedby="source-help" value={source} onChange={e=>changeSource(e.target.value)} onScroll={e=>{if(gutter.current)gutter.current.scrollTop=e.currentTarget.scrollTop;}} placeholder={"// Paste your code here\n// or drop a source file to get started"} spellCheck={false} autoCapitalize="off" autoComplete="off" autoCorrect="off" wrap="off"/></>}
            {dragging&&<div className={styles.dropOverlay}><Upload size={28}/><strong>Drop your source file</strong><span>Python, JavaScript or TypeScript · Up to 200 KiB</span></div>}
          </div>
          <div className={styles.editorFooter}><span id="source-help">{lineCount} {lineCount===1?"line":"lines"}<span>UTF-8</span></span><span>{result?<><LockKeyhole size={12}/> Detected secrets masked</>:".py · .js · .ts · Up to 200 KiB"}</span></div>
          <div className={styles.actions}><input ref={fileInput} type="file" accept=".py,.js,.jsx,.ts,.tsx" aria-label="Upload source file" className={styles.fileInput} onChange={e=>{void upload(e.target.files?.[0]);e.target.value="";}}/><SpringButton className={styles.uploadButton} onClick={()=>fileInput.current?.click()}><Upload size={16}/>Choose file</SpringButton><SpringButton className={styles.checkButton} disabled={!source.trim()||busy} onClick={checkCode}>{busy?<Loader2 size={17} className={styles.spin}/>:<ScanLine size={17}/>}<span>{busy?"Checking code…":"Check code"}</span><kbd aria-hidden="true">⌘ ↵</kbd></SpringButton></div>
          {error&&<p className={styles.error} role="alert"><Info size={15}/>{error}</p>}
        </div>
        <aside className={styles.resultsPane} aria-label="Code check results" aria-busy={busy}>
          <div className={styles.paneHeader}><span className={styles.resultsLabel}><ScanLine size={16}/>Review findings</span><span className={styles.engineLabel}>Syntax + data flow</span></div>
          {!result?<div className={styles.readyState}><div className={styles.inspectionGraphic} data-scanning={busy} aria-hidden="true"><div className={styles.scanBrackets}/><Code2 size={48} strokeWidth={.9}/><span className={styles.scanBeam}/></div><h2>{busy?"Tracing the code…":"Ready for a closer look."}</h2><p>{busy?"Inspecting your source on this device. Your code is never executed.":"Add your code and run a check. Findings will appear here, with the context to act on them."}</p><div className={styles.checkScope}><span><Check size={14}/>Injection &amp; unsafe execution</span><span><Check size={14}/>Potential exposed credentials</span><span><Check size={14}/>Risky security configuration</span></div><p className={styles.emptyNote}>Static findings are starting points for review,<br/>not proof of exploitability.</p></div>:<div className={styles.resultContent} data-testid="checker-results">
            <div className={styles.resultSummary} aria-live="polite"><span className={styles.resultCount}>{result.findings.length}</span><div><h2>Review findings</h2><p>{result.findings.length?"Potential issues. Your context matters.":"No findings from these checks. Coverage is limited."}</p></div><button className={styles.iconButton} aria-label="Export report" title="Export redacted JSON report" onClick={()=>saveFile("codeguardian-report.json",JSON.stringify({engine:"CodeGuardian local syntax and data-flow checks",...result},null,2),"application/json")}><Download size={17}/></button></div>
            <div className={`${styles.coverage} ${result.coverage.syntax==="partial"?styles.partial:""}`} role={result.coverage.syntax==="partial"?"status":undefined}><strong>{result.coverage.syntax==="partial"?"Partial analysis — review required":"Syntax parsed · single-file analysis"}</strong><p>{result.coverage.syntax==="partial"?"Parsing or analysis limits prevented full processing. Fix the source or check a smaller file.":"Selected flows and risky APIs checked. Cross-file and business logic are outside this analysis."}</p>{result.coverage.diagnostics.map((d,i)=><p key={i}>Line {d.line}: {d.message}</p>)}</div>
            {result.limitations.filter(item=>item.includes("100")).map(item=><p className={styles.capNotice} key={item}>{item}</p>)}
            {result.findings.length>0&&<><div className={styles.findingFilters}><span>{result.linesAnalyzed} lines checked</span><MotionSelection activeKey={filter} className={styles.severityTabs} role="group" aria-label="Filter severity">{["all","high","medium","low"].map(value=><button data-motion-item key={value} aria-pressed={filter===value} aria-label={value==="all"?"All severities":`${value[0].toUpperCase()}${value.slice(1)} severity`} onClick={()=>chooseSeverity(value)}>{value==="all"?"All":value[0].toUpperCase()+value.slice(1)}</button>)}</MotionSelection></div><MotionSelection activeKey={selected?.id||""} layoutKey={filter} className={styles.findingList}>{shown.map(f=><button data-motion-item className={`${styles.finding} ${selected?.id===f.id?styles.selected:""}`} key={f.id} aria-pressed={selected?.id===f.id} onClick={()=>selectFinding(f)}><span className={`${styles.severity} ${styles[f.severity]}`}>{f.severity}</span><strong>{f.title}</strong><span className={styles.findingLine}>L{f.line}</span><span className={styles.selectionIcon}>{selected?.id===f.id?<Check size={13}/>:<ArrowRight size={13}/>}</span></button>)}{!shown.length&&<p className={styles.noMatch}>No findings at this severity.</p>}</MotionSelection></>}
            {selected&&<MotionReveal className={styles.findingDetail} motionKey={selected.id}><div className={styles.detailMeta}><span>{selected.cwe}</span><span>{selected.classification==="secure_coding_suggestion"?"Secure-coding suggestion":"Potential vulnerability"}</span></div><h3>{selected.title}</h3><p>{selected.message}</p><div className={styles.evidenceKind}>{selected.evidence==="data_flow"?"Input-to-operation flow detected":selected.evidence==="structural"?"Syntax-based risk — input origin unconfirmed":"Pattern match — verify context"}<span>{selected.owasp}</span></div>{selected.trace&&selected.trace.length>0&&<div className={styles.flowTrace} aria-label="Evidence trace"><h4>Follow the evidence</h4><ol>{selected.trace.map((step,i)=><li key={i}><button aria-pressed={focusLine===step.line} onClick={()=>setFocusLine(step.line)} aria-label={`Show ${step.kind} at line ${step.line}`}><span>L{step.line}</span><div><strong>{step.kind}</strong><p>{step.label}</p></div><ArrowUpRight size={13}/></button></li>)}</ol><p>A static approximation. Review reachability and validation in your application.</p></div>}<h4>Recommended change</h4><p>{selected.remediation}</p><details><summary>What to verify<ChevronDown size={14}/></summary><ul>{selected.conditions.map((item,i)=><li key={i}>{item}</li>)}</ul></details>{selected.patch&&<><button className={styles.patchButton} aria-expanded={patchOpen} onClick={()=>setPatchOpen(!patchOpen)}><Code2 size={15}/>{patchOpen?"Hide proposed change":"Review proposed change"}<ChevronDown size={14}/></button>{patchOpen&&<div className={styles.patch}><div><span>Original</span><pre>{selected.patch.original}</pre></div><div><span>Proposed</span><pre>{selected.patch.modified}</pre></div><p>{selected.patch.caveat}</p><label><input type="checkbox" checked={reviewed} onChange={e=>setReviewed(e.target.checked)}/>I reviewed this change and will test it before use.</label><button disabled={!reviewed} onClick={()=>saveFile("codeguardian.patch",selected.patch!.diff,"text/plain")}><Download size={14}/>Export reviewed patch</button></div>}</>}</MotionReveal>}
            {!result.findings.length&&<div className={styles.noFindings}>{result.coverage.syntax==="partial"?<Info size={40} strokeWidth={1.1}/>:<CheckCheck size={40} strokeWidth={1.1}/>}<h3>{result.coverage.syntax==="partial"?"Analysis needs another pass.":"Review beyond this file."}</h3><p>Review authentication, authorization, runtime behavior and dependencies with the full context of your application. A zero result is not a security clearance.</p></div>}
          </div>}
          <div className={styles.reviewFooter}><LockKeyhole size={13}/><span>Never executed. Never sent to a server.</span></div>
        </aside>
      </section>
      <div className={styles.belowWorkbench}><span><ShieldCheck size={15}/>Your code stays in this tab. We don’t store it.</span><a href="#how-it-works">What these checks cover<ArrowDown size={13}/></a></div>
      <section className={styles.method} id="how-it-works"><div><h2>A useful first pass.<br/>An informed next step.</h2><p>Fast feedback without handing over your source.</p></div><div className={styles.methodRows}><div><Code2 size={18}/><div><h3>Bring the code, skip the connections.</h3><p>Paste a snippet or choose a source file. Python, JavaScript and TypeScript work without an account.</p></div></div><div><ScanLine size={18}/><div><h3>Follow the input. Verify the context.</h3><p>Syntax parsers and bounded data-flow checks follow selected inputs into risky operations. Review source-to-sink traces, CWE mappings and detected credentials. Cross-file logic, dependencies and runtime exploitability require deeper review. These are not Semgrep, Bandit or AI model results.</p></div></div><div><CheckCheck size={18}/><div><h3>Every change stays in your hands.</h3><p>Read the evidence, review a proposed change where available, and export a redacted report. Nothing is applied to your files.</p><a className={styles.agentLink} href="/workspace">Open the local RAG workspace<ArrowUpRight size={13}/><span>Requires the on-device review service</span></a></div></div></div></section>
      <footer className={styles.footer}><a className={styles.brand} href="#checker-title"><ShieldCheck size={20} strokeWidth={1.3}/><span>CodeGuardian</span></a><span>Evidence before inference.</span><a href="#how-it-works">About these checks <ArrowUpRight size={14}/></a></footer>
    </main>
  </div>;
}
