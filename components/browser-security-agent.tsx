"use client";

import { useEffect, useId, useLayoutEffect, useRef, useState } from "react";
import { ArrowUpRight, BookOpen, Check, ChevronDown, Download, Loader2, Send, ShieldCheck, Sparkles, X } from "lucide-react";
import type { BrowserFinding } from "@/lib/browser-analysis";
import { redactCode } from "@/lib/lexical-analysis";
import { BrowserAI, browserAIAvailable, BROWSER_MODEL_DOWNLOAD, BROWSER_MODEL_LABEL } from "@/lib/browser-ai";
import { buildBrowserRagMessages, retrieveBrowserGuidance, validateBrowserRagAnswer, type BrowserRagAnswer } from "@/lib/browser-rag";
import { MotionReveal, SpringButton } from "./parallel-motion";
import styles from "./browser-security-agent.module.css";

type Turn = { id: number; question: string; result: BrowserRagAnswer };
type ModelState = "idle" | "loading" | "ready" | "clearing";
const prompts = ["What should I verify?", "How should I fix this?", "What tests should I add?"];

export default function BrowserSecurityAgent({ finding, source }: { finding: BrowserFinding; source: string }) {
  const questionId = useId();
  const [question, setQuestion] = useState("");
  const [turns, setTurns] = useState<Turn[]>([]);
  const [available, setAvailable] = useState<boolean | null>(null);
  const [modelState, setModelState] = useState<ModelState>("idle");
  const [useModel, setUseModel] = useState(false);
  const [downloadAttempted, setDownloadAttempted] = useState(false);
  const [progress, setProgress] = useState(0);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState("");
  const [modelError, setModelError] = useState("");
  const client = useRef<BrowserAI | null>(null);
  const generation = useRef<AbortController | null>(null);
  const loading = useRef<AbortController | null>(null);
  const conversation = useRef<HTMLDivElement>(null);
  const nextTurn = useRef(0);
  const mounted = useRef(false);
  const latestTurn = turns.at(-1)?.id;
  const modelBusy = modelState === "loading" || modelState === "clearing";

  useEffect(() => {
    mounted.current = true;
    void browserAIAvailable().then(value => { if (mounted.current) setAvailable(value); }).catch(() => { if (mounted.current) setAvailable(false); });
    return () => {
      mounted.current = false;
      generation.current?.abort(); loading.current?.abort();
      generation.current = null; loading.current = null;
      client.current?.dispose();
    };
  }, []);

  useLayoutEffect(() => {
    if (generation.current) {
      generation.current.abort(); generation.current = null;
      client.current?.dispose(); setModelState("idle"); setUseModel(false);
    }
    setTurns([]); setQuestion(""); setError(""); setPending(false);
  }, [finding.id, source]);

  useLayoutEffect(() => {
    const list = conversation.current;
    const latest = list?.lastElementChild;
    if (!list || !latest) return;
    list.scrollTo({ top: latest.getBoundingClientRect().top - list.getBoundingClientRect().top + list.scrollTop, behavior: "instant" });
  }, [latestTurn]);

  function cancelAnswer() {
    generation.current?.abort(); generation.current = null;
    client.current?.dispose(); setPending(false); setModelState("idle"); setUseModel(false);
  }

  function stopModel() {
    loading.current?.abort(); loading.current = null;
    client.current?.dispose(); setModelState("idle"); setUseModel(false); setProgress(0);
  }

  async function enableModel() {
    if (!available || modelBusy || pending || loading.current) return;
    const controller = new AbortController();
    loading.current = controller;
    const engine = client.current ??= new BrowserAI();
    setModelState("loading"); setModelError(""); setProgress(0); setDownloadAttempted(true);
    try {
      await engine.load(controller.signal, value => {
        if (loading.current === controller && !controller.signal.aborted) setProgress(Math.min(1, Math.max(0, value)));
      });
      if (loading.current !== controller || controller.signal.aborted) return;
      setModelState("ready"); setUseModel(true);
    } catch {
      if (loading.current !== controller || controller.signal.aborted) return;
      engine.dispose(); setModelState("idle"); setUseModel(false);
      setModelError("The model could not load. Check your connection and available memory, then retry. Retrieved guidance still works.");
    } finally {
      if (loading.current === controller) loading.current = null;
    }
  }

  async function removeModel() {
    if (modelBusy || pending) return;
    const engine = client.current ??= new BrowserAI();
    engine.dispose(); setModelState("clearing"); setUseModel(false); setModelError("");
    try {
      await engine.clearCache();
      if (mounted.current) setDownloadAttempted(false);
    } catch {
      if (mounted.current) setModelError("The cached model could not be removed. You can clear this site's stored data in your browser settings.");
    } finally {
      if (mounted.current) setModelState("idle");
    }
  }

  async function ask(value: string) {
    const text = value.trim();
    if (text.length < 3 || text.length > 1200 || generation.current) return;
    const controller = new AbortController();
    generation.current = controller;
    setPending(true); setError("");
    try {
      let result = retrieveBrowserGuidance(finding, text);
      if (useModel && modelState === "ready" && client.current && !result.abstained) {
        try {
          const raw = await client.current.generate(buildBrowserRagMessages(finding, text, source), result.citations.map(item => item.id), controller.signal);
          if (generation.current !== controller || controller.signal.aborted) return;
          result = validateBrowserRagAnswer(raw, result);
        } catch {
          if (generation.current !== controller || controller.signal.aborted) return;
          client.current?.dispose(); setModelState("idle"); setUseModel(false);
          setError("The model could not produce a grounded answer. Showing retrieved guidance instead; you can enable the model again.");
        }
      }
      if (generation.current !== controller || controller.signal.aborted) return;
      const id = ++nextTurn.current;
      setTurns(current => [...current.slice(-2), { id, question: redactCode(text), result }]);
      setQuestion("");
    } catch {
      if (generation.current === controller && !controller.signal.aborted) setError("Guidance could not be prepared. Try a shorter question about this finding.");
    } finally {
      if (generation.current === controller) { generation.current = null; setPending(false); }
    }
  }

  return <section className={styles.agent} aria-label="Private browser security agent">
    <div className={styles.heading}><span><Sparkles size={16}/>Security agent</span><span className={styles.mode}>{useModel && modelState === "ready" ? "Browser AI + retrieval" : "Retrieved guidance"}</span></div>
    <p className={styles.context}>Ask about this finding. Review the evidence and the sources behind each answer.</p>
    {!turns.length && <div className={styles.prompts}>{prompts.map(prompt => <button key={prompt} type="button" disabled={pending} onClick={() => void ask(prompt)}>{prompt}<ArrowUpRight size={13}/></button>)}</div>}
    <div ref={conversation} className={styles.conversation} aria-live="polite" aria-relevant="additions">
      {turns.map(turn => <MotionReveal key={turn.id} motionKey={String(turn.id)} className={styles.turn}>
        <p className={styles.question}>{turn.question}</p>
        <div className={styles.answer}>
          <span className={styles.answerLabel}><Check size={12}/>{turn.result.provider === "browser_llm" ? "AI interpretation · review required" : "Retrieved guidance"}</span>
          <p>{turn.result.answer}</p>
          {turn.result.conditions_to_verify.length > 0 && <details open={turn.result.provider === "browser_llm"}><summary>Conditions to verify<ChevronDown size={13}/></summary><ul>{turn.result.conditions_to_verify.map((item, index) => <li key={index}>{item}</li>)}</ul></details>}
          <div className={styles.sources}><span><BookOpen size={12}/>Sources used</span>{turn.result.citations.length ? turn.result.citations.map(citation => <details key={citation.id}><summary>{citation.id} · {citation.title}<ChevronDown size={13}/></summary><p>{citation.excerpt}</p><a href={citation.url} target="_blank" rel="noreferrer">Read source<ArrowUpRight size={12}/></a></details>) : <p>No matching source. Try a question about the selected finding.</p>}</div>
          {turn.result.provider === "browser_llm" && <p className={styles.caveat}>A small local model can make mistakes. Citations identify retrieved guidance; they do not prove exploitability.</p>}
        </div>
      </MotionReveal>)}
    </div>
    {pending && <div className={styles.pending} role="status"><Loader2 size={15} className={styles.spinner}/><span>Preparing a grounded answer…</span><button type="button" aria-label="Cancel agent answer" onClick={cancelAnswer}><X size={14}/></button></div>}
    {error && <p className={styles.error} role="alert">{error}</p>}
    <form className={styles.composer} onSubmit={event => { event.preventDefault(); void ask(question); }}>
      <label htmlFor={questionId}>Question about this finding</label>
      <textarea id={questionId} value={question} onChange={event => setQuestion(event.target.value)} maxLength={1200} rows={2} placeholder="Which input or control should I verify?" disabled={pending}/>
      <div>{modelState === "ready" ? <label className={styles.modelChoice}><input type="checkbox" checked={useModel} onChange={event => setUseModel(event.target.checked)} disabled={pending}/>Use browser AI</label> : <span>No model needed</span>}<SpringButton type="submit" disabled={pending || question.trim().length < 3}><Send size={14}/>Ask</SpringButton></div>
    </form>
    <details className={styles.modelSettings}>
      <summary><span><ShieldCheck size={14}/>Private browser AI</span><ChevronDown size={14}/></summary>
      <p>Optional: {BROWSER_MODEL_LABEL} generates answers on your device. The first use downloads {BROWSER_MODEL_DOWNLOAD} from Hugging Face and GitHub. Model files may remain in your browser cache.</p>
      <p>Your code and questions stay on this device. Generation needs a compatible WebGPU browser and roughly 1 GB of available GPU memory.</p>
      {available === null && <p role="status">Checking browser support…</p>}
      {available === false && <p className={styles.unsupported}>WebGPU is unavailable in this browser. You can still use the cited guidance above.</p>}
      {modelState === "loading" && <div className={styles.downloadProgress} role="status"><div><span>Downloading and preparing model</span><span>{Math.round(progress * 100)}%</span></div><progress aria-label="Browser model loading" value={progress} max={1}/><button type="button" onClick={stopModel}>Cancel download</button></div>}
      {modelState === "clearing" && <p role="status">Removing cached model…</p>}
      <div className={styles.modelActions}>
        {available && modelState === "idle" && <SpringButton type="button" onClick={() => void enableModel()} disabled={pending}><Download size={14}/>{downloadAttempted ? "Load browser AI" : "Download & enable AI"}</SpringButton>}
        {modelState === "ready" && <><span className={styles.ready}><Check size={13}/>Model ready</span><button type="button" onClick={stopModel} disabled={pending}>Unload model</button></>}
        {!modelBusy && <button type="button" onClick={() => void removeModel()} disabled={pending}>Remove cached model</button>}
      </div>
      {modelError && <p className={styles.error} role="alert">{modelError}</p>}
    </details>
    <p className={styles.privacy}>No account. No code upload. Questions stay in this tab and reset when you change findings. Nothing is applied to your files.</p>
  </section>;
}
