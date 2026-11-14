"use client";

import { useEffect, useLayoutEffect, useRef, useState } from "react";
import { ArrowUpRight, BookOpen, Check, Loader2, Send, Sparkles, X } from "lucide-react";
import { api } from "@/lib/api";
import { MotionReveal, SpringButton } from "./parallel-motion";
import styles from "./security-agent.module.css";

type Answer = {
  answer: string;
  provider: string;
  classification: string;
  citations: { id: string; title: string; url: string; excerpt: string }[];
  conditions_to_verify: string[];
  limitations: string | string[];
  retrieval: { method: string; matched_documents: number };
};
type Turn = { id: number; question: string; result: Answer };
const prompts = ["What should I verify?", "How should I fix this?", "What tests should I add?"];

export default function SecurityAgent({ scanId, fingerprint, title, csrf, llm, local }: {
  scanId: string; fingerprint: string; title: string; csrf?: string; llm: boolean; local: boolean;
}) {
  const [question, setQuestion] = useState("");
  const [turns, setTurns] = useState<Turn[]>([]);
  const [useModel, setUseModel] = useState(llm);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState("");
  const request = useRef<AbortController | null>(null);
  const conversation = useRef<HTMLDivElement>(null);
  const nextTurn = useRef(0);
  const latestTurn = turns.at(-1)?.id;
  useEffect(() => () => request.current?.abort(), []);
  useLayoutEffect(() => {
    const list = conversation.current;
    const latest = list?.lastElementChild;
    if (!list || !latest) return;
    // Move only the conversation viewport, keeping the question and composer in place.
    list.scrollTo({top: latest.getBoundingClientRect().top - list.getBoundingClientRect().top + list.scrollTop, behavior: "instant"});
  }, [latestTurn]);

  async function ask(value: string) {
    if (!value.trim() || pending) return;
    const controller = new AbortController();
    request.current = controller;
    setPending(true); setError("");
    try {
      const result = await api<Answer>(`/scans/${scanId}/findings/${fingerprint}/agent`, {
        method: "POST", signal: controller.signal,
        body: JSON.stringify({ question: value.trim(), use_model: useModel && llm }),
      }, csrf);
      if (controller.signal.aborted) return;
      const id = ++nextTurn.current;
      setTurns(current => [...current.slice(-2), { id, question: value.trim(), result }]);
      setQuestion("");
    } catch (failure) {
      if (!controller.signal.aborted) setError((failure as Error).message);
    } finally {
      if (request.current === controller) { request.current = null; setPending(false); }
    }
  }

  return <section className={styles.agent} aria-label="Security RAG agent">
    <div className={styles.heading}><span><Sparkles size={16}/>Security agent</span><span className={styles.mode}>{useModel && llm ? local ? "Local AI + retrieval" : "AI + retrieval" : "Retrieved guidance"}</span></div>
    <p className={styles.context}>Ask about <strong>{title}</strong>. Answers use the finding and reviewed security guidance.</p>
    {!turns.length && <div className={styles.prompts}>{prompts.map(prompt => <button key={prompt} disabled={pending} onClick={() => void ask(prompt)}>{prompt}<ArrowUpRight size={13}/></button>)}</div>}
    <div ref={conversation} className={styles.conversation} aria-live="polite" aria-relevant="additions">
      {turns.map(turn => <MotionReveal motionKey={String(turn.id)} key={turn.id} className={styles.turn}>
        <p className={styles.question}>{turn.question}</p>
        <div className={styles.answer}>
          <span className={styles.answerLabel}><Check size={12}/>{turn.result.provider === "curated_retrieval" ? "Retrieved guidance" : "AI interpretation · review required"}</span>
          <p>{turn.result.answer}</p>
          {turn.result.conditions_to_verify.length > 0 && <details><summary>Conditions to verify</summary><ul>{turn.result.conditions_to_verify.map((condition, i) => <li key={i}>{condition}</li>)}</ul></details>}
          <div className={styles.sources}><span><BookOpen size={12}/>Sources used</span>{turn.result.citations.length ? turn.result.citations.map(citation => <details key={citation.id}><summary>{citation.id} · {citation.title}</summary><p>{citation.excerpt}</p><a href={citation.url} target="_blank" rel="noreferrer">Read source<ArrowUpRight size={12}/></a></details>) : <p>No relevant source found. The agent cannot ground an answer.</p>}</div>
          <p className={styles.limitations}>{Array.isArray(turn.result.limitations) ? turn.result.limitations.join(" ") : turn.result.limitations}</p>
        </div>
      </MotionReveal>)}
    </div>
    {pending && <div className={styles.pending} role="status"><Loader2 size={15} className="spin"/><span>{useModel ? "Preparing a grounded answer…" : "Retrieving security guidance…"}</span><button aria-label="Cancel agent answer" onClick={() => { request.current?.abort(); setPending(false); }}><X size={14}/></button></div>}
    {error && <p className={styles.error} role="alert">{error}</p>}
    <form className={styles.composer} onSubmit={event => { event.preventDefault(); void ask(question); }}>
      <label htmlFor="agent-question">Question about this finding</label>
      <textarea id="agent-question" value={question} onChange={event => setQuestion(event.target.value)} maxLength={3000} rows={2} placeholder="Which input or control should I verify?" disabled={pending}/>
      <div>{llm ? <label className={styles.modelChoice}><input type="checkbox" checked={useModel} onChange={event => setUseModel(event.target.checked)} disabled={pending}/>{local ? "Use local model" : "Use configured model"}</label> : <span>Model not configured</span>}<SpringButton type="submit" disabled={pending || question.trim().length < 3}><Send size={14}/>Ask</SpringButton></div>
    </form>
    <p className={styles.privacy}>{local ? "Processed on this device. " : "Uses your configured review service. "}Questions stay out of saved reports. Every answer is scoped to this finding; no files are modified.</p>
  </section>;
}
