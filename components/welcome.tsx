"use client";
import { ArrowRight, BookOpen, Check, Code2, Fingerprint, GitBranch, Github, LockKeyhole, Moon, ShieldCheck, Sun } from "lucide-react";
import { Mark } from "./ui";

export default function Welcome({configured, loading, available, error, theme, onTheme, onRetry}: {
  configured: boolean; loading: boolean; available: boolean; error: string;
  theme: string; onTheme: () => void; onRetry: () => void;
}) {
  return <div className="welcome-page">
    <div className="welcome-atmosphere" aria-hidden="true"/>
    <header className="welcome-header"><a className="welcome-brand" href="/"><Mark/><span>CodeGuardian<span className="brand-ai">AI</span></span></a><div className="welcome-header-actions"><a href="https://github.com/aashleshshet/CodeGuardian#readme" target="_blank" rel="noreferrer">Documentation <ArrowRight size={14}/></a><button className="icon-button" aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} theme`} onClick={onTheme}>{theme === "dark" ? <Sun size={18}/> : <Moon size={18}/>}</button></div></header>
    <main className="welcome-main" id="main">
      <section className="welcome-story">
        <h1>See the risk.<br/><span>Own the fix.</span></h1>
        <p className="welcome-description">Your code deserves a closer look. Bring security evidence, source context, and a clear path to remediation into one workspace.</p>
        <div className="welcome-flow" aria-label="Security review workflow">
          <div className="flow-track" aria-hidden="true"/>
          <div className="flow-step"><span><GitBranch size={21}/></span><strong>Your repository</strong><small>Only the access you allow</small></div>
          <div className="flow-step"><span><Fingerprint size={21}/></span><strong>Real analysis</strong><small>Traceable scanner evidence</small></div>
          <div className="flow-step"><span><Code2 size={21}/></span><strong>Your decision</strong><small>Review every proposed change</small></div>
        </div>
        <div className="welcome-principles"><span><Check size={15}/>Private by design</span><span><Check size={15}/>No automatic code changes</span><span><Check size={15}/>Human review, always</span></div>
      </section>
      <section className="signin-panel" aria-label="Sign in">
        <div className="signin-emblem"><Mark/></div><h2>Your next review <br/>starts here.</h2><p>Sign in to create your security workspace. You choose which repositories to connect.</p>
        {loading ? <div className="signin-loading" role="status">Checking your session…</div> : available ? <a className="button primary signin-button" href="/api/backend/auth/github/start"><Github size={18}/>Continue with GitHub<ArrowRight size={17}/></a> : <div className="service-notice" role="status"><ShieldCheck size={19}/><div><strong>{configured ? "Sign-in is not available yet" : "Workspace setup is in progress"}</strong><p>{error || (configured ? "The service administrator needs to finish GitHub App configuration before you can sign in." : "The review service is not connected to this deployment yet. Your workspace will be available once setup is complete.")}</p>{configured && <button className="text-button" onClick={onRetry}>Check again <ArrowRight size={13}/></button>}</div></div>}
        <div className="signin-divider"/><div className="signin-note"><LockKeyhole size={17}/><p>GitHub authentication is handled securely. CodeGuardian never asks you to paste an access token.</p></div>
        <a className="setup-guide" href="https://github.com/aashleshshet/CodeGuardian/blob/main/docs/deployment.md" target="_blank" rel="noreferrer"><BookOpen size={15}/>Deployment &amp; setup guide<ArrowRight size={14}/></a>
      </section>
    </main>
    <footer className="welcome-footer"><span>CodeGuardian AI <span className="footer-dot">·</span> Evidence before inference.</span><a href="https://github.com/aashleshshet/CodeGuardian/blob/main/SECURITY.md" target="_blank" rel="noreferrer"><LockKeyhole size={12}/>Security architecture<ArrowRight size={12}/></a></footer>
  </div>;
}
