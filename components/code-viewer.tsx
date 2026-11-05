"use client";
import { useEffect, useRef, useState } from "react";
import type * as Monaco from "monaco-editor";
import type { Finding, Patch } from "@/lib/types";

// Monaco is self-hosted: source code never goes to a CDN. Workers use the same origin.
let loading: Promise<typeof import("monaco-editor/esm/vs/editor/editor.api.js")> | null = null;
function loadMonaco() {
  if (!loading) {
    loading = import("monaco-editor/esm/vs/editor/editor.api.js").then(async monaco => {
      await Promise.all([
        import("monaco-editor/esm/vs/basic-languages/python/python.contribution.js"),
        import("monaco-editor/esm/vs/basic-languages/typescript/typescript.contribution.js"),
        import("monaco-editor/esm/vs/basic-languages/javascript/javascript.contribution.js"),
      ]);
      (self as typeof self & {MonacoEnvironment?: unknown}).MonacoEnvironment = {getWorker: () => new Worker(new URL("monaco-editor/esm/vs/editor/editor.worker.js", import.meta.url), {type: "module"})};
      monaco.editor.defineTheme("guardian-dark", {base: "vs-dark", inherit: true, rules: [{token: "comment", foreground: "84918f"}, {token: "string", foreground: "abc8a4"}, {token: "keyword", foreground: "b5a8db"}, {token: "number", foreground: "ddb886"}], colors: {"editor.background": "#101314", "editor.foreground": "#ccd5d1", "editorLineNumber.foreground": "#7b8781", "editorLineNumber.activeForeground": "#b8c6bf", "editor.selectionBackground": "#29483c", "editor.lineHighlightBackground": "#191e1c", "editorGutter.background": "#101314"}});
      return monaco;
    });
  }
  return loading!;
}

export default function CodeViewer({source, path, finding, theme, patch}: {source: string; path: string; finding?: Finding; theme: string; patch?: Patch}) {
  const el = useRef<HTMLDivElement>(null);
  const [loaded, setLoaded] = useState(false);
  const [failed, setFailed] = useState(false);
  useEffect(() => {
    let dead = false;
    let editor: Monaco.editor.IStandaloneCodeEditor | Monaco.editor.IStandaloneDiffEditor | undefined;
    let models: Monaco.editor.ITextModel[] = [];
    let resize: ResizeObserver | undefined;
    setLoaded(false); setFailed(false);
    loadMonaco().then(monaco => {
      if (dead || !el.current) return;
      const language = path.endsWith(".py") ? "python" : path.endsWith(".ts") || path.endsWith(".tsx") ? "typescript" : path.endsWith(".js") ? "javascript" : "plaintext";
      const opts = {theme: theme === "light" ? "vs" : "guardian-dark", fontFamily: "IBM Plex Mono, monospace", fontSize: 12, lineHeight: 24, minimap: {enabled: false}, scrollBeyondLastLine: false, readOnly: true, domReadOnly: true, renderLineHighlight: "all" as const, padding: {top: 18}, overviewRulerLanes: 0, hideCursorInOverviewRuler: true, automaticLayout: true, contextmenu: false, wordWrap: "on" as const, lineNumbersMinChars: 3, glyphMargin: true, folding: false, ariaLabel: patch ? "Review proposed patch diff" : `Source code for ${path}`};
      if (patch) {
        const original = monaco.editor.createModel(patch.original, language);
        const modified = monaco.editor.createModel(patch.modified, language);
        models = [original, modified];
        const diff = monaco.editor.createDiffEditor(el.current, {...opts, renderSideBySide: el.current.clientWidth > 600, useInlineViewWhenSpaceIsLimited: false, originalEditable: false, enableSplitViewResizing: true});
        diff.setModel({original, modified}); editor = diff;
      } else {
        const model = monaco.editor.createModel(source, language); models = [model];
        const code = monaco.editor.create(el.current, {...opts, model}); editor = code;
        if (finding) {
          code.createDecorationsCollection([{range: new monaco.Range(finding.line, 1, finding.end_line, 1), options: {isWholeLine: true, className: `code-line-${finding.severity}`, glyphMarginClassName: "finding-glyph"}}]);
          monaco.editor.setModelMarkers(model, "codeguardian", [{startLineNumber: finding.line, startColumn: 1, endLineNumber: finding.end_line, endColumn: model.getLineMaxColumn(Math.min(finding.end_line, model.getLineCount())), message: `${finding.rule_id}: ${finding.message}`, severity: finding.severity === "high" ? monaco.MarkerSeverity.Error : monaco.MarkerSeverity.Warning}]);
          code.revealLineInCenter(finding.line);
        }
      }
      resize = new ResizeObserver(() => editor?.layout()); resize.observe(el.current);
      setLoaded(true);
    }).catch(() => {if (!dead) setFailed(true);});
    return () => {dead = true; resize?.disconnect(); editor?.dispose(); models.forEach(model => model.dispose());};
  }, [source, path, finding, theme, patch]);
  return <div className="editor-shell"><div className="monaco-host" ref={el}/>{!loaded && <div className="source-fallback" aria-label={failed ? "Plain text source viewer" : "Loading source editor"}>{source.split("\n").map((line, i) => <div key={i} className={i + 1 === finding?.line ? "highlight" : ""}><span>{i + 1}</span><code>{line || " "}</code></div>)}</div>}</div>;
}
