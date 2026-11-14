/** Offline syntax and bounded single-file data-flow analysis. Source is never executed. */
import {analyzeCode as analyzePatterns} from "./lexical-analysis.ts";
import {analyzeJavaScript} from "./javascript-analysis.ts";
import {analyzePython} from "./python-analysis.ts";
import {owaspCategory} from "./owasp.ts";
import type {FlowStep, StructuralResult} from "./analysis-types.ts";
import type {BrowserFinding as PatternFinding, BrowserLanguage, BrowserSeverity} from "./lexical-analysis.ts";
export {redactCode, MAX_CODE_BYTES} from "./lexical-analysis.ts";
export type {BrowserLanguage, BrowserSeverity};

export type BrowserFinding = PatternFinding & {
  evidence: "data_flow" | "structural" | "pattern";
  owasp: string;
  trace?: FlowStep[];
};
export type BrowserAnalysis = {
  findings: BrowserFinding[];
  redactedSource: string;
  language: BrowserLanguage;
  filename: string;
  linesAnalyzed: number;
  limitations: string[];
  coverage: {syntax: "parsed" | "partial"; scope: "single_file"; diagnostics: {line:number; message:string}[]};
  engineVersion: string;
};

const LIMITATIONS = [
  "Local syntax and bounded single-file data-flow checks; not Semgrep, Bandit, Gitleaks, a dependency audit, or an AI model.",
  "Findings require human review. A traced flow is static evidence, not proof of runtime exploitability. No matches do not establish that code is secure.",
  "Cross-file dependencies, runtime behavior, authentication/authorization logic, business rules and all possible paths are not analyzed. Reflection, complex object aliases and unsupported framework APIs can be missed.",
  "Data-flow analysis approximates branches and calls. Sanitizers and allowlists must be reviewed in the actual application context. Unknown, encoded and split credentials may be missed.",
];

export function analyzeCode(source:string, language:BrowserLanguage, filename:string): BrowserAnalysis {
  // This validates input and applies the existing secret detector even when parsing fails.
  const fallback=analyzePatterns(source, language, filename);
  let analysis: StructuralResult;
  try {analysis=language === "python" ? analyzePython(source) : analyzeJavaScript(source,language,filename);}
  catch {analysis={findings:[],parsed:false,truncated:true,diagnostics:[{line:1,message:"The structural analyzer could not complete. Review a smaller, complete source file."}]};}
  const findings: BrowserFinding[]=[];
  const add=(finding:BrowserFinding)=>{
    const existing=findings.findIndex(f=>f.line===finding.line && (f.ruleId===finding.ruleId || (f.cwe===finding.cwe && f.ruleId!=="hardcoded-credential")));
    if(existing<0)findings.push(finding);
    else if(finding.evidence==="data_flow" && findings[existing].evidence!=="data_flow")findings[existing]=finding;
  };
  const secrets=fallback.findings.filter(f=>f.ruleId==="hardcoded-credential");
  for(const f of secrets)add({...f,evidence:"pattern",owasp:owaspCategory(f.cwe)});
  for(const f of analysis.findings){
    const {patchProperty,...finding}=f;
    let patch:PatternFinding["patch"];
    if(patchProperty && !secrets.length && !fallback.redactedSource.includes("[REDACTED]")){
      const {start,end}=patchProperty;
      const lineStart=source.lastIndexOf("\n",start-1)+1;
      const newline=source.indexOf("\n",end);
      const lineEnd=newline<0?source.length:newline;
      if(source.slice(start,end)==="innerHTML" && !source.slice(lineStart,lineEnd).includes("\n")){
        const original=source.slice(lineStart,lineEnd);
        const modified=source.slice(lineStart,start)+"textContent"+source.slice(end,lineEnd);
        const patchLine=source.slice(0,start).split("\n").length;
        patch={original,modified,diff:`--- a/${fallback.filename}\n+++ b/${fallback.filename}\n@@ -${patchLine},1 +${patchLine},1 @@\n-${original}\n+${modified}\n`,caveat:"Renders plain text instead of HTML. Review markup-dependent behavior and test before applying."};
      }
    }
    add({...finding,id:`${f.ruleId}-${f.line}`,owasp:owaspCategory(f.cwe),patch});
  }
  // Retain best-effort checks on invalid syntax, visibly marked as partial coverage.
  if(!analysis.parsed)for(const f of fallback.findings)add({...f,evidence:"pattern",owasp:owaspCategory(f.cwe)});
  const order:Record<BrowserSeverity,number>={high:0,medium:1,low:2};
  findings.sort((a,b)=>order[a.severity]-order[b.severity]||a.line-b.line);
  const capped=findings.length>100 || analysis.truncated || fallback.limitations.some(x=>x.includes("first 100"));
  const diagnostics=analysis.diagnostics.slice(0,5).map(d=>({line:Math.max(1,d.line),message:d.message}));
  return {findings:findings.slice(0,100),redactedSource:fallback.redactedSource,filename:fallback.filename,language,linesAnalyzed:fallback.linesAnalyzed,
    limitations:[...LIMITATIONS,...(!analysis.parsed?["Syntax could not be fully parsed. Results include best-effort patterns; correct the syntax or submit a complete file and check again."]:[]),...(capped?["Analysis budget reached; at most 100 findings are shown. Review smaller portions for additional matches."]:[])],
    coverage:{syntax:analysis.parsed&&!analysis.truncated?"parsed":"partial",scope:"single_file",diagnostics},engineVersion:"2026.11.14-flow.2"};
}
