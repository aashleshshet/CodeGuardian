/** Credential redaction and explicitly partial lexical fallback for syntax failures. */
export type BrowserLanguage = "python" | "javascript" | "typescript";
export type BrowserSeverity = "high" | "medium" | "low";
export type BrowserFinding = {
  id: string; title: string; severity: BrowserSeverity; line: number; endLine: number;
  ruleId: string; cwe: string; message: string; remediation: string; conditions: string[];
  classification: "potential_vulnerability" | "secure_coding_suggestion";
  patch?: {original: string; modified: string; diff: string; caveat: string};
};
export type BrowserAnalysis = {
  findings: BrowserFinding[]; redactedSource: string; language: BrowserLanguage;
  filename: string; linesAnalyzed: number; limitations: string[];
};
export const MAX_CODE_BYTES = 200 * 1024;
const MAX_FINDINGS = 100;

type SecretRange = {start: number; end: number; line: number; endLine: number};
function secretRanges(source: string): SecretRange[] {
  const patterns: [RegExp, number][] = [
    [/-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/gd, 0],
    [/\b(?:gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{30,255})\b/gd, 0],
    [/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/gd, 0],
    [/\bsk[-_](?:live[-_]|test[-_]|proj-)?[A-Za-z0-9_-]{20,255}\b/gd, 0],
    [/\b[\w-]{0,64}(?:password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key)["']?\s*[:=]\s*["']([^"'\r\n]{8,})["']/gid, 1],
    [/(?:https?|postgres(?:ql)?|mysql|redis):\/\/[^\s:/]+:([^@\s]+)@/gid, 1],
    [/\bbearer\s+([A-Za-z0-9._~-]{16,4096})/gid, 1],
    [/\beyJ[A-Za-z0-9_-]{8,4096}\.[A-Za-z0-9_-]{8,4096}\.[A-Za-z0-9_-]{8,4096}\b/gd, 0],
  ];
  const found: SecretRange[] = [];
  const newlines:number[]=[];
  for(let i=0;i<source.length;i++)if(source[i]==="\n")newlines.push(i);
  const lineAt=(position:number)=>{let low=0,high=newlines.length;while(low<high){const mid=(low+high)>>>1;if(newlines[mid]<position)low=mid+1;else high=mid;}return low+1;};
  for (const [pattern, group] of patterns) {
    for (const match of source.matchAll(pattern)) {
      const value = match[group];
      if (value.includes("[REDACTED]") || /^(\$\{|\{\{|<)/.test(value)) continue;
      const [start, end] = match.indices![group];
      const line = lineAt(start);
      found.push({start, end, line, endLine: line + (value.match(/\n/g)?.length || 0)});
    }
  }
  const merged:SecretRange[]=[];
  for(const range of found.sort((a,b)=>a.start-b.start||b.end-a.end)){
    const previous=merged.at(-1);
    if(previous&&range.start<previous.end){previous.end=Math.max(previous.end,range.end);previous.endLine=Math.max(previous.endLine,range.endLine);}
    else merged.push(range);
  }
  return merged;
}

function maskSecrets(source: string, ranges: SecretRange[]): string {
  const pieces:string[]=[];let cursor=0;
  for(const {start,end,line,endLine} of ranges){pieces.push(source.slice(cursor,start),"[REDACTED]","\n".repeat(endLine-line));cursor=end;}
  pieces.push(source.slice(cursor));return pieces.join("");
}

/** Use before displaying or exporting source; novel/encoded secrets can be missed. */
export function redactCode(source: string): string {
  if (new TextEncoder().encode(source).length > MAX_CODE_BYTES) throw new Error("Choose a file smaller than 200 KiB.");
  return maskSecrets(source, secretRanges(source));
}

/** Preserve positions, retaining string delimiters but hiding their contents. */
function lexicalViews(source: string, language: BrowserLanguage): {code: string; withoutComments: string} {
  const code = source.split("");
  const withoutComments = source.split("");
  let state: "code" | "line" | "block" | "string" = "code";
  let quote = "";
  let triple = false;
  const hide = (at: number, comment: boolean) => {
    if (source[at] !== "\n") {code[at] = " "; if (comment) withoutComments[at] = " ";}
  };
  for (let i = 0; i < source.length; i++) {
    const char = source[i], next = source[i + 1];
    if (state === "line") {
      hide(i, true); if (char === "\n") state = "code";
    } else if (state === "block") {
      hide(i, true);
      if (char === "*" && next === "/") {hide(++i, true); state = "code";}
    } else if (state === "string") {
      if (char === "\\") {hide(i, false); if (i + 1 < source.length) hide(++i, false);}
      else if (triple && source.slice(i, i + 3) === quote.repeat(3)) {
        code[i] = quote; hide(i + 1, false); hide(i + 2, false); i += 2; state = "code";
      } else if (!triple && char === quote) {state = "code";}
      else hide(i, false);
    } else if (language === "python" && char === "#") {hide(i, true); state = "line";}
    else if (language !== "python" && char === "/" && next === "/") {hide(i, true); hide(++i, true); state = "line";}
    else if (language !== "python" && char === "/" && next === "*") {hide(i, true); hide(++i, true); state = "block";}
    else if (char === "'" || char === '"' || (language !== "python" && char === "`")) {
      quote = char; triple = language === "python" && source.slice(i, i + 3) === char.repeat(3);
      if (triple) {hide(i + 1, false); hide(i + 2, false); i += 2;}
      state = "string";
    }
  }
  return {code: code.join(""), withoutComments: withoutComments.join("")};
}

function filenameFor(name: string, language: BrowserLanguage): string {
  const basename = name.replace(/\\/g, "/").split("/").at(-1) || "";
  const safe = redactCode(basename.slice(0, 200)).replace(/[^A-Za-z0-9_.-]/g, "_").slice(0, 96);
  return safe || `untitled.${language === "python" ? "py" : language === "typescript" ? "ts" : "js"}`;
}

const LIMITATIONS = [
  "These are browser-based pattern checks, not Semgrep, Bandit, Gitleaks, a dependency audit, or an AI model.",
  "A match needs human review. No matches do not establish that code is secure.",
  "No parsing, data-flow analysis, cross-file context or code execution is performed. Multiline constructs, aliases and encoded secrets may be missed.",
];

export function analyzeCode(source: string, language: BrowserLanguage, filename: string): BrowserAnalysis {
  if (!["python", "javascript", "typescript"].includes(language)) throw new Error("Choose Python, JavaScript or TypeScript.");
  if (new TextEncoder().encode(source).length > MAX_CODE_BYTES) throw new Error("Choose a file smaller than 200 KiB.");
  if (!source.trim()) throw new Error("Paste code or choose a source file first.");
  const ranges = secretRanges(source);
  const redactedSource = maskSecrets(source, ranges);
  const safeFilename = filenameFor(filename, language);
  const {code, withoutComments} = lexicalViews(source, language);
  const lines = source.split("\n"), active = code.split("\n"), commentsRemoved = withoutComments.split("\n");
  const findings: BrowserFinding[] = [];
  let capped = false;
  const add = (line: number, ruleId: string, title: string, severity: BrowserSeverity, cwe: string, message: string, remediation: string, conditions: string[], extra: Partial<BrowserFinding> = {}) => {
    if (findings.length >= MAX_FINDINGS) {capped = true; return;}
    if (findings.some(f => f.line === line && f.ruleId === ruleId)) return;
    findings.push({id: `${ruleId}-${line}`, line, endLine: line, ruleId, title, severity, cwe, message, remediation, conditions, classification: "potential_vulnerability", ...extra});
  };
  for (const range of ranges) add(range.line, "hardcoded-credential", "Potential hardcoded secret", "high", "CWE-798", "A credential-shaped value was detected and redacted. Its validity has not been checked.", "Verify the credential locally. If active, revoke and rotate it, remove it from source and history, and load it from a secret store.", ["Determine whether the value is an active credential or a synthetic test value without sharing it."], {endLine: range.endLine});

  for (let index = 0; index < lines.length; index++) {
    const line = index + 1, text = commentsRemoved[index], visible = active[index];
    if (!visible.trim()) continue;
    const matchCode = (pattern: RegExp) => {
      for (const match of text.matchAll(new RegExp(pattern.source, pattern.flags + "g"))) {
        if (visible[match.index] === text[match.index]) return match;
      }
      return null;
    };
    const literal = (value: string) => /^\s*["'`]/.test(value) && !value.includes("${") && !/["'`]\s*\+/.test(value);
    if (matchCode(/\beval\s*\(/)) add(line, "dynamic-eval", "Dynamic code evaluation", "high", "CWE-95", "An eval call can interpret its argument as executable code.", "Remove dynamic evaluation. For a JSON-only input contract, parse JSON and validate its schema; preserve error handling.", ["Trace whether untrusted input can reach eval and whether execution is required."]);
    if (/\b(?:SELECT|INSERT|UPDATE|DELETE)\b/i.test(text)) {
      const interpolation = language === "python" ? matchCode(/\bf["']/) : matchCode(/`/);
      const dynamic = language === "python" ? !!interpolation || /\.format\s*\(|["']\s*[%+]\s*\w/.test(text) : !!interpolation && /\$\{/.test(text) || /["']\s*\+\s*\w/.test(text);
      if (dynamic && /(?:=|\b(?:query|execute)\s*\()/.test(visible)) add(line, "sql-interpolation", "SQL string interpolation", "high", "CWE-89", "SQL text appears to be combined with a dynamic value. This check does not establish whether the query is executed.", "Use the database driver's bound parameter API. Keep query syntax separate from values, and allowlist dynamic table or column identifiers.", ["Confirm whether this string reaches a database call.", "Trace input provenance and use the placeholder syntax required by the actual driver."]);
    }
    if (language === "python") {
      if (matchCode(/\bsubprocess\.(?:run|call|Popen|check_call|check_output)\s*\(/) && /\bshell\s*=\s*True\b/.test(visible)) add(line, "python-shell", "Shell interpretation enabled", "high", "CWE-78", "A subprocess call enables shell interpretation.", "Pass a fixed executable and an argument list with shell=False. Validate arguments and reject option injection where relevant.", ["Confirm whether any command component can be influenced by untrusted input."]);
      const system = matchCode(/\bos\.system\s*\(\s*/);
      if (system && !literal(text.slice(system.index + system[0].length))) add(line, "python-os-system", "Dynamic shell command", "high", "CWE-78", "A dynamic value is passed to a shell command API.", "Use a library or subprocess with a fixed executable, an argument list and shell=False.", ["Check the origin of the command and each argument."]);
      if (matchCode(/\byaml\.load\s*\(/) && !/\b(?:yaml\.)?(?:SafeLoader|CSafeLoader)\b/.test(visible)) add(line, "python-unsafe-yaml", "Unsafe YAML loading", "medium", "CWE-502", "yaml.load is used without a recognized safe loader on this line.", "Use yaml.safe_load for data-only YAML and validate the result against an expected schema.", ["Inspect surrounding lines for an explicit safe loader.", "Verify whether custom YAML objects are required."]);
      if (matchCode(/\bpickle\.loads?\s*\(/)) add(line, "python-pickle", "Executable deserialization", "high", "CWE-502", "Pickle deserialization can invoke code encoded in a payload.", "Use a data-only format such as JSON for untrusted inputs. Do not deserialize untrusted pickle payloads.", ["Verify that the serialized data cannot be created or modified by an untrusted actor."]);
      if (/\bverify\s*=\s*False\b/.test(visible)) add(line, "python-tls-verification", "Certificate verification disabled", "medium", "CWE-295", "A verify=False argument may disable certificate verification in an HTTP client.", "Enable certificate and hostname verification and configure the intended trusted CA bundle.", ["Confirm which API receives verify=False; unrelated APIs may use this name."]);
      if (matchCode(/\bhashlib\.(?:md5|sha1)\s*\(/)) add(line, "python-weak-hash", "Legacy hash algorithm", "low", "CWE-327", "MD5 or SHA-1 appears in a hashing call; its security role is unknown.", "Use a current vetted algorithm for security-sensitive hashing. Use a dedicated password hashing function for passwords.", ["Distinguish a non-security checksum from a signature, password or integrity boundary."], {classification: "secure_coding_suggestion"});
    } else {
      const html = matchCode(/\.innerHTML\s*=\s*(?!=)/);
      if (html && !literal(text.slice(html.index + html[0].length))) {
        const patch = !ranges.length && !redactedSource.includes("[REDACTED]") ? (() => {
          const original = lines[index], modified = original.slice(0, html.index) + original.slice(html.index).replace(".innerHTML", ".textContent");
          return {original, modified, diff: `--- a/${safeFilename}\n+++ b/${safeFilename}\n@@ -${line},1 +${line},1 @@\n-${original}\n+${modified}\n`, caveat: "Renders plain text instead of HTML. Review markup-dependent behavior and test before applying."};
        })() : undefined;
        add(line, "javascript-innerhtml", "Untrusted HTML insertion", "high", "CWE-79", "A dynamic value is assigned to innerHTML, which interprets HTML markup.", "Prefer textContent for plain text. If HTML is required, use a maintained sanitizer appropriate to the rendering context.", ["Trace whether the assigned value can contain attacker-controlled markup.", "Check whether existing sanitization covers this exact context."], {patch});
      }
      const write = matchCode(/\bdocument\.write\s*\(\s*/);
      if (write && !literal(text.slice(write.index + write[0].length))) add(line, "javascript-document-write", "Dynamic document markup", "high", "CWE-79", "document.write receives a dynamic value that may be interpreted as HTML.", "Build DOM nodes with textContent for plain text; avoid document.write.", ["Confirm whether untrusted input reaches this call."]);
      const exec = matchCode(/(?<![\w.])(?:(?:child_process|childProcess)\.)?exec(?:Sync)?\s*\(\s*/);
      if (exec && !literal(text.slice(exec.index + exec[0].length))) add(line, "javascript-shell", "Potential dynamic shell command", "high", "CWE-78", "An exec-style call receives a dynamic argument; this may invoke a shell.", "For Node child_process calls, prefer execFile or spawn with a fixed executable and separate arguments, without a shell.", ["Confirm that this is Node child_process rather than an unrelated function or RegExp.exec.", "Trace every argument's source and validate the allowed command."]);
      if (/\brejectUnauthorized\s*:\s*false\b/.test(visible)) add(line, "javascript-tls-verification", "Certificate verification disabled", "medium", "CWE-295", "A TLS option disables certificate validation.", "Keep rejectUnauthorized enabled and configure the intended certificate authority.", ["Confirm whether this option reaches a TLS client."]);
      if (matchCode(/\b(?:crypto\.)?createHash\s*\(\s*["'](?:md5|sha1)["']/i)) add(line, "javascript-weak-hash", "Legacy hash algorithm", "low", "CWE-327", "MD5 or SHA-1 appears in a hashing call; its security role is unknown.", "Use a current vetted algorithm for security-sensitive hashing and a dedicated password hasher for passwords.", ["Confirm whether this is security-sensitive rather than a non-security checksum."], {classification: "secure_coding_suggestion"});
    }
  }
  const order: Record<BrowserSeverity, number> = {high: 0, medium: 1, low: 2};
  findings.sort((a, b) => order[a.severity] - order[b.severity] || a.line - b.line);
  return {findings, redactedSource, language, filename: safeFilename, linesAnalyzed: lines.length, limitations: [...LIMITATIONS, ...(capped ? ["Only the first 100 pattern matches are shown. Review smaller portions for additional matches."] : [])]};
}
