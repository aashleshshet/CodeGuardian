import {parse} from "@babel/parser";
import type {FlowStep, StructuralFinding, StructuralResult} from "./analysis-types.ts";

// This is a bounded abstract interpreter, never an evaluator of submitted JavaScript.
// Branches are joined conservatively. Import names identify modeled APIs; no module is loaded.
type Ast = {type: string; start?: number | null; end?: number | null; loc?: {start: {line: number}; end: {line: number}}; [key: string]: any};
type Value = {
  dynamic: boolean; trace: FlowStep[]; htmlSafe?: boolean; constant?: string | number | boolean | null;
  api?: string; props?: Map<string, Value>; fn?: Ast; closure?: Scope; sql?: boolean;
};
class Scope {
  values = new Map<string, Value>();
  parent?: Scope;
  constructor(parent?: Scope) {this.parent = parent;}
  get(name: string): Value | undefined {return this.values.has(name) ? this.values.get(name) : this.parent?.get(name);}
  has(name: string): boolean {return this.values.has(name) || !!this.parent?.has(name);}
  set(name: string, value: Value) {if (this.values.has(name) || !this.parent?.has(name)) this.values.set(name, value); else this.parent.set(name, value);}
  flatten(): Scope {const copy = this.parent?.flatten() || new Scope(); for (const [key, value] of this.values) copy.values.set(key, value); return copy;}
}
const unknown = (): Value => ({dynamic: true, trace: []});
const fixed = (constant?: Value["constant"]): Value => ({dynamic: false, trace: [], constant});
const line = (node: Ast): number => node.loc?.start.line || 1;
function traceUnion(values: Value[]): FlowStep[] {
  const seen = new Set<string>(); const trace: FlowStep[] = [];
  for (const value of values) for (const step of value.trace) {
    const key = `${step.kind}:${step.line}:${step.label}`;
    if (!seen.has(key)) {seen.add(key); trace.push(step);}
  }
  // Keep the original source and the most recent intermediate steps.
  return trace.length > 7 ? [trace[0], ...trace.slice(-6)] : trace;
}
function join(...values: Value[]): Value {
  if (!values.length) return fixed();
  const first = values[0];
  return {dynamic: values.some(v => v.dynamic), trace: traceUnion(values),
    htmlSafe: values.every(v => !v.dynamic || v.htmlSafe),
    constant: values.every(v => v.constant === first.constant) ? first.constant : undefined,
    api: values.every(v => v.api === first.api) ? first.api : undefined,
    fn: values.every(v => v.fn === first.fn) ? first.fn : undefined,
    closure: values.every(v => v.closure === first.closure) ? first.closure : undefined,
    sql: values.some(v => v.sql),
    props: values.length === 1 ? first.props : undefined};
}
function step(value: Value, node: Ast, kind: FlowStep["kind"], label: string): Value {
  if (!value.trace.length) return value;
  return {...value, trace: traceUnion([value, {dynamic: true, trace: [{line: line(node), kind, label}]}])};
}
const isSql = (text: unknown) => typeof text === "string" && /\b(?:SELECT\s|INSERT\s+INTO|UPDATE\s|DELETE\s+FROM|WHERE\s)/i.test(text);
const keyOf = (node?: Ast): string | undefined => node?.type === "Identifier" ? node.name : ["StringLiteral", "NumericLiteral"].includes(node?.type || "") ? String(node!.value) : undefined;
const members = new Set(["MemberExpression", "OptionalMemberExpression"]);

export function analyzeJavaScript(source: string, language: "javascript" | "typescript", filename: string): StructuralResult {
  let tree: Ast;
  try {
    const parseSource = (jsx: boolean) => parse(source, {sourceType: "unambiguous", allowReturnOutsideFunction: true, allowAwaitOutsideFunction: true,
      errorRecovery: false, attachComment: false, plugins: language === "typescript" ? ["typescript", ...(jsx ? ["jsx" as const] : [])] : ["jsx"]}) as unknown as Ast;
    try {tree = parseSource(filename.endsWith(".tsx"));}
    catch (error) {
      // Pasted TypeScript has no reliable extension. Retry JSX without weakening syntax errors.
      if (language !== "typescript" || filename.endsWith(".tsx")) throw error;
      tree = parseSource(true);
    }
  } catch (error) {
    const errorLine = (error as {loc?: {line?: number}})?.loc?.line;
    return {findings: [], parsed: false, diagnostics: [{line: typeof errorLine === "number" ? errorLine : 1,
      message: "Syntax could not be parsed. Correct the syntax or select the matching language, then check again."}], truncated: false};
  }
  const findings: StructuralFinding[] = [];
  const pending: {node: Ast; closure: Scope}[] = [];
  const queued = new Set<Ast>();
  const called = new Set<Ast>();
  const exported = new Set<Ast>();
  const exportedNames = new Set<string>();
  let visits = 0, calls = 0, truncated = false;
  const budget = (depth: number) => {if (++visits > 60_000 || depth > 100) {truncated = true; return false;} return true;};
  const external = (node: Ast, label: string): Value => ({dynamic: true, trace: [{line: line(node), kind: "source", label}]});
  const queue = (node: Ast, closure: Scope) => {if (!queued.has(node)) {queued.add(node); pending.push({node, closure});}};
  const add = (node: Ast, value: Value, ruleId: string, title: string, cwe: string, message: string, remediation: string,
    conditions: string[], options: Partial<StructuralFinding> = {}) => {
    const dataFlow = value.trace.some(t => t.kind === "source");
    const finding: StructuralFinding = {ruleId, title, cwe, line: line(node), endLine: node.loc?.end.line || line(node), severity: "high",
      message, remediation, conditions, classification: "potential_vulnerability", evidence: dataFlow ? "data_flow" : "structural",
      ...(dataFlow ? {trace: [...value.trace, {line: line(node), kind: "sink" as const, label: "Value reaches the security-sensitive operation"}]} : {}), ...options};
    const existing = findings.findIndex(f => f.ruleId === ruleId && f.line === finding.line);
    if (existing >= 0) {if (findings[existing].evidence !== "data_flow" && dataFlow) findings[existing] = finding; return;}
    if (findings.length >= 100) {truncated = true; return;}
    findings.push(finding);
  };
  const htmlSink = (node: Ast, value: Value, ruleId = "javascript-innerhtml", property?: Ast) => {
    if (!value.dynamic || value.htmlSafe) return;
    add(node, value, ruleId, "Potential HTML injection", "CWE-79",
      value.trace.length ? "Input from a modeled external source reaches an HTML interpretation operation." : "A dynamic value reaches an HTML interpretation operation; its trust and sanitization are unknown.",
      "Use textContent for plain text. If HTML is required, sanitize it with a maintained sanitizer for this exact rendering context.",
      ["Verify the input origin, any validation outside this file and the actual DOM context.", "Sanitization for SQL, URLs or shell commands does not make HTML safe."],
      property?.start != null && property?.end != null ? {patchProperty: {start: property.start, end: property.end}} : {});
  };
  const readMember = (base: Value, key: string | undefined, node: Ast): Value => {
    if (key && base.props?.has(key)) return base.props.get(key)!;
    if (base.api === "request" && key && ["query", "body", "params", "cookies", "headers", "url"].includes(key)) {
      return {...external(node, "Request-controlled input enters the program"), api: `request.${key}`};
    }
    if ((base.api === "browser.location" && ["search", "hash", "href", "pathname"].includes(key || "")) ||
      (base.api === "dom.element" && ["value", "textContent"].includes(key || "")) ||
      (base.api === "document" && key === "cookie")) return external(node, "Browser-controlled input enters the program");
    if (base.api === "window" && key === "location") return {dynamic: true, trace: [], api: "browser.location"};
    if (base.api === "context" && key === "request") return {dynamic: true, trace: [], api: "request"};
    if (base.api === "event" && key === "target") return {dynamic: true, trace: [], api: "dom.element"};
    return {...base, constant: undefined, fn: undefined, closure: undefined, props: undefined, api: base.api && key ? `${base.api}.${key}` : undefined};
  };
  const bind = (pattern: Ast | undefined, value: Value, env: Scope, declare: boolean, depth: number): void => {
    if (!pattern || !budget(depth)) return;
    if (pattern.type === "Identifier") {const next = step(value, pattern, "assignment", "Value is assigned to a local binding"); if (declare) env.values.set(pattern.name, next); else env.set(pattern.name, next);}
    else if (pattern.type === "AssignmentPattern") bind(pattern.left, join(value, evaluate(pattern.right, env, depth + 1)), env, declare, depth + 1);
    else if (pattern.type === "ObjectPattern") for (const property of pattern.properties || []) {
      if (property.type === "RestElement") bind(property.argument, value, env, declare, depth + 1);
      else bind(property.value, readMember(value, keyOf(property.key), property), env, declare, depth + 1);
    }
    else if (pattern.type === "ArrayPattern") (pattern.elements || []).forEach((element: Ast, i: number) => bind(element, readMember(value, String(i), pattern), env, declare, depth + 1));
    else if (pattern.type === "RestElement") bind(pattern.argument, value, env, declare, depth + 1);
  };
  const param = (node: Ast): Value => {
    const name = node.type === "Identifier" ? node.name : "";
    if (["req", "request"].includes(name)) return {dynamic: true, trace: [], api: "request"};
    if (["ctx", "context"].includes(name)) return {dynamic: true, trace: [], api: "context"};
    if (["event", "e"].includes(name)) return {dynamic: true, trace: [], api: "event"};
    return unknown();
  };
  const runFunction = (node: Ast, closure: Scope, args: Value[] | undefined, depth: number, callDepth: number): Value => {
    if (callDepth > 4 || ++calls > 180 || !budget(depth)) {truncated = true; return join(...(args || []), unknown());}
    if (args) called.add(node);
    const env = new Scope(closure.flatten());
    (node.params || []).forEach((p: Ast, i: number) => bind(p, args?.[i] || param(p), env, true, depth + 1));
    const previous = currentCallDepth; currentCallDepth = callDepth;
    let result: Value;
    if (node.body?.type === "BlockStatement") result = statements(node.body.body, env, depth + 1);
    else result = evaluate(node.body, env, depth + 1);
    currentCallDepth = previous;
    return result;
  };
  let currentCallDepth = 0;
  const mergeScopes = (env: Scope, branches: Scope[]) => {
    const names = new Set(branches.flatMap(b => [...b.values.keys()]));
    for (const name of names) if (env.has(name)) env.set(name, join(...branches.map(b => b.get(name) || env.get(name) || unknown())));
  };
  const checkCall = (node: Ast, callee: Value, args: Value[], env: Scope, depth: number): Value => {
    const api = callee.api || "";
    const input = args[0] || fixed();
    const property = members.has(node.callee?.type) ? keyOf(node.callee.property) : undefined;
    if ((api === "eval" || api === "Function") && args.some(value => value.dynamic)) add(node, join(...args), "dynamic-eval", "Dynamic code evaluation", "CWE-95",
      "A dynamic value reaches an API that interprets JavaScript code.", "Remove dynamic evaluation. Use data-only parsing and validate the expected schema.", ["Verify whether an attacker can influence the code string."]);
    if (/^(?:node:)?child_process\.(?:exec|execSync)$/.test(api) && input.dynamic) add(node, input, "javascript-shell", "Potential shell command injection", "CWE-78",
      "A dynamic value reaches Node.js shell execution.", "Use execFile or spawn with a fixed executable and separate validated arguments, without a shell.", ["Check each argument's origin and reject option injection."]);
    if (/^(?:node:)?child_process\.(?:spawn|spawnSync|execFile|execFileSync)$/.test(api) && (args[2] || args[1])?.props?.get("shell")?.constant === true && join(...args.slice(0, 2)).dynamic) add(node, join(...args.slice(0, 2)), "javascript-shell", "Shell execution enabled for dynamic input", "CWE-78",
      "Dynamic input reaches a process API with shell interpretation enabled.", "Disable shell interpretation and use a fixed executable with separate validated arguments.", ["Validate arguments as well as the executable name."]);
    if (api === "document.write" || api === "document.writeln") htmlSink(node, join(...args), "javascript-document-write");
    if (property === "insertAdjacentHTML") htmlSink(node, args[1] || fixed(), "javascript-html-insertion");
    if ((property === "query" || property === "execute" || property === "raw" || /\.(?:query|execute|raw)$/.test(api)) && input.dynamic && (input.sql || input.trace.length)) add(node, input, "sql-interpolation", "Potential SQL injection", "CWE-89",
      "A dynamically constructed value reaches a database query operation. Parameter arguments do not protect SQL text that was already interpolated.", "Keep SQL syntax constant and pass values through the driver's bound parameter API. Allowlist identifiers that cannot be bound.", ["Confirm this method is a database API and inspect the driver's parameter convention.", "Verify any validation or query builder behavior outside this file."]);
    if ((api === "fetch" || /^axios(?:\.(?:get|post|put|delete|patch|request|head))?$/.test(api) || /^(?:https?|node:https?)\.(?:get|request)$/.test(api)) && input.trace.length) add(node, input, "javascript-ssrf", "Potential server-side request forgery", "CWE-918",
      "Externally influenced input reaches an outbound request destination.", "Allowlist destinations and protocols, block private/reserved addresses after DNS resolution, and validate every redirect. Prefer a fixed service endpoint.", ["Confirm this executes on a server; browser requests have a different threat boundary.", "Review DNS rebinding, redirects and any network policy outside this file."]);
    if (/^(?:node:)?fs(?:\.promises)?\.(?:readFile|readFileSync|writeFile|writeFileSync|createReadStream|createWriteStream|unlink|unlinkSync|open|openSync|rm|rmSync)$/.test(api) && input.trace.length) add(node, input, "javascript-path-traversal", "Potential path traversal", "CWE-22",
      "Externally influenced input reaches a filesystem path operation. Joining or normalizing a path does not establish containment.", "Resolve against a fixed directory and enforce containment after canonicalization. Use allowlisted identifiers and account for symlinks.", ["Verify filesystem permissions, symlink behavior and validation outside this file."]);
    if (property === "redirect" && join(...args).trace.length) add(node, join(...args), "javascript-open-redirect", "Potential open redirect", "CWE-601",
      "Externally influenced input reaches a redirect operation.", "Allowlist redirect destinations or use fixed application route identifiers; reject external origins and protocol-relative URLs.", ["Confirm the redirect API and any destination validation performed elsewhere."]);
    if (/^(?:node:)?crypto\.createHash$/.test(api) && ["md5", "sha1"].includes(String(input.constant).toLowerCase())) add(node, fixed(), "javascript-weak-hash", "Legacy hash algorithm", "CWE-327",
      "MD5 or SHA-1 is selected for hashing; its security role is unknown.", "Use a current vetted algorithm for security-sensitive hashing and a dedicated password hasher for passwords.", ["Distinguish non-security checksums from password, signature or integrity boundaries."], {severity: "low", classification: "secure_coding_suggestion"});
    if (/^jsonwebtoken\.verify$/.test(api) && args.some(v => v.props?.get("algorithms")?.props && [...v.props.get("algorithms")!.props!.values()].some(a => a.constant === "none"))) add(node, input, "javascript-jwt-none", "Unsigned JWT algorithm accepted", "CWE-347",
      "JWT verification explicitly permits the unsigned 'none' algorithm.", "Allowlist the intended signing algorithm and validate the signature, issuer, audience and expiry.", ["Confirm the deployed library's behavior and key configuration."]);
    if (/^(?:dompurify|isomorphic-dompurify)(?:\.default)?\.sanitize$/.test(api)) return {...input, htmlSafe: true};
    if (api === "require" && typeof input.constant === "string") return {dynamic: false, trace: [], api: input.constant.replace(/^node:/, "")};
    if (api === "URLSearchParams") return {...input, api: "url.searchparams"};
    if (api === "url.searchparams.get" || api === "url.searchparams.getAll") return callee.dynamic ? external(node, "URL query input enters the program") : fixed();
    if (/^document\.(?:getElementById|querySelector)$/.test(api)) return {dynamic: true, trace: [], api: "dom.element"};
    if (/^request\.(?:json|text|formData)$/.test(api)) return external(node, "Request payload enters the program");
    if (callee.fn) return step(runFunction(callee.fn, callee.closure || env, args.map(value => step(value, node, "call", "Value is passed to a same-file helper")), depth + 1, currentCallDepth + 1), node, "call", "Value returns from a same-file helper");
    // Preserve provenance through unknown transforms; never assume they sanitize.
    return step(join(...args, ...(callee.trace.length ? [callee] : []), unknown()), node, "call", "Value passes through a function call");
  };
  const evaluate = (node: Ast | undefined | null, env: Scope, depth: number): Value => {
    if (!node || !budget(depth)) return unknown();
    switch (node.type) {
      case "StringLiteral": return {...fixed(node.value), sql: isSql(node.value)};
      case "NumericLiteral": case "BooleanLiteral": return fixed(node.value);
      case "NullLiteral": return fixed(null);
      case "RegExpLiteral": return fixed();
      case "Identifier": {
        const bound = env.get(node.name); if (bound) return bound;
        const globals: Record<string, string> = {eval: "eval", Function: "Function", fetch: "fetch", require: "require", URLSearchParams: "URLSearchParams", location: "browser.location", document: "document", window: "window", req: "request", request: "request", ctx: "context", context: "context", crypto: "crypto", child_process: "child_process", childProcess: "child_process", axios: "axios", fs: "fs", process: "process"};
        return {...unknown(), api: globals[node.name]};
      }
      case "TSAsExpression": case "TSTypeAssertion": case "TSNonNullExpression": case "TypeCastExpression": case "ParenthesizedExpression": case "AwaitExpression": return evaluate(node.expression || node.argument, env, depth + 1);
      case "MemberExpression": case "OptionalMemberExpression": return readMember(evaluate(node.object, env, depth + 1), node.computed && node.property.type === "Identifier" ? undefined : keyOf(node.property), node);
      case "TemplateLiteral": return join(...node.quasis.map((q: Ast) => ({...fixed(q.value.cooked ?? q.value.raw), sql: isSql(q.value.cooked ?? q.value.raw)})), ...node.expressions.map((n: Ast) => evaluate(n, env, depth + 1)));
      case "BinaryExpression": return join(evaluate(node.left, env, depth + 1), evaluate(node.right, env, depth + 1));
      case "LogicalExpression": {
        const left = evaluate(node.left, env, depth + 1), unchanged = env.flatten(), executed = env.flatten();
        const right = evaluate(node.right, executed, depth + 1);
        mergeScopes(env, [unchanged, executed]);
        return join(left, right);
      }
      case "UnaryExpression": case "UpdateExpression": return evaluate(node.argument, env, depth + 1);
      case "SequenceExpression": {let value = fixed(); for (const expression of node.expressions) value = evaluate(expression, env, depth + 1); return value;}
      case "ConditionalExpression": {
        evaluate(node.test, env, depth + 1);
        const yes = env.flatten(), no = env.flatten();
        const value = join(evaluate(node.consequent, yes, depth + 1), evaluate(node.alternate, no, depth + 1));
        mergeScopes(env, [yes, no]);
        return value;
      }
      case "ArrayExpression": {const props = new Map<string, Value>(); node.elements.forEach((n: Ast, i: number) => props.set(String(i), evaluate(n, env, depth + 1))); return {...join(...props.values()), props};}
      case "ObjectExpression": {
        const props = new Map<string, Value>();
        for (const property of node.properties) {
          if (property.type === "SpreadElement") {const spread = evaluate(property.argument, env, depth + 1); for (const [key, value] of spread.props || []) props.set(key, value); continue;}
          const key = keyOf(property.key); const value = property.type === "ObjectMethod" ? functionValue(property, env) : evaluate(property.value, env, depth + 1);
          if (key) props.set(key, value);
          if (key === "rejectUnauthorized" && value.constant === false) add(property, fixed(), "javascript-tls-verification", "Certificate verification disabled", "CWE-295",
            "A TLS-shaped option disables certificate validation.", "Keep certificate verification enabled and configure the intended trust store.", ["Confirm that this object reaches a TLS client."], {severity: "medium"});
        }
        return {...join(...props.values()), props};
      }
      case "FunctionExpression": case "ArrowFunctionExpression": return functionValue(node, env);
      case "AssignmentExpression": {
        const right = evaluate(node.right, env, depth + 1); const value = node.operator === "=" ? right : join(evaluate(node.left, env, depth + 1), right);
        if (members.has(node.left.type)) {
          const key = node.left.computed && node.left.property.type === "Identifier" ? undefined : keyOf(node.left.property);
          if (key === "innerHTML" || key === "outerHTML") htmlSink(node, value, key === "innerHTML" ? "javascript-innerhtml" : "javascript-html-insertion", key === "innerHTML" && !node.left.computed && node.operator === "=" ? node.left.property : undefined);
          const object = evaluate(node.left.object, env, depth + 1);
          if (key === "href" && object.api === "browser.location" && value.trace.length) add(node, value, "javascript-open-redirect", "Potential client-side open redirect", "CWE-601", "Untrusted input reaches a browser navigation destination.", "Allowlist same-origin routes and reject protocol-relative or external URLs.", ["Inspect destination validation and the browser's URL interpretation."]);
          if (key && node.left.object.type === "Identifier") {const prior = env.get(node.left.object.name) || unknown(); const props = new Map(prior.props); props.set(key, step(value, node, "assignment", "Value is assigned to an object property")); env.set(node.left.object.name, {...prior, props});}
        } else bind(node.left, value, env, false, depth + 1);
        return value;
      }
      case "CallExpression": case "OptionalCallExpression": case "NewExpression": {
        const callee = evaluate(node.callee, env, depth + 1);
        const args = node.arguments.map((argument: Ast) => evaluate(argument.type === "SpreadElement" ? argument.argument : argument, env, depth + 1));
        return checkCall(node, callee, args, env, depth + 1);
      }
      case "TaggedTemplateExpression": return join(evaluate(node.quasi, env, depth + 1), unknown());
      case "JSXElement": {
        for (const attribute of node.openingElement?.attributes || []) {
          if (attribute.type === "JSXAttribute" && attribute.name?.name === "dangerouslySetInnerHTML") {const value = evaluate(attribute.value?.expression, env, depth + 1); htmlSink(attribute, value.props?.get("__html") || fixed(), "javascript-react-html");}
          else if (attribute.type === "JSXSpreadAttribute") {const value = evaluate(attribute.argument, env, depth + 1); const html = value.props?.get("dangerouslySetInnerHTML")?.props?.get("__html"); if (html) htmlSink(attribute, html, "javascript-react-html");}
        }
        for (const child of node.children || []) evaluate(child, env, depth + 1);
        return fixed();
      }
      case "JSXExpressionContainer": return evaluate(node.expression, env, depth + 1);
      case "JSXFragment": for (const child of node.children || []) evaluate(child, env, depth + 1); return fixed();
      default: return unknown();
    }
  };
  const functionValue = (node: Ast, env: Scope): Value => {queue(node, env); return {...fixed(), fn: node, closure: env};};
  const statements = (nodes: Ast[], env: Scope, depth: number): Value => {
    let result = fixed();
    for (const node of nodes || []) if (node.type === "FunctionDeclaration" && node.id) env.values.set(node.id.name, functionValue(node, env));
    for (const node of nodes || []) {
      if (!budget(depth)) break;
      switch (node.type) {
        case "ImportDeclaration": {
          const module = String(node.source.value).replace(/^node:/, "");
          for (const specifier of node.specifiers) {
            const named = specifier.type === "ImportSpecifier" ? keyOf(specifier.imported) : "";
            env.values.set(specifier.local.name, {dynamic: false, trace: [], api: module + (named ? "." + named : "")});
          }
          break;
        }
        case "VariableDeclaration": for (const declaration of node.declarations) bind(declaration.id, declaration.init ? evaluate(declaration.init, env, depth + 1) : unknown(), env, true, depth + 1); break;
        case "ExpressionStatement": evaluate(node.expression, env, depth + 1); break;
        case "ReturnStatement": result = join(result, evaluate(node.argument, env, depth + 1)); break;
        case "ThrowStatement": evaluate(node.argument, env, depth + 1); break;
        case "ExportNamedDeclaration": case "ExportDefaultDeclaration": {
          for (const specifier of node.specifiers || []) {const name = keyOf(specifier.local); if (name) exportedNames.add(name);}
          if (node.declaration) {
            if (["FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression"].includes(node.declaration.type)) exported.add(node.declaration);
            if (node.declaration.type === "Identifier") exportedNames.add(node.declaration.name);
            if (node.declaration.type === "VariableDeclaration") for (const item of node.declaration.declarations) if (item.id.type === "Identifier") exportedNames.add(item.id.name);
            if (node.declaration.type.endsWith("Declaration")) result = join(result, statements([node.declaration], env, depth + 1)); else evaluate(node.declaration, env, depth + 1);
          }
          break;
        }
        case "BlockStatement": result = join(result, statements(node.body, new Scope(env), depth + 1)); break;
        case "IfStatement": {
          evaluate(node.test, env, depth + 1); const yes = env.flatten(), no = env.flatten();
          result = join(result, statements(node.consequent.type === "BlockStatement" ? node.consequent.body : [node.consequent], new Scope(yes), depth + 1), node.alternate ? statements(node.alternate.type === "BlockStatement" ? node.alternate.body : [node.alternate], new Scope(no), depth + 1) : fixed());
          mergeScopes(env, [yes, no]); break;
        }
        case "ForStatement": case "ForOfStatement": case "ForInStatement": case "WhileStatement": case "DoWhileStatement": {
          const original = env.flatten(), loop = env.flatten();
          if (node.init?.type === "VariableDeclaration") statements([node.init], loop, depth + 1); else if (node.init) evaluate(node.init, loop, depth + 1);
          const iterated = node.right ? evaluate(node.right, loop, depth + 1) : unknown();
          if (node.left?.type === "VariableDeclaration") for (const declaration of node.left.declarations) bind(declaration.id, iterated, loop, true, depth + 1);
          else if (node.left) bind(node.left, iterated, loop, false, depth + 1);
          for (let i = 0; i < 2; i++) {evaluate(node.test, loop, depth + 1); result = join(result, statements(node.body?.type === "BlockStatement" ? node.body.body : [node.body], new Scope(loop), depth + 1)); if (node.update) evaluate(node.update, loop, depth + 1);}
          mergeScopes(env, [original, loop]); break;
        }
        case "TryStatement": {
          const success = env.flatten(), failure = env.flatten(); result = join(result, statements(node.block.body, new Scope(success), depth + 1));
          if (node.handler) {const catchScope = new Scope(failure); if (node.handler.param) bind(node.handler.param, unknown(), catchScope, true, depth + 1); result = join(result, statements(node.handler.body.body, catchScope, depth + 1));}
          mergeScopes(env, [success, failure]); if (node.finalizer) result = join(result, statements(node.finalizer.body, env, depth + 1)); break;
        }
        case "SwitchStatement": {
          evaluate(node.discriminant, env, depth + 1); const branches = [env.flatten()];
          for (const item of node.cases) {const branch = env.flatten(); evaluate(item.test, branch, depth + 1); result = join(result, statements(item.consequent, new Scope(branch), depth + 1)); branches.push(branch);}
          mergeScopes(env, branches); break;
        }
        case "ClassDeclaration": case "ClassExpression": for (const item of node.body?.body || []) {if (["ClassMethod", "ClassPrivateMethod"].includes(item.type)) queue(item, env); else if (item.value) evaluate(item.value, env, depth + 1);} break;
        case "LabeledStatement": statements([node.body], env, depth + 1); break;
      }
    }
    return result;
  };
  const rootScope = new Scope();
  statements(tree.program.body, rootScope, 0);
  for (const name of exportedNames) {const fn = rootScope.get(name)?.fn; if (fn) exported.add(fn);}
  // Uncalled exports and framework callbacks are entry points with unknown arguments.
  for (let i = 0; i < pending.length && visits <= 60_000; i++) {
    if (!called.has(pending[i].node) || exported.has(pending[i].node)) runFunction(pending[i].node, pending[i].closure, undefined, 0, 1);
  }
  return {findings, parsed: true, diagnostics: [], truncated};
}
