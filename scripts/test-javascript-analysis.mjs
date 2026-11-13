import {test} from 'node:test';
import assert from 'node:assert/strict';
import {analyzeJavaScript} from '../lib/javascript-analysis.ts';

test('pasted TypeScript containing JSX is parsed without requiring a filename',()=>{
 const result=analyzeJavaScript('const html=req.body.html; const view=<div dangerouslySetInnerHTML={{__html:html}}/>;','typescript','untitled.ts');
 assert.equal(result.parsed,true);
 assert.equal(result.findings.find(f=>f.cwe==='CWE-79')?.evidence,'data_flow');
});
const analyze=(source, language='typescript', filename='review.ts')=>analyzeJavaScript(source,language,filename);
const rules=source=>analyze(source).findings.map(f=>f.ruleId);
const has=(source,rule)=>{const result=analyze(source); assert.equal(result.parsed,true); const finding=result.findings.find(f=>f.ruleId===rule); assert.ok(finding,JSON.stringify(result)); return finding;};

test('tracks require destructuring, aliases and multiple-line shell calls',()=>{
 const f=has('const {exec: shell} = require("node:child_process");\nconst run=shell;\nconst value=req.body.command;\nrun(\n value\n);','javascript-shell');
 assert.equal(f.line,4);assert.equal(f.endLine,6);assert.equal(f.evidence,'data_flow');
});
test('follows helper arguments into sinks and helper return values',()=>{
 const f=has('import {exec} from "child_process";\nfunction launch(arg) { exec(arg); }\nlaunch(req.query.command);','javascript-shell');
 assert.equal(f.line,2); assert.equal(f.evidence,'data_flow');
 assert.ok(f.trace.some(t=>t.line===3 && t.kind==='source'));
});
test('joins taint through branches and loops instead of clearing it on one branch',()=>{
 has('let x = "fixed"; if (condition) {x=req.query.html;} else {x="fixed";} document.body.innerHTML=x;','javascript-innerhtml');
 has('let x="fixed"; for (const value of req.query.items) {x=value;} document.body.innerHTML=x;','javascript-innerhtml');
});
test('block scope shadows are distinct from the outer variable',()=>{
 assert.deepEqual(rules('let x="fixed"; {const x=req.query.html;} document.body.innerHTML=x;'),[]);
 has('const x=req.query.html; {const x="fixed";} document.body.innerHTML=x;','javascript-innerhtml');
});
test('reassignment to a constant removes prior input influence',()=>{
 assert.deepEqual(rules('let x=req.query.html; x="<p>fixed</p>"; document.body.innerHTML=x;'),[]);
});
test('unrelated exec methods and shadowed globals are not shell or evaluation sinks',()=>{
 assert.deepEqual(rules('const match=regex.exec(req.query.pattern); function run(evalFn) {evalFn(req.query.value);}'),[]);
 assert.deepEqual(rules('function fetch(target) { return target; } fetch(req.query.url);'),[]);
});
test('unknown sanitizers do not clear HTML taint',()=>{
 assert.equal(has('const safe = sanitize(req.query.html); element.innerHTML=safe;','javascript-innerhtml').evidence,'data_flow');
});
test('a trusted HTML sanitizer does not clear SQL or shell provenance',()=>{
 const source='import DOMPurify from "dompurify"; import {exec} from "node:child_process"; const safe=DOMPurify.sanitize(req.query.value); exec(safe); db.query("SELECT * FROM x WHERE id="+safe);';
 assert.ok(rules(source).includes('javascript-shell'));assert.ok(rules(source).includes('sql-interpolation'));
});
test('sanitize on only one branch does not establish HTML safety',()=>{
 has('import DOMPurify from "dompurify"; let html=req.query.html; if(condition){html=DOMPurify.sanitize(html);} element.innerHTML=html;','javascript-innerhtml');
});
test('binding named DOMPurify without trusted import does not sanitize',()=>{
 has('const DOMPurify={sanitize: (x)=>x}; element.innerHTML=DOMPurify.sanitize(req.query.html);','javascript-innerhtml');
});
test('detects template-literal expressions nested in strings',()=>{
 assert.ok(rules('const content = `prefix ${eval(req.query.code)}`;').includes('dynamic-eval'));
});
test('new Function checks the dynamic body, not only the first parameter',()=>{
 has('new Function("arg", req.body.code);','dynamic-eval');
});
test('browser form and URL search inputs have provenance',()=>{
 assert.equal(has('const input=document.querySelector("input"); const x=input.value; element.innerHTML=x;','javascript-innerhtml').evidence,'data_flow');
 assert.equal(has('const params=new URLSearchParams(location.search); const x=params.get("x"); element.innerHTML=x;','javascript-innerhtml').evidence,'data_flow');
});
test('path joining is not containment validation',()=>{
 assert.equal(has('import path from "node:path"; import {readFile} from "node:fs"; const name=path.join("/safe",req.query.file); readFile(name);','javascript-path-traversal').evidence,'data_flow');
});
test('shell false uses argument-vector process APIs without a shell finding',()=>{
 assert.deepEqual(rules('import {spawn} from "node:child_process"; spawn("printf",[req.query.value],{shell:false});'),[]);
 has('import {spawn} from "node:child_process"; spawn("printf",[req.query.value],{shell:true});','javascript-shell');
});
test('flags unsigned JWT configuration and weak crypto separately',()=>{
 assert.ok(rules('import jwt from "jsonwebtoken"; jwt.verify(req.query.token, "", {algorithms:["none"]});').includes('javascript-jwt-none'));
 const finding=has('import {createHash as hash} from "node:crypto"; hash("md5");','javascript-weak-hash');assert.equal(finding.classification,'secure_coding_suggestion');
});
test('comments, literals and regex literals do not become executable sinks',()=>{
 assert.deepEqual(rules('const s="eval(req.query.x)"; const re=/eval\\(x\\)/; // element.innerHTML=x;\n/* exec(req.query.command) */'),[]);
});
test('parse diagnostics never echo source contents',()=>{
 const r=analyze('const confidential_marker="literal"; function (');assert.equal(r.parsed,false);assert.ok(r.diagnostics.length);assert.ok(!JSON.stringify(r).includes('confidential_marker'));
});
test('patch location points only at a direct property token',()=>{
 const source='const text="innerHTML"; element.innerHTML = req.query.value;';const f=has(source,'javascript-innerhtml');assert.equal(source.slice(f.patchProperty.start,f.patchProperty.end),'innerHTML');
 assert.equal(has('element["innerHTML"] = req.query.value;','javascript-innerhtml').patchProperty,undefined);
});
test('findings and recursive function analysis have explicit limits',()=>{
 const r=analyze('eval(req.query.x);\n'.repeat(110));assert.equal(r.findings.length,100);assert.equal(r.truncated,true);
 const recursive=analyze('function loop(x){return loop(x)}; element.innerHTML=loop(req.query.x);');assert.equal(recursive.truncated,true);
});
test('source is never executed and trace labels contain no copied values',()=>{
 const source='globalThis.codeGuardianExecuted=true; const private_variable=req.query.private_name; element.innerHTML=private_variable;';const r=analyze(source);assert.equal(globalThis.codeGuardianExecuted,undefined);assert.ok(!JSON.stringify(r).includes('private_variable'));assert.ok(!JSON.stringify(r).includes('private_name'));
});

test('a same-file internal helper called only with a literal does not acquire a hypothetical finding',()=>{
 assert.deepEqual(rules('function render(html) {document.body.innerHTML=html;} render("fixed");'),[]);
 const findings=analyze('export function render(html: string) {document.body.innerHTML=html;} render("fixed");').findings;
 assert.equal(findings[0].evidence,'structural');
});

test('short-circuit and conditional side effects preserve the unsanitized branch',()=>{
 for (const branch of ['enabled && (v=DOMPurify.sanitize(v))','enabled || (v=DOMPurify.sanitize(v))','enabled ?? (v=DOMPurify.sanitize(v))','enabled ? (v=DOMPurify.sanitize(v)) : null','enabled ? null : (v=DOMPurify.sanitize(v))']) {
  const f=has(`import DOMPurify from "dompurify"; let v=location.hash; ${branch}; document.body.innerHTML=v;`,'javascript-innerhtml');
  assert.equal(f.evidence,'data_flow');
 }
});
test('exported arrows and named export handlers remain external entry points after a safe local call',()=>{
 const declaration='const handler=(req)=>{fetch(req.query.url)};';
 const call='handler({query:{url:"https://example.com"}});';
 for(const source of ['export '+declaration+call,declaration+call+'export {handler};','export {handler};'+declaration+call,declaration+call+'export default handler;','export default (req)=>{fetch(req.query.url)};']) {
   assert.equal(has(source,'javascript-ssrf').evidence,'data_flow');
 }
});
test('two-argument spawn overload observes shell option',()=>{
 assert.equal(has('import {spawn} from "node:child_process"; spawn(req.query.command,{shell:true});','javascript-shell').evidence,'data_flow');
 assert.deepEqual(rules('import {spawn} from "node:child_process"; spawn(req.query.command,{shell:false});'),[]);
});
