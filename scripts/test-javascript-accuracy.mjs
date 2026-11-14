import {test} from 'node:test';
import assert from 'node:assert/strict';
import {analyzeJavaScript} from '../lib/javascript-analysis.ts';

const analyze=source=>{
  const result=analyzeJavaScript(source,'typescript','accuracy.ts');
  assert.equal(result.parsed,true,JSON.stringify(result.diagnostics));
  return result;
};
const has=(source,cwe)=>{
  const result=analyze(source);
  const finding=result.findings.find(item=>item.cwe===cwe);
  assert.ok(finding,JSON.stringify(result));
  return finding;
};
const lacks=(source,cwe)=>assert.ok(!analyze(source).findings.some(item=>item.cwe===cwe));
const imports='import * as child from "node:child_process";';

test('constant computed HTML properties preserve evidence without proposing an unsafe token patch',()=>{
  for (const property of ['innerHTML','outerHTML']) {
    const finding=has(`const property="${property}"; const alias=property; document.body[alias]=location.hash;`,'CWE-79');
    assert.equal(finding.evidence,'data_flow');
    assert.equal(finding.patchProperty,undefined);
  }
  lacks('const property="textContent"; document.body[property]=location.hash;','CWE-79');
});

test('computed object and destructuring keys resolve constants rather than identifier spellings',()=>{
  has(`${imports} const key="exec"; const {[key]:run}=child; run(req.query.command);`,'CWE-78');
  has('const key="html"; const state={[key]:location.hash}; document.body.innerHTML=state[key];','CWE-79');
  has('const key="insertAdjacentHTML"; element[key]("beforeend",location.hash);','CWE-79');
  lacks('const innerHTML="textContent"; document.body[innerHTML]=location.hash;','CWE-79');
  // Unknown keys must retain provenance; never turn an external-key lookup into a known safe value.
  has('const state={[req.query.key]:req.query.html}; const value=state[req.query.key]; document.body.innerHTML=value;','CWE-79');
  has('const state={}; state[req.query.key]=req.query.html; document.body.innerHTML=state[req.query.key];','CWE-79');
  has('const state={html:"fixed",[req.query.key]:req.query.html}; document.body.innerHTML=state.html;','CWE-79');
  has('const state={html:"fixed",...req.query.state}; document.body.innerHTML=state.html;','CWE-79');
  lacks('const state={[req.query.key]:req.query.html,html:"fixed"}; document.body.innerHTML=state.html;','CWE-79');
});

test('bound imported command methods and further aliases invoke their original sink',()=>{
  const finding=has(`${imports}\nconst run=child.exec.bind(child);\nconst launch=run;\nlaunch(req.query.command);`,'CWE-78');
  assert.equal(finding.line,4);
  assert.equal(finding.evidence,'data_flow');
  lacks(`${imports} const run=child.exec.bind(child,req.query.command);`,'CWE-78');
});

test('prebound command arguments retain their order across repeated binding',()=>{
  has(`${imports} const run=child.exec.bind(child,req.query.command); run();`,'CWE-78');
  has(`${imports} const first=child.exec.bind(child); const run=first.bind(null,req.query.command); run();`,'CWE-78');
  lacks(`${imports} const first=child.exec.bind(child,"printf hello"); const run=first.bind(null,req.query.command); run();`,'CWE-78');
  lacks(`${imports} const run=child.exec.bind(child,"printf hello"); run(req.query.command);`,'CWE-78');
});

test('binding overloads and literal-array spreads preserve shell options and tainted input',()=>{
  has(`${imports} const run=child.spawn.bind(child,"printf",[req.query.value]); run({shell:true});`,'CWE-78');
  lacks(`${imports} const run=child.spawn.bind(child,"printf",[req.query.value]); run({shell:false});`,'CWE-78');
  has(`${imports} const run=child.exec.bind(...[child,req.query.command]); run();`,'CWE-78');
  has(`${imports} const initial=[child,req.query.command]; const run=child.exec.bind(...initial); run();`,'CWE-78');
  has(`${imports} const run=child.exec.bind(...req.query.arguments); run();`,'CWE-78');
  lacks(`${imports} const run=child.exec.bind(...[child,"printf hello"]); run(req.query.command);`,'CWE-78');
});

test('reassignment and explicit own bind overrides take precedence over the modeled builtin',()=>{
  lacks(`${imports} let run=child.exec.bind(child); run=(value)=>value; run(req.query.command);`,'CWE-78');
  lacks(`${imports} const op=child.exec; op.bind=(value)=>value; const run=op.bind(null); run(req.query.command);`,'CWE-78');
  has(`${imports} const op=child.exec; op.bind=(value)=>{child.exec(value);}; op.bind(req.query.command);`,'CWE-78');
});

test('bound same-file helpers keep defaults and overrides conservative',()=>{
  has(`${imports} function launch(command=req.query.command){child.exec(command)} const run=launch.bind(null); run();`,'CWE-78');
  has(`${imports} function launch(command="printf hello"){child.exec(command)} const run=launch.bind(null,req.query.command); run();`,'CWE-78');
  lacks(`${imports} function launch(command){child.exec(command)} const run=launch.bind(null,"printf hello"); run();`,'CWE-78');
});

test('primitive Number conversion prevents SQL syntax influence while retaining evidence at other sinks',()=>{
  lacks('const id=Number(req.query.id); if(Number.isSafeInteger(id)) db.query("SELECT * FROM users WHERE id="+id);','CWE-89');
  lacks('const numeric=Number; const id=numeric(req.query.id); db.query(`SELECT * FROM users WHERE id=${id}`);','CWE-89');
  has(`${imports} const number=Number(req.query.value); child.exec(number);`,'CWE-78');
  has('const id=Number(req.query.id); db.query("SELECT * FROM users WHERE id="+id+req.query.extra);','CWE-89');
});

test('shadowed, rebound and boxed Number expressions do not become SQL sanitizers',()=>{
  for(const source of [
    'const Number=(value)=>value; const id=Number(req.query.id);',
    'function Number(value){return value} const id=Number(req.query.id);',
    'Number=(value)=>value; const id=Number(req.query.id);',
    'const id=new Number(req.query.id);',
    'const id=unknownTransform(Number(req.query.id));',
    'const id=Number(req.query.id)[req.query.key];',
  ]) has(`${source} db.query("SELECT * FROM users WHERE id="+id);`,'CWE-89');
  has('function run(Number=(value)=>value){db.query("SELECT * FROM users WHERE id="+Number(req.query.id))} run();','CWE-89');
});

test('strict literal equality allowlists narrow only the matching branch',()=>{
  lacks('const destination=req.query.next; if(destination==="/home"||destination==="/profile") res.redirect(destination);','CWE-601');
  lacks('const destination=req.query.next; if("/home"===destination) res.redirect(destination);','CWE-601');
  has('const destination=req.query.next; if(destination==="/home"||destination==="/profile") log(destination); res.redirect(destination);','CWE-601');
  has('const destination=req.query.next; if(destination==="/home") log(destination); else res.redirect(destination);','CWE-601');
});

test('partial or coercing redirect guards and subsequent reassignment never clear provenance',()=>{
  for(const guard of [
    'destination==="/home"||req.query.bypass',
    'destination=="/home"',
    'destination.startsWith("/home")',
    'destination==="/home"||other==="/profile"',
    'destination==="/home"||(destination=req.query.next)',
  ]) has(`let destination=req.query.next; const other=req.query.other; if(${guard}) res.redirect(destination);`,'CWE-601');
  has('let destination=req.query.next; if(destination==="/home"||destination==="/profile"){destination=req.query.override;res.redirect(destination)}','CWE-601');
  has('let destination=req.query.next; if(destination==="/home"||destination==="/profile"){const destination=req.query.override;res.redirect(destination)}','CWE-601');
});

test('bound callable depth remains budgeted without executing source',()=>{
  const source=`${imports} globalThis.__bindingExecuted=true; const run=child.exec${'.bind(null)'.repeat(150)}; run(req.query.command);`;
  const result=analyze(source);
  assert.equal(result.truncated,true);
  assert.equal(globalThis.__bindingExecuted,undefined);
});

test('mutable redirect bindings are not narrowed across closure calls or await points',()=>{
  has('let destination=req.query.next; function replace(){destination=req.query.override;} if(destination==="/home"){replace();res.redirect(destination);}','CWE-601');
  has('let destination=req.query.next; async function replace(){destination=req.query.override;} if(destination==="/home"){await replace();res.redirect(destination);}','CWE-601');
  has('var destination=req.query.next; function replace(){destination=req.query.override;} if(destination==="/home"){replace();res.redirect(destination);}','CWE-601');
  // An inner mutable binding must not inherit an outer const declaration's metadata.
  has('const destination="/home"; {let destination=req.query.next; function replace(){destination=req.query.override;} if(destination==="/home"){replace();res.redirect(destination);}}','CWE-601');
  has('const destination="/home"; function run(destination){if(destination==="/home"){replace();res.redirect(destination);}} run(req.query.next);','CWE-601');
  lacks('const destination=req.query.next; if(destination==="/home"){await harmless();res.redirect(destination);}','CWE-601');
});

test('possible global Number replacement anywhere invalidates numeric SQL conversion safety',()=>{
  for(const mutation of [
    'globalThis.Number=(value)=>value;',
    'window.Number=(value)=>value;',
    'global.Number=(value)=>value;',
    'self["Number"]=(value)=>value;',
    'globalThis[req.query.property]=(value)=>value;',
    'function replace(){Number=(value)=>value;} replace();',
    'function replace(){globalThis.Number=(value)=>value;} replace();',
    'function replace(){({number:Number}=req.query.builtins);} replace();',
    '(Number as any)=(value)=>value;',
  ]) has(`${mutation} const id=Number(req.query.id); db.query("SELECT * FROM users WHERE id="+id);`,'CWE-89');
  has('const numeric=Number; function replace(){Number=(value)=>value;} replace(); const id=numeric(req.query.id); db.query("SELECT * FROM users WHERE id="+id);','CWE-89');
});
