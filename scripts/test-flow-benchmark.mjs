// Owned synthetic examples, not a measurement of general security coverage.
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {analyzeCode} from '../lib/browser-analysis.ts';
const cases=JSON.parse(readFileSync(new URL('../tests/fixtures/browser-flow-cases.json',import.meta.url),'utf8'));
for(const entry of cases)test(`flow corpus: ${entry.name}`,()=>{
  const filename=entry.language==='python'?'case.py':entry.source.includes('<div')?'case.tsx':'case.ts';
  const result=analyzeCode(entry.source,entry.language,filename);
  assert.equal(result.coverage.syntax,'parsed',JSON.stringify(result.coverage));
  if(entry.expected_cwe){
    const finding=result.findings.find(f=>f.cwe===entry.expected_cwe);
    assert.ok(finding,`${entry.name}: expected ${entry.expected_cwe}, got ${result.findings.map(f=>f.cwe).join(', ')}`);
    assert.equal(finding.classification,'potential_vulnerability');
    assert.equal(finding.evidence,'data_flow',`${entry.name} should follow a known input`);
    assert.ok(finding.trace.some(step=>step.kind==='source'));
    assert.ok(finding.trace.some(step=>step.kind==='sink'));
    assert.ok(finding.trace.every(step=>step.line>=1&&step.line<=result.linesAnalyzed));
  } else assert.deepEqual(result.findings,[],entry.name);
});

test('parse errors are partial and diagnostics never quote source values',()=>{
 const marker='private_marker_must_not_be_in_diagnostic';
 for(const [language,source] of [['typescript',`const x = "${marker}"; function (`],['python',`value = "${marker}"\ndef broken(`]]){
   const result=analyzeCode(source,language,'broken');
   assert.equal(result.coverage.syntax,'partial');
   assert.ok(result.coverage.diagnostics.length>0);
   assert.ok(!JSON.stringify(result.coverage).includes(marker));
 }
});

test('secret-containing source never creates a patch or reveals values in flow metadata',()=>{
 const secret='synthetic_flow_secret_241113';
 const result=analyzeCode(`const api_key="${secret}";\nconst value=req.query.html;\nelement.innerHTML=value;`,'typescript','source.ts');
 assert.ok(!JSON.stringify(result).includes(secret));
 assert.ok(result.findings.every(f=>!f.patch));
});

test('deep input returns a bounded partial result without execution',()=>{
 const source='const input='+ '('.repeat(1800)+'req.query.value'+')'.repeat(1800)+';';
 const result=analyzeCode(source,'typescript','deep.ts');
 assert.equal(result.coverage.syntax,'partial');
 assert.ok(result.limitations.some(x=>/budget|parsing|Syntax/i.test(x)));
});

test('many credential matches are fully redacted even when findings are capped',()=>{
 const credential='synthetic_many_secret_241113';
 const result=analyzeCode(`const api_key = "${credential}";\n`.repeat(2000),'javascript','many.js');
 assert.ok(!JSON.stringify(result).includes(credential));
 assert.equal(result.findings.length,100);
 assert.ok(result.limitations.some(x=>x.includes('100 findings')));
});
