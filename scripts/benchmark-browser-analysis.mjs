import {readFileSync} from 'node:fs';
import {analyzeCode} from '../lib/browser-analysis.ts';
import {analyzeCode as patternBaseline} from '../lib/lexical-analysis.ts';
const cases=JSON.parse(readFileSync(new URL('../tests/fixtures/browser-flow-cases.json',import.meta.url),'utf8'));
const summary=(analyzer)=>{
 let detected=0, traced=0, falsePositives=0, partial=0;
 const rows=cases.map(entry=>{
  const result=analyzer(entry.source,entry.language,entry.language==='python'?'case.py':'case.tsx');
  const finding=result.findings.find(f=>f.cwe===entry.expected_cwe);
  if(entry.expected_cwe&&finding){detected++;if(finding.evidence==='data_flow')traced++;}
  if(!entry.expected_cwe&&result.findings.length)falsePositives++;
  if(result.coverage?.syntax==='partial')partial++;
  return {name:entry.name,expected:entry.expected_cwe,matched:!!finding,findings:result.findings.length};
 });
 return {vulnerableCases:cases.filter(x=>x.expected_cwe).length,detected,traced,safeCases:cases.filter(x=>!x.expected_cwe).length,safeCasesFlagged:falsePositives,partial,rows};
};
const current=summary(analyzeCode),baseline=summary(patternBaseline);
console.log(JSON.stringify({scope:'Owned 26-case regression corpus only; not a general accuracy or exploitability guarantee.',baseline,current},null,2));
if(current.detected!==current.vulnerableCases||current.safeCasesFlagged||current.partial)process.exitCode=1;
