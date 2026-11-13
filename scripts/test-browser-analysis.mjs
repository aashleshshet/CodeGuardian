// Run with Node 22.18+ or `node --experimental-strip-types` on older Node 22.
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {analyzeCode, redactCode, MAX_CODE_BYTES} from '../lib/browser-analysis.ts';

const rules = (source, language='typescript') => analyzeCode(source, language, 'review.ts').findings.map(f=>f.ruleId);

test('detects JavaScript sinks and distinguishes unverified evidence from suggestions',()=>{
 const result=analyzeCode('const query = `SELECT * FROM users WHERE id = ${id}`;\neval(input);\nelement.innerHTML = payload;\nexec(command);\nconst tls = {rejectUnauthorized: false};\ncrypto.createHash("md5");','typescript','../private/review.ts');
 assert.deepEqual(result.findings.map(f=>f.ruleId),['sql-interpolation','dynamic-eval','javascript-innerhtml','javascript-shell','javascript-tls-verification','javascript-weak-hash']);
 assert.equal(result.filename,'review.ts');
 assert.ok(result.findings.every(f=>f.classification!=='verified_analyzer'));
 assert.equal(result.findings.at(-1).classification,'secure_coding_suggestion');
 assert.equal(result.linesAnalyzed,6);
 assert.ok(result.limitations.some(x=>x.includes('not Semgrep')));
});

test('detects Python risks without executing the submitted code',()=>{
 const source='query = f"SELECT * FROM users WHERE id = {user_id}"\nsubprocess.run(cmd, shell=True)\nyaml.load(payload)\npickle.loads(payload)\nrequests.get(url, verify=False)\nhashlib.sha1(value)\nraise RuntimeError("must not run")';
 assert.deepEqual(rules(source,'python'),['sql-interpolation','python-shell','python-pickle','python-unsafe-yaml','python-tls-verification','python-weak-hash']);
});

test('safe alternatives and ordinary regular-expression exec do not match unsafe sinks',()=>{
 assert.deepEqual(rules('db.query("SELECT * FROM users WHERE id = $1", [id]);\nelement.textContent = input;\nconst data = JSON.parse(input);\nconst hit = regex.exec(input);\nconst tls = {rejectUnauthorized: true};'),[]);
 assert.deepEqual(rules('cursor.execute("SELECT * FROM users WHERE id = %s", [user_id])\nyaml.safe_load(payload)\nyaml.load(payload, Loader=yaml.SafeLoader)\nsubprocess.run(["ls", path], shell=False)\nrequests.get(url, verify=True)','python'),[]);
});

test('full-line, block comments and ordinary string literals do not become findings',()=>{
 assert.deepEqual(rules('// eval(input)\n/* element.innerHTML = input;\nexec(command); */\nconst message = "eval(input)";\nconst more = `document.write(input)`;'),[]);
 assert.deepEqual(rules('# eval(input)\n"""\npickle.loads(input)\n"""\nmessage = "yaml.load(input)"','python'),[]);
 assert.ok(rules('const description = "eval(input)"; eval(value);').includes('dynamic-eval'));
});

test('language gates avoid applying Python rules to JavaScript',()=>{
 assert.deepEqual(rules('pickle.loads(value)\nyaml.load(value)\nrequests.get(url, verify=False)','javascript'),[]);
 assert.deepEqual(rules('element.innerHTML = value\ndocument.write(value)\ncrypto.createHash("md5")','python'),[]);
});

test('redacts supported credential forms from source, reports and patches while preserving lines',()=>{
 const secret='synthetic_password_123456';
 const key='ghp_'+'A'.repeat(30);
 const source=`const password = "${secret}";\n// ${key}\nconst pem = "-----BEGIN PRIVATE KEY-----\nsynthetic-key-material\n-----END PRIVATE KEY-----";\nelement.innerHTML = payload;`;
 const result=analyzeCode(source,'javascript','input.js');
 const serialized=JSON.stringify(result);
 for(const value of [secret,key,'synthetic-key-material']) assert.ok(!serialized.includes(value));
 assert.equal(result.redactedSource.split('\n').length,source.split('\n').length);
 assert.equal(result.findings.filter(f=>f.ruleId==='hardcoded-credential').length,3);
 assert.equal(result.findings.find(f=>f.ruleId==='javascript-innerhtml').patch,undefined);
 assert.ok(result.redactedSource.includes('[REDACTED]'));
});

test('redaction covers URI passwords, bearer credentials and provider keys',()=>{
 const value='not_a_real_password_123';
 const input=`postgres://user:${value}@localhost/app\nBearer ${value}\nsk-test-${'x'.repeat(30)}`;
 assert.ok(!redactCode(input).includes(value));
 assert.ok(!redactCode(input).includes('x'.repeat(30)));
});

test('bounded patches change only the identified assignment and carry a human-review caveat',()=>{
 const source='const label = ".innerHTML"; element.innerHTML = input;';
 const result=analyzeCode(source,'javascript','review.js');
 const patch=result.findings.find(f=>f.ruleId==='javascript-innerhtml').patch;
 assert.equal(patch.original,source);
 assert.equal(patch.modified,'const label = ".innerHTML"; element.textContent = input;');
 assert.ok(patch.diff.includes('@@ -1,1 +1,1 @@'));
 assert.ok(patch.caveat.includes('test before applying'));
 assert.equal(analyzeCode('element.innerHTML = "<b>fixed</b>";','javascript','safe.js').findings.length,0);
});

test('bounds bytes, rejects invalid input and reports a match cap honestly',()=>{
 assert.throws(()=>analyzeCode(' ','python','empty.py'),/Paste code/);
 assert.throws(()=>analyzeCode('eval(x)','ruby','x.rb'),/Choose Python/);
 assert.throws(()=>analyzeCode('x'.repeat(MAX_CODE_BYTES+1),'python','big.py'),/200 KiB/);
 assert.throws(()=>redactCode('é'.repeat(MAX_CODE_BYTES)),/200 KiB/);
 const result=analyzeCode('eval(input);\n'.repeat(120),'javascript','many.js');
 assert.equal(result.findings.length,100);
 assert.ok(result.limitations.some(x=>x.includes('first 100')));
});

test('never evaluates malicious source or uses a source-provided filename as a path',()=>{
 const source='globalThis.__codeGuardianExecuted = true; eval(input);';
 const result=analyzeCode(source,'javascript','../../report\n</script>.js');
 assert.equal(globalThis.__codeGuardianExecuted,undefined);
 assert.ok(!result.filename.includes('/')&&!result.filename.includes('<')&&!result.filename.includes('\n'));
});
