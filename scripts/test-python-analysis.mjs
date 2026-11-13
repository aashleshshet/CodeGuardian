import {test} from 'node:test';
import assert from 'node:assert/strict';
import {analyzePython} from '../lib/python-analysis.ts';

const check=source=>analyzePython(source);
const rules=source=>check(source).findings.map(f=>f.ruleId);

test('Python multiline imported shell alias retains an external-input trace',()=>{
 const result=check(`from subprocess import run as launch\nfrom flask import request as req\nname = req.args.get('name')\ncommand = 'echo ' + name\nlaunch(\n    command,\n    shell=True\n)\n`);
 const issue=result.findings.find(f=>f.ruleId==='python-shell');
 assert.equal(result.parsed,true); assert.equal(issue.evidence,'data_flow');
 assert.equal(issue.line,5); assert.equal(issue.endLine,8);
 assert.ok(issue.trace.some(t=>t.line===3&&t.kind==='source'));
 assert.ok(issue.trace.some(t=>t.line===4&&t.kind==='assignment'));
 assert.ok(issue.trace.some(t=>t.line===5&&t.kind==='sink'));
});

test('Python query construction flows through a local helper to SQL execution',()=>{
 const result=check(`from flask import request\ndef query_for(value):\n    query = "SELECT * FROM users WHERE name = '" + value + "'"\n    return query\nuser = request.args.get('name')\nsql = query_for(user)\ncursor.execute(\n    sql\n)\n`);
 const issue=result.findings.find(f=>f.ruleId==='sql-interpolation');
 assert.equal(issue.evidence,'data_flow');assert.equal(issue.line,7);
 assert.ok(issue.trace.some(t=>t.kind==='call'));
 assert.ok(!JSON.stringify(issue).includes('SELECT'));
});

test('Python f-strings and format interpolation are inspected at the execution sink',()=>{
 assert.ok(rules(`query = f"SELECT * FROM users WHERE id = {request.args['id']}"\ncursor.execute(query)`).includes('sql-interpolation'));
 assert.ok(rules(`query = "SELECT * FROM users WHERE id = {}".format(request.args['id'])\ncursor.execute(query)`).includes('sql-interpolation'));
 assert.ok(rules(`query = "SELECT * FROM users WHERE id = %s" % request.args['id']\ncursor.execute(query)`).includes('sql-interpolation'));
 assert.ok(!rules(`query = f"SELECT * FROM users WHERE id = {request.args['id']}"`).includes('sql-interpolation'));
});

test('Python SSRF, traversal, templates and redirect preserve input provenance',()=>{
 const result=check(`from urllib.request import urlopen as fetch\nfrom flask import request, render_template_string as render, redirect\nimport os\nurl = request.args.get('url')\nfetch(url)\npath = os.path.join('/uploads', request.args['file'])\nopen(path)\nrender(request.form['template'])\nredirect(url)\n`);
 for(const rule of ['python-ssrf','python-path-traversal','python-template-injection','python-open-redirect'])assert.equal(result.findings.find(f=>f.ruleId===rule)?.evidence,'data_flow',rule);
});

test('Python safe loaders, bound parameters, fixed destinations and argument lists do not match',()=>{
 const result=check(`from yaml import load, SafeLoader as Safe\nimport subprocess as sp\nimport requests\nfrom flask import request\nvalue = request.args['id']\ncursor.execute('SELECT * FROM users WHERE id = %s', [value])\nsp.run(['echo', value], shell=False)\nload(\n    value,\n    Loader=Safe\n)\nrequests.get('https://example.com', verify=True)\nopen('/fixed/path')\n`);
 assert.deepEqual(result.findings,[]);assert.equal(result.parsed,true);
});

test('Python dangerous deserialization, TLS and hashes are structural findings',()=>{
 const result=check(`from pickle import loads as deserialize\nfrom yaml import load as load_yaml\nimport requests as http\nfrom hashlib import sha1 as digest\ndeserialize(payload)\nload_yaml(payload)\nhttp.get('https://example.com', verify=False)\ndigest(b'value')\n`);
 assert.deepEqual(result.findings.map(f=>f.ruleId),['python-pickle','python-unsafe-yaml','python-tls-verification','python-weak-hash']);
 assert.ok(result.findings.every(f=>f.evidence==='structural'));
 assert.equal(result.findings.at(-1).classification,'secure_coding_suggestion');
});

test('Python comments, docstrings and ordinary literals never become sink calls',()=>{
 assert.deepEqual(rules(`# eval(user)\n"""pickle.loads(payload)\nrequests.get(request.args['url'])\n"""\nmessage = "os.system(command)"\n`),[]);
 assert.deepEqual(rules(`def safe():\n    """yaml.load(payload)"""\n    return 'eval(value)'\n`),[]);
});

test('Python branches conservatively retain a tainted assignment',()=>{
 const result=check(`if allowed:\n    target = request.args['url']\nelse:\n    target = 'https://example.com'\nrequests.get(target)\n`);
 assert.equal(result.findings.find(f=>f.ruleId==='python-ssrf')?.evidence,'data_flow');
});

test('Python reassignment and shadowed input objects do not invent taint',()=>{
 assert.deepEqual(rules(`target = request.args['url']\ntarget = 'https://example.com'\nrequests.get(target)\n`),[]);
 assert.deepEqual(rules(`request = Mock()\nrequests.get(request.args['url'])\n`),[]);
 assert.deepEqual(rules(`from subprocess import run\nrun = safe_library\nrun(command, shell=True)\n`),[]);
});

test('Python function parameters stay unknown unless an actual source reaches them',()=>{
 const source=`import os\ndef run_it(cmd):\n    os.system(cmd)\nrun_it(request.args['command'])\n`;
 const result=check(source);const issue=result.findings.find(f=>f.ruleId==='python-os-system');
 assert.equal(issue.evidence,'data_flow');
 const unknown=check(`import os\ndef run_it(cmd):\n    os.system(cmd)\n`);
 assert.equal(unknown.findings[0].evidence,'structural');
});

test('Python parse errors return incomplete generic diagnostics without source values',()=>{
 const marker='private_marker_that_must_not_escape';
 const result=check(`def ${marker}(:\n  pass\n`);
 assert.equal(result.parsed,false);assert.ok(result.diagnostics.length);assert.ok(!JSON.stringify(result).includes(marker));
});

test('Python source, recursion and finding limits are explicit and never execute input',()=>{
 assert.equal(check('x'.repeat(200*1024+1)).parsed,false);
 const repeated=check('eval(user)\n'.repeat(120));assert.equal(repeated.findings.length,100);assert.equal(repeated.truncated,true);
 const recursive=check(`def f(value):\n    return f(value)\nf(request.args['x'])\n`);assert.equal(recursive.truncated,true);
 const result=check(`__import__('os').system('do not execute')\neval(user)\n`);assert.ok(result.findings.some(f=>f.ruleId==='dynamic-eval'));
});

test('Python keyword shell options and assigned aliases are recognized',()=>{
 const result=check(`import subprocess\nlaunch = subprocess.run\noptions = {'shell': True}\ncommand = request.args['command']\nlaunch(command, **options)\n`);
 assert.equal(result.findings.find(f=>f.ruleId==='python-shell')?.evidence,'data_flow');
});

test('Python nested helper scopes and global updates do not leak function bindings',()=>{
 const result=check(`import os\ncommand = 'safe'\ndef launch():\n    os.system(command)\ncommand = request.args['command']\nlaunch()\n`);
 assert.equal(result.findings.find(f=>f.ruleId==='python-os-system')?.evidence,'data_flow');
 const safe=check(`def query(value):\n    return 'constant'\ndef outer(value):\n    def query(value):\n        return value\n    return query(value)\ncursor.execute(query(request.args['id']))\n`);
 assert.deepEqual(safe.findings,[]);
});

test('Python constant branches and session destinations are treated contextually',()=>{
 assert.deepEqual(rules(`if mode:\n    value = '1 + 1'\nelse:\n    value = '2 + 2'\neval(value)\n`),[]);
 const result=check(`import requests as http\nsession = http.Session()\nsession.get(request.args['url'])\n`);
 assert.equal(result.findings.find(f=>f.ruleId==='python-ssrf')?.evidence,'data_flow');
});

test('Python long propagation chains keep both origin and sink in bounded traces',()=>{
 const source=`value0 = request.args['x']\n`+Array.from({length:15},(_,i)=>`value${i+1} = value${i}\n`).join('')+`eval(value15)\n`;
 const issue=check(source).findings.find(f=>f.ruleId==='dynamic-eval');
 assert.ok(issue.trace.length<=10);assert.ok(issue.trace.some(t=>t.kind==='source'));assert.equal(issue.trace.at(-1).kind,'sink');
});

test('Python request parameters expose framework fields without tainting every parameter',()=>{
 const result=check(`import requests\ndef handler(request):\n    requests.get(request.GET['url'])\n`);
 assert.equal(result.findings.find(f=>f.ruleId==='python-ssrf')?.evidence,'data_flow');
 const typed=check(`import requests\ndef handler(incoming: Request):\n    requests.get(incoming.query_params['url'])\n`);
 assert.equal(typed.findings.find(f=>f.ruleId==='python-ssrf')?.evidence,'data_flow');
 assert.deepEqual(rules(`import requests\ndef helper(value):\n    requests.get(value)\n`),[]);
});

test('Python chained assignment propagates the right-hand value to each target',()=>{
 const result=check(`import requests\na = b = request.args.get('url')\nrequests.get(b)\nrequests.get(a)\n`);
 assert.equal(result.findings.filter(f=>f.ruleId==='python-ssrf'&&f.evidence==='data_flow').length,2);
});

test('Python defaults are evaluated at definition and bind missing arguments',()=>{
 const result=check(`import requests\ndef get_url(url=request.args.get('url')):\n    requests.get(url)\nget_url()\n`);
 assert.equal(result.findings.find(f=>f.ruleId==='python-ssrf')?.evidence,'data_flow');
 const atDefinition=check(`def f(value=eval(request.args.get('code'))):\n    pass\n`);
 assert.equal(atDefinition.findings.find(f=>f.ruleId==='dynamic-eval')?.evidence,'data_flow');
 const namedDefault=check(`from flask import render_template_string\nfixed = '<p>fixed</p>'\ndef render(value=fixed):\n    return render_template_string(value)\nrender()\n`);
 assert.deepEqual(namedDefault.findings,[]);
});

test('Python called-only safe helpers are not rescanned as unknown entrypoints',()=>{
 const helper=`from flask import render_template_string\ndef render(value):\n    return render_template_string(value)\nrender('<p>fixed</p>')\n`;
 assert.deepEqual(check(helper).findings,[]);
 const uncalled=check(`from flask import render_template_string\ndef render(value):\n    return render_template_string(value)\n`);
 assert.ok(uncalled.findings.some(f=>f.ruleId==='python-template-injection'));
 const decorated=check(`from flask import render_template_string\n@app.route('/render')\ndef render(value):\n    return render_template_string(value)\nrender('<p>fixed</p>')\n`);
 assert.ok(decorated.findings.some(f=>f.ruleId==='python-template-injection'));
});
