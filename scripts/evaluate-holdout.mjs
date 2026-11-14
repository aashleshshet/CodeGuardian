// Additional authored challenge cases. These are synthetic, not an independent
// industry benchmark or a statistical sample of production vulnerabilities.
// Keep the labels and missed cases visible; never drop a case to improve a score.
import { analyzeCode } from '../lib/browser-analysis.ts';

export const cases = [
  {name: 'computed DOM write', language: 'javascript', expected: ['CWE-79'], source: 'const property = "innerHTML";\ndocument.body[property] = location.hash;'},
  {name: 'bound command method', language: 'typescript', expected: ['CWE-78'], source: 'import * as child from "node:child_process";\nconst run = child.exec.bind(child);\nrun(req.query.command);'},
  {name: 'object property carries HTML', language: 'javascript', expected: ['CWE-79'], source: 'const state = {};\nstate.html = location.hash;\ndocument.body.innerHTML = state.html;'},
  {name: 'awaited SQL helper', language: 'typescript', expected: ['CWE-89'], source: 'async function build(value: string) { return "SELECT * FROM users WHERE id=" + value; }\nasync function handler(req: any) {\n const query = await build(req.query.id);\n db.query(query);\n}'},
  {name: 'Python pathlib instance path', language: 'python', expected: ['CWE-22'], source: 'from pathlib import Path\nfrom flask import request\nPath(request.args.get("path")).read_text()'},
  {name: 'Python subprocess attribute alias', language: 'python', expected: ['CWE-78'], source: 'import subprocess\nfrom flask import request\nrun = subprocess.run\nrun(request.args.get("command"), shell=True)'},
  {name: 'Python SQL percent formatting', language: 'python', expected: ['CWE-89'], source: 'from flask import request\nquery = "SELECT * FROM users WHERE id=%s" % request.args.get("id")\ncursor.execute(query)'},
  {name: 'missing per-object authorization', language: 'typescript', category: 'product_policy', expected: ['CWE-862'], source: 'app.get("/invoices/:id", requireLogin, async (req, res) => {\n const invoice = await db.invoice.findUnique({where: {id: req.params.id}});\n res.json(invoice);\n});', note: 'Assumes invoices are private to an owner and no downstream ownership check; a source-only checker cannot establish that product policy.'},
  {name: 'fixed text DOM write', language: 'javascript', expected: [], source: 'document.body.textContent = location.hash;'},
  {name: 'numeric SQL interpolation', language: 'typescript', expected: [], source: 'const id = Number(req.query.id);\nif (Number.isSafeInteger(id)) db.query("SELECT * FROM users WHERE id=" + id);', note: 'SQL-injection label only: the interpolated value is a checked integer.'},
  {name: 'Python static parameterized SQL', language: 'python', expected: [], source: 'from flask import request\ncursor.execute("SELECT * FROM users WHERE id=%s", (request.args.get("id"),))'},
  {name: 'Python fixed path read', language: 'python', expected: [], source: 'from pathlib import Path\ncontent = Path("/srv/public/help.txt").read_text()'},
  {name: 'validated redirect allowlist', language: 'javascript', expected: [], source: 'const destination = req.query.next;\nif (destination === "/home" || destination === "/profile") res.redirect(destination);', note: 'Only the two fixed local destinations reach the redirect.'},
  {name: 'constant shell-free subprocess', language: 'python', expected: [], source: 'import subprocess\nsubprocess.run(["/usr/bin/printf", "%s", "hello"], shell=False)'},
  {name: 'sanitized HTML', language: 'typescript', expected: [], source: 'import DOMPurify from "dompurify";\ndocument.body.innerHTML = DOMPurify.sanitize(location.hash);'},
  {name: 'ordinary arithmetic', language: 'python', expected: [], source: 'def square(number):\n    return number * number\n'},
];

let tp = 0, fp = 0, fn = 0, tn = 0, partial = 0;
const rows = cases.map(entry => {
  const result = analyzeCode(entry.source, entry.language, entry.language === 'python' ? 'challenge.py' : 'challenge.ts');
  const predicted = [...new Set(result.findings.map(finding => finding.cwe))];
  const matched = entry.expected.filter(cwe => predicted.includes(cwe));
  const missed = entry.expected.filter(cwe => !predicted.includes(cwe));
  const extra = predicted.filter(cwe => !entry.expected.includes(cwe));
  tp += matched.length; fn += missed.length; fp += extra.length;
  if (!entry.expected.length && !predicted.length) tn++;
  if (result.coverage.syntax === 'partial') partial++;
  return { name: entry.name, language: entry.language, category: entry.category || 'single_file_pattern', expected: entry.expected, predicted, missed, extra, ...(entry.note ? {note: entry.note} : {}) };
});
const ratio = (n, d) => d ? Number((n / d).toFixed(6)) : null;
const patternRows = rows.filter(row => row.category === 'single_file_pattern');
const patternTP = patternRows.reduce((sum, row) => sum + row.expected.length - row.missed.length, 0);
const patternFN = patternRows.reduce((sum, row) => sum + row.missed.length, 0);
const patternFP = patternRows.reduce((sum, row) => sum + row.extra.length, 0);
console.log(JSON.stringify({
  scope: 'Authored 16-case challenge corpus; not a representative accuracy claim. CWE labels scored once per case. Extra CWE labels count as false positives.',
  cases: cases.length, positiveCases: cases.filter(c => c.expected.length).length, negativeCases: cases.filter(c => !c.expected.length).length,
  tp, fp, fn, tn, partial,
  precision: ratio(tp, tp + fp), recall: ratio(tp, tp + fn), f1: ratio(2 * tp, 2 * tp + fp + fn),
  exactCaseMatch: ratio(rows.filter(row => !row.missed.length && !row.extra.length).length, cases.length),
  singleFilePatternSubset: {
    scope: 'Excludes product-policy authorization, which is outside advertised scope. Still challenges known unsupported syntax/data-flow constructs.',
    cases: patternRows.length, tp: patternTP, fp: patternFP, fn: patternFN,
    tn: patternRows.filter(row => !row.expected.length && !row.predicted.length).length,
    precision: ratio(patternTP, patternTP + patternFP), recall: ratio(patternTP, patternTP + patternFN),
    f1: ratio(2 * patternTP, 2 * patternTP + patternFP + patternFN),
    exactCaseMatch: ratio(patternRows.filter(row => !row.missed.length && !row.extra.length).length, patternRows.length),
  }, rows,
}, null, 2));
// This is diagnostic, not a release gate. Document misses instead of hiding them.
