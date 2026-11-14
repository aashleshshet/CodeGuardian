import {test} from 'node:test';
import assert from 'node:assert/strict';
import {analyzeCode} from '../lib/browser-analysis.ts';

const analyze = source => analyzeCode(source, 'python', 'path_review.py');
const prefix = 'from pathlib import Path\nfrom flask import request\n';
for (const [name, source] of [
  ['inline constructor read_text', 'Path(request.args.get("path")).read_text()'],
  ['inline constructor read_bytes', 'Path(request.args.get("path")).read_bytes()'],
  ['inline constructor open', 'Path(request.args.get("path")).open("rb")'],
  ['assigned path receiver', 'selected = Path(request.args.get("path"))\nselected.read_text()'],
  ['constructor import alias', 'from pathlib import Path as FilePath\nFilePath(request.args.get("path")).read_bytes()'],
  ['module alias', 'import pathlib as paths\npaths.Path(request.args.get("path")).open()'],
  ['constructor assigned alias', 'FilePath = Path\nFilePath(request.args.get("path")).read_text()'],
  ['bound method alias', 'selected = Path(request.args.get("path"))\nread = selected.read_text\nread()'],
  ['joinpath retains input', 'Path("/srv/public").joinpath(request.args.get("path")).read_text()'],
  ['division join retains input', 'selected = Path("/srv/public") / request.args.get("path")\nselected.read_bytes()'],
  ['normalization is not containment', 'Path(request.args.get("path")).resolve().read_text()'],
  ['parent path retains provenance', 'Path(request.args.get("path")).parent.read_text()'],
  ['local helper returns path', 'def build(value):\n    return Path("/srv/public") / value\nbuild(request.args.get("path")).open()'],
]) test(`pathlib flow: ${name}`, () => {
  const result = analyze(prefix + source);
  assert.equal(result.coverage.syntax, 'parsed');
  const finding = result.findings.find(finding => finding.cwe === 'CWE-22');
  assert.ok(finding, name);
  assert.equal(finding.evidence, 'data_flow');
  assert.equal(finding.classification, 'potential_vulnerability');
  assert.ok(finding.trace.some(step => step.kind === 'source'));
  assert.ok(finding.trace.some(step => step.kind === 'sink'));
});

for (const [name, source] of [
  ['fixed path read', 'Path("/srv/public/help.txt").read_text()'],
  ['fixed joined segments', '(Path("/srv/public") / "help.txt").read_bytes()'],
  ['fixed normalized path', 'Path("/srv/public/help.txt").resolve().open()'],
  ['tainted content is not a tainted path', 'Path("/srv/public/output.txt").write_text(request.args.get("text"))'],
  ['shadowed constructor', 'def Path(value):\n    return value\nPath(request.args.get("path")).read_text()'],
  ['unrelated application method', 'reader.read_text(request.args.get("text"))'],
]) test(`pathlib safe control: ${name}`, () => {
  const result = analyze(prefix + source);
  assert.equal(result.coverage.syntax, 'parsed');
  assert.ok(!result.findings.some(finding => finding.cwe === 'CWE-22'), JSON.stringify(result.findings));
});
