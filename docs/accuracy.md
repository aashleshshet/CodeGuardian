# Detection quality and the 97% target

**CodeGuardian does not currently establish 97% accuracy on arbitrary code.** A passing regression suite does not measure coverage of all vulnerabilities. The browser checker performs bounded, single-file static analysis; its findings need human review. The private RAG agent explains evidence and retrieved guidance, but does not make the analyzer more accurate merely by generating an answer.

Initial measurements on 14 November 2026 against browser analyzer `2026.11.13-flow.1` (before the fixes below):

| Corpus | Cases | True positives | False positives | False negatives | True negatives | Precision | Recall | F1 | Exact case match |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Existing regression corpus | 26 | 14 | 0 | 0 | 12 | 100% | 100% | 100% | 100% |
| Additional authored challenge corpus | 16 | 4 | 2 | 4 | 6 | 66.7% | 50.0% | 57.1% | 62.5% |
| Challenge single-file pattern subset | 15 | 4 | 2 | 3 | 6 | 66.7% | 57.1% | 61.5% | 66.7% |

These are small, synthetic, application-owned corpora. The first was developed with the analyzer and mainly protects known behavior. The second was authored after implementation to expose additional blind spots; it is not an independent, representative production benchmark. Its source and labels remain visible in the evaluator, including misses. The single-file subset excludes the business-authorization case, which is explicitly outside the checker's advertised scope; it still deliberately exercises known unsupported alias and syntax forms. No score should be marketed as general accuracy. These numbers are the initial pre-fix baseline: retain them when adding a tuned retest, and evaluate future generalization on new examples.

## Retest after targeted fixes

Retested on 15 November 2026, analyzer `2026.11.14-flow.2` resolves constant computed properties and bound calls, tracks pathlib receivers, recognizes primitive numeric SQL values, and narrows pure strict-equality allowlists on immutable bindings within their matching branch. The original labels and cases are unchanged. Targeted tests include shadowing, reassignment, unsafe guard bypasses, unknown computed writes, partial binds and fixed-path controls.

| Corpus | TP | FP | FN | TN | Precision | Recall | F1 | Exact case match |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Existing 26-case regression corpus | 14 | 0 | 0 | 12 | 100% | 100% | 100% | 100% |
| Same 16-case challenge, now used for development | 7 | 0 | 1 | 8 | 100% | 87.5% | 93.3% | 93.75% |
| Same 15-case single-file subset | 7 | 0 | 0 | 8 | 100% | 100% | 100% | 100% |

The remaining challenge miss is policy-dependent object authorization. The 16-case exact-match score is below 97%. The smaller subset passes completely, but it is now a tuned regression set; neither result supports a 97% generalization claim. Additional independent project-level evaluation remains necessary.

## Reproduce and interpret

```sh
pnpm benchmark:analysis
node --experimental-strip-types scripts/evaluate-holdout.mjs
```

The regression inputs are in `tests/fixtures/browser-flow-cases.json`. The additional challenge inputs are in `scripts/evaluate-holdout.mjs`; despite the filename, they are an authored challenge set, not a statistically independent holdout dataset. The challenge command is diagnostic and deliberately returns success even when it reports misses. It is not a release gate.

For these examples, a true positive is a predicted expected CWE, counted once per case. A missing expected CWE is a false negative; an extra CWE is a false positive. A case with no expected findings and no predicted findings is a true negative. Precision is `TP / (TP + FP)`, recall is `TP / (TP + FN)`, and F1 is `2TP / (2TP + FP + FN)`. Exact case match means all expected CWE labels, with no extra labels, divided by the number of cases. In this run, each positive case has one label and each negative case has none. These are label-level measurements, not proof that an exploit is reachable at runtime.

## What the challenge set exposed

| Case | Observed result | Review implication |
| --- | --- | --- |
| DOM property selected through a constant variable | Initially missed CWE-79; now detected | Constant computed names are modeled; dynamic names remain a coverage limitation. |
| `child.exec.bind(child)` called with request input | Initially missed CWE-78; now detected | Bound imported methods and prebound arguments are modeled within analysis limits. |
| `Path(request.args.get("path")).read_text()` | Initially missed CWE-22; now detected | Known pathlib constructors and receiver transformations retain input provenance. |
| Invoice lookup with no visible ownership check | Missed CWE-862 | This label assumes private invoices and no downstream authorization. Product policy and cross-layer enforcement cannot be inferred from this snippet alone. |
| SQL built from a checked integer | Initially flagged CWE-89; now clear | Primitive Number conversion cannot contribute arbitrary SQL syntax; this does not certify query correctness. |
| Redirect guarded by two fixed local destinations | Initially flagged CWE-601; now clear | Pure strict literal-equality guards narrow only their matching branch; general validation is not proven. |

The challenge set also checks asynchronous SQL helpers, object-carried HTML, Python subprocess aliases and percent-formatted SQL, plus eight negative controls. None produced a parser failure in this run. Negative controls establish absence of the labeled weakness in these snippets; they are not an assertion that a complete application is secure.

## How to evaluate a 97% goal honestly

Use **precision and recall as separate targets**, not one ambiguous accuracy number. A checker can appear accurate by missing rare vulnerabilities in a mostly benign dataset. Before making a public target claim:

1. Freeze the evaluated analyzer version, supported languages, frameworks and CWE scope.
2. Assemble a substantially larger, independently labeled set with vulnerable cases and realistic safe controls. Keep evaluation examples separate from development examples, and split by project to avoid near-duplicate leakage.
3. Record disagreements and contextual assumptions; adjudicate labels with a security reviewer. Include unsupported and ambiguous cases in a separately reported coverage category rather than silently discarding them.
4. Measure precision, recall, F1 and uncertainty by language and weakness class as well as overall. A point estimate of 97% from a small set does not establish a 97% underlying rate.
5. Freeze thresholds before evaluation. Keep misses and false positives visible, add fixes to regression tests, then evaluate again on new examples.

The optional isolated backend scanners have different coverage and must be evaluated separately. Results from this browser benchmark cannot be transferred to Semgrep, Bandit, secret scanners, dependency scanners or their combined output.

## RAG quality is a separate measurement

Browser RAG tests verify retrieval relevance, abstention, secret masking, bounded prompts, citation membership and rejection of selected unsupported claims. These checks do not establish semantic correctness of generated prose. Generated answers remain labeled as AI interpretations requiring review. Evaluate answer correctness, evidence support, useful remediation and abstention with independently reviewed questions; do not combine a citation-validation pass rate with vulnerability-detection recall.
