# Private browser code checker

Open `/`, paste code or choose one `.py`, `.js`, `.jsx`, `.ts` or `.tsx` file, and select **Check code**. No account, repository connection, backend service or model is required. The language can be changed explicitly. Files are limited to 200 KiB; binary files and unsupported extensions are rejected.

The checker parses JavaScript/TypeScript with the [Babel parser](https://babeljs.io/docs/babel-parser) and Python with [Lezer](https://github.com/lezer-parser/python), then runs application-owned structural and bounded single-file data-flow checks. It follows selected external inputs through assignments, imported API aliases, multiline expressions, branch joins and local helper calls. Nothing is executed. Rules cover dynamic SQL at execution sites, command injection, HTML/template insertion, SSRF, path traversal, redirects, unsafe deserialization, credential formats and selected TLS/cryptographic settings.

Known input-to-operation paths display a line-by-line trace. Dynamic operations with an unconfirmed source are labeled structural risks. Credential formats use pattern evidence. No result is represented as a verified exploitable vulnerability. Trusted HTML sanitization is recognized only for its HTML context, and bound SQL values do not excuse an already-interpolated query.

This is not whole-program or path-sensitive analysis. Cross-file dependencies, runtime behavior, authentication/authorization design, business rules, full object aliasing and every framework API are not modeled. There are false positives and false negatives. Parse errors and traversal/call limits show **Partial analysis**; the worker has a 15-second deadline. Best-effort pattern checks are retained on invalid syntax. A zero-result check never establishes security. Semgrep, Bandit and the other full repository scanners remain in the local workspace.

Results contain a line reference, severity, CWE, explicit OWASP Top 10:2021 mapping where applicable, evidence type, explanation, suggested remediation and conditions to verify. Trace steps navigate the source viewer. Unknown mappings stay unmapped. Credential values detected by the bounded patterns are masked in the source viewer and exported JSON. Unknown, encoded, concatenated and novel secret formats can be missed. Results are capped at 100 findings, with a visible notice when an analysis or finding budget is reached.

Some findings offer a narrowly scoped proposed change. Review the original, proposed line and semantic caveat, then acknowledge the review before exporting its diff. A patch is not generated when a credential is detected in the file. Nothing is applied automatically. Editing, clearing or replacing source discards the prior findings and patch approval, and cancels any pending worker.

Source and results remain in tab memory. The application has no source-upload request, source persistence, telemetry or model call in this flow. Only the theme preference uses local storage. Downloading a report or reviewed patch saves it to the user's device. Refreshing or closing the tab discards the working source.

## Interface

The editor and evidence share equal-width panes on desktop and stack on narrow screens. Centered navigation, appearance controls and severity filters use pill-shaped selections; the active finding includes a check indicator. The charcoal/sage palette, Public Sans and IBM Plex Mono sit within restrained liquid-glass chrome with static Gaussian backdrop blur and independently interruptible spring transitions. Selection capsules retain momentum during rapid inputs; source and result containers are never blurred during motion. Code stays crisp on an opaque surface. Light mode uses pale mineral surfaces. Motion respects `prefers-reduced-motion`; reduced-transparency settings use opaque chrome. Controls include accessible selected states, visible keyboard focus and an editor skip link. `Ctrl/Cmd + Enter` runs a check.

The example loads only when requested and is intentionally unsafe. Its findings are computed by the same worker used for user input. Severity filtering, source highlighting, report export and the human review gate operate on the actual result.

## Reproduce verification

```sh
pnpm test:browser-analysis
pnpm benchmark:analysis
pnpm test:e2e
pnpm build
```

The public checker tests can also target a running production build or public deployment without starting test servers:

```sh
CHECKER_TEST_URL=https://codeguardianxweb.vercel.app pnpm exec playwright test tests/e2e/checker.spec.ts
```

These browser tests use synthetic source only, check the worker results and redacted download, require review before patch export, verify that no API request/source transmission occurs, and cover dark/light/mobile/tablet layouts. The full scanner and local AI installation remains at `/workspace`; see [local operation](local.md).

## Targeted detection benchmark

The owned corpus in `tests/fixtures/browser-flow-cases.json` contains 14 vulnerable snippets and 12 safe counterparts, covering both language engines. `benchmark:analysis` compares the retained lexical fallback with the syntax/flow engine and exits unsuccessfully if the current engine misses an expected weakness, flags a safe counterpart or reports partial parsing. On this corpus, the lexical baseline detects 3/14 vulnerable examples and flags 3/12 safe examples; the new engine detects and traces 14/14 and flags 0/12 safe examples. These figures measure this small regression set only, not general real-world accuracy. Unique engine tests additionally exercise aliases, branch sanitization, helper scopes, parse failures and resource limits.

OWASP categories explicitly use the [2021 taxonomy](https://owasp.org/Top10/2021/) to match the existing scanner workspace; they do not imply certification or coverage of every category.
