# Private browser code checker

Open `/`, paste code or choose one `.py`, `.js`, `.jsx`, `.ts` or `.tsx` file, and select **Check code**. No account, repository connection, backend service or model is required. The language can be changed explicitly. Files are limited to 200 KiB; binary files and unsupported extensions are rejected.

The checker runs application-owned lexical rules in a dedicated Web Worker. It inspects patterns without executing source. Rules cover selected injection and dynamic execution patterns, credential formats, unsafe deserialization, TLS verification settings and weak hashing. Comments and quoted string contents are masked for code-pattern rules. This is not a parser, interprocedural data-flow analysis, dependency audit, Semgrep/Bandit scan, or AI assessment. There are false positives and false negatives. A zero-result check does not establish security.

Results contain a line reference, severity, CWE, explanation, suggested remediation and conditions to verify. Credential values detected by the bounded patterns are masked in the source viewer and exported JSON. Unknown, encoded, concatenated and novel secret formats can be missed. Results are capped at 100 findings, with a visible notice when that limit is reached.

Some findings offer a narrowly scoped proposed change. Review the original, proposed line and semantic caveat, then acknowledge the review before exporting its diff. A patch is not generated when a credential is detected in the file. Nothing is applied automatically. Editing, clearing or replacing source discards the prior findings and patch approval, and cancels any pending worker.

Source and results remain in tab memory. The application has no source-upload request, source persistence, telemetry or model call in this flow. Only the theme preference uses local storage. Downloading a report or reviewed patch saves it to the user's device. Refreshing or closing the tab discards the working source.

## Interface

The editor and evidence form one split workspace on desktop and stack on narrow screens. The established charcoal/sage palette, Public Sans and IBM Plex Mono are retained, with a translucent navigation surface, fine borders, scan motion and short result transitions. Light mode uses pale mineral surfaces. Motion respects `prefers-reduced-motion`; controls include visible keyboard focus and an editor skip link. `Ctrl/Cmd + Enter` runs a check.

The example loads only when requested and is intentionally unsafe. Its findings are computed by the same worker used for user input. Severity filtering, source highlighting, report export and the human review gate operate on the actual result.

## Reproduce verification

```sh
pnpm test:browser-analysis
pnpm test:e2e
pnpm build
```

The public checker tests can also target a running production build or public deployment without starting test servers:

```sh
CHECKER_TEST_URL=https://codeguardianxweb.vercel.app pnpm exec playwright test tests/e2e/checker.spec.ts
```

These browser tests use synthetic source only, check the worker results and redacted download, require review before patch export, verify that no API request/source transmission occurs, and cover dark/light/mobile/tablet layouts. The full scanner and local AI installation remains at `/workspace`; see [local operation](local.md).
