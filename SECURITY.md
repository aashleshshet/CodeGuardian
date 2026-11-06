# Security model

CodeGuardian reviews authorized source. It is not a guarantee that code is secure and has not received an independent production security audit.

- **Authorization:** OAuth PKCE, expiring single-use state, encrypted user access/refresh tokens, hashed opaque sessions, exact-Origin CSRF checks and per-resource tenant ownership. Installation tokens request only a selected repository and read contents; optional check publishing adds Checks write. No repository write credential is requested.
- **Source intake:** Only GitHub-authorized snapshots or explicitly authorized ZIP uploads. Bounded archive, expansion, file counts and sizes; reject traversal, symlinks and unsafe paths. Never install submitted dependencies, run tests, execute repository scripts or build submitted images.
- **Isolation:** Actual analyzers run in Docker with no network, read-only source/cache/root filesystem, non-root UID, dropped capabilities, no-new-privileges, constrained temporary storage and CPU/memory/process/file/time limits. Worker Docker authority must live on a dedicated host. API containers have no socket. This is OS-container isolation, not a microVM or protection from every kernel/scanner exploit.
- **Secrets:** Gitleaks and built-in patterns identify candidate values. Detected values are masked across source, findings, AI prompts and reports; raw analyzer output stays in private temporary files and is not logged. Upload source is encrypted in PostgreSQL while queued; Redis contains opaque job IDs only. Unknown, split, encoded and novel credentials may be missed. Pattern matches are potential credentials, not verified active secrets.
- **Analyzer integrity:** Application-owned configurations and pinned, checksum-verified executables. Repository rules/ignore configuration do not override the submitted command policy. Unsupported or failed coverage is explicit. Offline vulnerability data is provisioned administratively and freshness is reported; stale/missing data makes coverage incomplete.
- **AI:** Disabled by default, optional local-compatible endpoint; remote HTTPS source sharing requires explicit operator opt-in. Only bounded redacted context and retrieved trusted guidance are supplied. Source/documents are untrusted data, model tools are absent, returned identifiers/citations are checked. Prompt controls reduce risk; they do not prove arbitrary generated prose true. AI never changes the original finding classification.
- **Changes:** Patch suggestions are separate, untested secure-coding suggestions. Export requires a matching digest and human acknowledgement. No repository modification, direct PR creation or automatic merge is implemented.
- **Lifecycle:** Signed raw-body webhooks, unique delivery IDs, durable job keys, atomic claims, admission limits, cancellation and heartbeat recovery. Check summaries are opt-in and default neutral for findings unless the repository explicitly opts into blocking behavior. Fork PRs are skipped.
- **Privacy:** Source expires independently (24 hours default). Historic scans expire after 90 days by default except scans backing latest finding state. Latest evidence persists until repository/account deletion. Revocation purges retained source and stops future authorized imports. Account deletion attempts GitHub grant revocation and reports when remote revocation could not be confirmed; uninstall the App separately in GitHub Settings.
- **Operator duties:** Dedicated scanner daemon, protected encrypted backups, TLS, strong secrets, daily database updates, secure reverse-proxy logging, infrastructure rate limits, resource monitoring, key rotation procedures and real-host isolation checks. Do not expose PostgreSQL/Redis publicly. Do not log OAuth callback queries.

## Reporting a vulnerability

Do not post credentials, private source or exploitation details in public issues. Use GitHub's private vulnerability reporting for this repository if enabled; otherwise contact the repository owner privately to arrange a secure report. Include a minimal synthetic reproducer and the affected version.

The intentionally vulnerable `fixtures/` are test data and must never run as an application. Production images omit the test-only session harness. No production demo login or fixture endpoint exists.

## Dependency review for the connected release

The application self-scan identified advisories in Monaco's DOMPurify and Semgrep's pinned MCP/OpenTelemetry dependencies. The frontend pins DOMPurify 3.4.17, overrides the transitive package and replaces Monaco's separately vendored sanitizer import at build time. Source/diff rendering is covered by browser regression tests; the production bundle is checked for the replacement.

Semgrep 1.183.0 and the inspected 1.184.0 release both constrain MCP 1.29.0 and OpenTelemetry 1.37.x. Forcing incompatible Python dependency versions is not treated as a verified fix. Those scanner dependencies remain a documented residual risk inside the network-disabled scanner image; CodeGuardian does not start Semgrep's MCP server or enable telemetry. API and worker images use the separate runtime requirements and exclude MCP, OpenTelemetry and Semgrep. Keep monitoring upstream compatible releases. The self-scan artifact retains these findings for review; a green functional workflow does not mean zero advisories.

A Gitleaks match in README prose is a reviewed false positive (ordinary text around “secret redaction”), not an active credential. It is preserved in scan output rather than hidden with a repository suppression.
