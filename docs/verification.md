# Verification record

Upgrade verification on 2026-11-06/07:

Production connection follow-up on 2026-11-07: the existing `codeguardian-ai` Vercel project serves `https://codeguardianxweb.vercel.app`, but had no environment variables configured. Its API proxy returned 503 because `API_URL` was absent. No backend host or GitHub App credentials were supplied. The targeted follow-up reads frontend configuration at request time, gates sign-in on service readiness, adds migration-aware independent readiness probes and supports one-worker deployment on smaller hosts. Local checks pass: **50 backend tests**, including all five real analyzers; **4 browser scenarios**; TypeScript, production build and the bundled sanitizer check. These tests do not establish a connected production backend. A host is still being selected; no paid infrastructure was provisioned.

| Check | Evidence |
| --- | --- |
| Python suite | 47 passing tests, including real analyzer processes, auth/lifecycle/security, cache throttling and migration preservation |
| Real analyzers | Semgrep, Bandit, Gitleaks 8.30.1, OSV-Scanner 2.7.0 and Trivy 0.76.2 all completed on the owned vulnerable fixture; secret-value absence asserted |
| Offline data | Official npm/PyPI OSV databases and Trivy databases/checks downloaded administratively; manifest records hashes and update time |
| Browser suite | Three end-to-end scenarios passed: honest landing/theme/mobile/reduced-motion; empty account/settings; real persisted evidence/Monaco/triage/human patch gate/report download |
| Migration | Fresh SQLite and PostgreSQL migrations pass; populated SQLite 001→002 test preserves imported evidence and removes explicitly marked fixtures |
| Docker isolation | GitHub Actions ran all five analyzers using the actual network-disabled, resource-limited scanner command successfully |
| Visual review | Captured dark/light landing, real-data workspace, source/diff review and mobile layouts; images inspected directly |

The initial upgrade CI run passed PostgreSQL, all application tests and the offline Docker fixture scan. Its self-review uncovered JSX parser warnings and dependency advisories; the follow-up escapes JSX text, patches the bundled sanitizer and separates scanner-only dependencies from the API image. The workflow creates a CodeGuardian self-review artifact. Consult the run for this commit for the current CI result. Self-review artifacts surface findings for review and do not certify vulnerability-free dependencies.

Docker is unavailable on the local workstation; local exact-fixture execution is test-only and does not establish container isolation. A live backend host has not been selected. No production GitHub App credentials, private-repository authorization or local/remote model endpoint was supplied. Those live paths require the activation smoke tests in [deployment.md](deployment.md). Mocked GitHub/model tests validate application contracts, not external service configuration.

The Vercel frontend has no fabricated fallback data. Without a configured API, it presents a service-setup notice. The test harness resides only in `backend/tests/e2e_app.py`, refuses non-test environments and is excluded from production images.

Reproduce checks using the commands in [README.md](../README.md). Keep the scanner-data manifest when comparing advisory results: public databases evolve independently of the pinned executable versions.
