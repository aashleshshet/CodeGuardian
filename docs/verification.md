# Verification record

## Public browser checker — 2026-11-13

The public `/` route now checks pasted/uploaded code without an account, repository connection or API. The full authenticated scanner workspace moved to `/workspace`, including its OAuth return target. Public results come from actual bounded browser rules, not fabricated findings or a remote model.

| Check | Evidence |
| --- | --- |
| Analyzer contracts | 10 tests pass for positive/negative patterns, comments/literals, language gates, input limits, finding cap, non-execution, redaction and bounded patches |
| Browser regression | All eight scenarios pass: three public-checker flows and five existing full-workspace flows |
| Production policy | All three checker scenarios pass against the production build, including real Web Worker execution and the loaded Monaco viewer under production CSP |
| Privacy/export | Synthetic source is absent from request bodies/URLs and local storage; downloaded JSON excludes the synthetic credential; patch export requires a human acknowledgement |
| Existing login | OAuth state/PKCE/session/logout contract passes with the new `/workspace#integrations` return path |
| Build | Next.js production build, TypeScript and production DOMPurify bundle verification pass |
| Visual finish | Dark results, light empty state, tablet and mobile renders inspected; independent finish review found no material issue; reduced-motion and overflow assertions pass |

The design detector could not run because its engine was unavailable; manual rendered inspection and an independent visual reviewer were used. Evidence is saved under ignored `.cache/screenshots`; the README contains the production-build checker screenshot. Browser checks do not execute Semgrep/Bandit or an LLM and cannot establish exploitability or complete security coverage. See [checker behavior and reproduction](code-checker.md).

## Device-only installation — 2026-11-12

The current installation runs at `http://localhost:3000` on the user's Mac, using a project-scoped Lima VM and Docker Compose. No Oracle host or cloud backend was provisioned. The existing Vercel deployment remains separate and has not been connected to this private local stack.

| Check | Evidence |
| --- | --- |
| Service readiness | FastAPI reports database, current Alembic schema, Redis queue and Celery worker ready; PostgreSQL, Redis and Ollama are healthy |
| Local authentication | Real access-key login, opaque session, CSRF, logout and persisted results after a fresh login verified through HTTP; browser login and archive upload verified |
| Scanner isolation | Actual local Docker worker ran Semgrep, Bandit, Gitleaks, OSV-Scanner and Trivy on the owned 11-file fixture; all five completed with 86 normalized findings and complete coverage |
| Offline databases | Administrative download repaired and tested; failed downloads preserve the last successful cache; scans use the private offline cache |
| Local AI | Real Ollama `qwen2.5-coder:1.5b` responses displayed in the production browser for dependency and SQL injection findings, with CWE-89 citations and unchanged analyzer classifications |
| Evidence separation | Analyzer messages remain visible when AI output arrives; remediation retains curated CWE guidance or scanner-reported fix versions; no repository changes or automatic patches occur |
| Local network boundary | Browser verification observed no external HTTP requests; model/API/database/worker have no published ports and use the internal Docker network; only the frontend publishes `127.0.0.1:3000` |
| Automated tests | 81 backend tests passed, including real analyzers and 18 local-AI contract tests; five browser scenarios passed, including evidence separation, masked local login, Monaco, human patch approval and report download |
| Build | TypeScript passed and the local Next.js production container build completed successfully |

The browser check uses only the owned vulnerable fixture and removes its imported repository afterward. Local evidence and screenshots are under the ignored `.cache/local` and `.cache/screenshots` directories. Credentials stay in owner-only local files and are not included in those reports. Reproduce the HTTP/worker/model flow with `scripts/local_setup.py smoke`; see [local operation](local.md) for startup, shutdown and cache refresh commands.

Model output remains review material. Contract checks reject malformed JSON, unknown citations/advisory identifiers, unsupported dependency versions and specific unsupported exploitability assurances; they do not establish the truth of arbitrary generated prose. Generated fixes are never applied automatically. Live GitHub App login, private-repository authorization, cloud checks and remote-model providers remain unconfigured and unverified for this installation.

## Earlier cloud preparation

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

At the time of these earlier cloud checks, Docker and a model endpoint were unavailable on the workstation. The device-only verification above supersedes those local limitations. Cloud backend and GitHub App activation still require the smoke tests in [deployment.md](deployment.md). Mocked GitHub/model tests validate application contracts, not external service configuration.

The advanced `/workspace` route has no fabricated fallback data. Without a configured API, it presents a service-setup notice. The public `/` checker now works independently of that API. The test harness resides only in `backend/tests/e2e_app.py`, refuses non-test environments and is excluded from production images.

Reproduce checks using the commands in [README.md](../README.md). Keep the scanner-data manifest when comparing advisory results: public databases evolve independently of the pinned executable versions.
