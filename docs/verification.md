# Verification record

## Private web RAG and detector review — 2026-11-15

The public checker now retrieves the reviewed CWE corpus locally and optionally runs the pinned Qwen2.5 0.5B model through WebLLM in a browser worker. The first model use requires an explicit approximately 300 MB download. Code and questions remain in the tab. Both direct fetch and Cache API downloads are restricted to fixed model assets, then disabled before inference. Cache removal performs no download.

Verification: **142 browser analyzer/RAG/runtime tests**, **11 end-to-end browser scenarios**, TypeScript, Next.js production build and bundled DOMPurify check pass. A real production-build Chromium/Metal WebGPU smoke downloaded the model, generated a CWE-79-cited answer, verified no question/source upload or external requests during inference, and removed all model cache entries. It reported zero page errors. Reproduce with `node scripts/smoke-browser-ai.mjs --download-model`; compatible hardware is required. This is functional generation evidence, not a semantic accuracy benchmark.

The additional 16-case authored detection challenge initially scored 4 TP / 2 FP / 4 FN / 6 TN. After computed-property, bound-function, pathlib, numeric-value and immutable-allowlist fixes, the unchanged set scores **7 TP / 0 FP / 1 FN / 8 TN**: **100% precision, 87.5% recall, 93.75% exact case match**. The original 26-case regression set still passes completely. The 15 single-file cases in the new set pass completely after tuning; the remaining miss depends on product-specific object authorization. Independent review also caught and regression-tested unsafe assumptions around mutable guarded variables and overwritten `Number`. See [all labels, limitations and denominators](accuracy.md); these measurements do not establish 97% accuracy on arbitrary code.


## Parallel motion and local RAG agent — 2026-11-14

The frontend uses application-owned spring tracks inspired by interruptible parallel interactions. It does not embed a OnePlus/OxygenOS SDK. Seven motion tests verify momentum retention, independent tracks, shared frame scheduling, cleanup, reduced motion, hidden tabs and long-frame stability. A 90-frame local Chromium sample during rapid theme/filter switching recorded no frame intervals over 34 ms (95th percentile 19.1 ms); this is a local diagnostic, not a cross-device frame-rate guarantee. No browser page errors were observed.

All 93 browser-analysis/motion unit tests, ten browser regression scenarios, TypeScript and the production build pass. All five public-checker scenarios also pass against the running local production container. The backend suite reports 107 passing tests and one skipped optional five-scanner integration; the real local Docker smoke separately ran all five scanners successfully with 86 findings from the owned fixture.

The smoke used actual Ollama `qwen2.5-coder:1.5b` for both the existing explanation and the new finding-scoped RAG answer. Both returned CWE-89 citations with unchanged evidence classification. The temporary repository was removed afterward. Retrieval tests cover topic anchoring and abstention, and API tests cover authentication, ownership, CSRF and request bounds. Model contract tests cover redaction, untrusted context, unknown citations/identifiers, malformed output and unsupported claims. These checks do not prove arbitrary model prose correct.

The RAG service is available in the on-device `/workspace`; the public Vercel checker remains browser-only and does not send source to the private model. See [RAG operation and limits](rag-agent.md).

## Syntax and input-flow upgrade — 2026-11-14

The public checker now uses pinned Babel and Lezer parsers with application-owned bounded single-file analysis. Findings distinguish traced input flows, structural risks with unconfirmed input origins, and credential patterns. Line-level evidence traces, CWE/OWASP mappings and explicit partial-analysis states are visible in the interface. Source stays in the browser.

The 26-case owned regression corpus includes 14 vulnerable snippets and 12 safe counterparts. The retained lexical baseline detects 3/14 vulnerable snippets and flags 3/12 safe snippets. The new engine detects and traces 14/14 and flags 0/12 safe snippets. This small targeted corpus does not measure general real-world accuracy; it is committed for reproduction with `pnpm benchmark:analysis`.

The analyzer suite has 86 passing tests covering the corpus, aliases, helper returns/default arguments, branch-dependent sanitization, exported handlers, Python chained assignment, secret redaction, malformed source, recursive input and finding limits. Peer review identified six semantic edge cases; regression tests now cover each correction. All nine browser regression scenarios pass, including the preserved full scanner workspace. Production-build checks validate the actual worker, loaded Monaco viewer, trace navigation, review-gated patch export, redacted reports and partial syntax coverage.

The previous repository self-review failed because Semgrep partially parsed a raw JSX ampersand in the checker copy. The text now uses an escaped entity; the pinned Semgrep scan of the changed checker and analyzer modules reports no parse errors. No rule or coverage gate was suppressed. TypeScript, the production build and bundled DOMPurify verification pass. Cross-file logic, runtime authorization and business rules remain outside the browser checker; no claim of exhaustive detection is made.

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
