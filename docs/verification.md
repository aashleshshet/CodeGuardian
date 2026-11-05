# Verification record

Verified locally on 5 November 2026 against the pinned dependency lockfiles.

| Boundary | Evidence |
|---|---|
| Real analysis | Semgrep 1.183.0, Bandit 1.9.4 and built-in secret patterns: 12 current, 15 baseline, 3 resolved findings |
| Backend security | 21 passing tests covering auth, tenant isolation, CSRF, secret redaction, hostile archive paths/links/size limits, model citation rejection, webhook signatures, patch review gate and actual scanner integrations |
| Frontend type safety | `pnpm typecheck` passes |
| Production compilation | Next.js webpack production build passes; no credentials required for fixture mode |
| Browser review workflow | Playwright verifies filters, line-level Monaco, diff viewer, blocked export before acknowledgment, patch/report downloads, themes and mobile overflow |
| Full-stack workflow | Playwright starts FastAPI, uses a development session, invokes actual scanners on the trusted fixture, persists results in SQLite, confirms a finding and verifies persisted state through the API |
| Screenshots | Actual rendered dark/light overview, mobile overview and review/diff screen captured under `.impeccable/review/` |

No real GitHub App, private repository token, external LLM, or production backend credential was supplied. Those live integration flows are implemented but not locally exercised against customer services. Docker is not installed on the local workstation, so the GitHub Actions container smoke check is the executable validation for the isolated runner. Local full-stack testing uses the explicitly restricted trusted-fixture mode and does not demonstrate container isolation.

Development React needs `unsafe-eval` for debugging; production CSP omits it. Webpack is selected explicitly because the local Turbopack build stalled with Monaco's worker bundle; the production webpack build completed successfully.

The deployment is a fixture explorer until `API_URL` points to a configured backend. UI and documentation distinguish this from a connected scanning service. Patches are untested suggestions, reviewed before export, and never applied automatically.
