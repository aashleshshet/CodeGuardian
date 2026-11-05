# API reference

Development OpenAPI: `GET /docs`. The schema remains at `/openapi.json`; interactive docs are disabled in production. The browser uses `/api/backend/*`, a same-origin Next.js proxy. Set `API_URL` only on the Next.js server.

Authenticated routes use the `cg_session` HTTP-only cookie. For non-GET requests also send the exact `Origin` configured as `PUBLIC_URL` and `X-CSRF-Token` from `GET /auth/me`.

| Endpoint | Purpose |
|---|---|
| `GET /health` | Liveness; not a full dependency health check |
| `GET /capabilities` | Non-secret feature configuration |
| `GET /auth/github/start` | Begin App OAuth with state + PKCE |
| `GET /auth/github/callback` | Exchange authorization code and create session |
| `GET /auth/me` | Current login and CSRF token |
| `POST /auth/logout` | Revoke current session |
| `POST /auth/demo` | Explicitly enabled local/test session; absent in production |
| `GET /github/repositories` | Repositories available through user + installation access |
| `GET /repositories` | Owned repositories and scan history |
| `POST /repositories/github` | Import `{full_name, installation_id}` |
| `POST /repositories/upload` | Multipart ZIP + `authorized=true` |
| `POST /repositories/fixture` | Run the bundled fixture through the configured runner |
| `POST /repositories/{id}/scans` | Rescan an authorized GitHub repository or fixture |
| `GET /scans/{id}` | Redacted source, findings, coverage, review state |
| `GET /scans/{id}/compare/{baseline_id}` | Compare two owned scans of the same repository |
| `POST /scans/{id}/findings/{fingerprint}/explanation` | `{use_llm:false}` for curated guidance; true explicitly calls configured provider |
| `POST /scans/{id}/findings/{fingerprint}/patch` | Produce a bounded, untested suggestion |
| `POST /scans/{id}/findings/{fingerprint}/patch/export` | Require `{reviewed:true,digest:"..."}` before download |
| `PATCH /scans/{id}/findings/{fingerprint}/review` | `{status:"open\|confirmed\|dismissed",note:"..."}`; dismissal needs a note |
| `GET /scans/{id}/report?format=json\|sarif` | Redacted security report (no whole source files) |
| `POST /webhooks/github` | Optional signed PR event handler, direct API host only |

## Scan states

`queued → running → completed | partial | failed`

`completed` means all configured analyzers finished without recorded errors. It is not a vulnerability-free certification. Missing analyzers and parser failures produce partial/failed results, with explicit coverage information. Celery hard-killed or abandoned tasks require the maintenance job to move stale states to `failed`.

## Source normalization

`fingerprint`, `engine`, `rule_id`, `severity`, `confidence`, `classification`, `cwe`, `owasp`, `path`, `line`, `end_line`, `snippet`, `message`, `title`, and `status` are present on each finding. Secret candidates never include raw matched values. JSON responses are rendered as text in the frontend, never HTML.

## Errors

401 unauthenticated; 403 CSRF/origin or GitHub authorization failure; 404 resource absent/not owned; 409 review digest mismatch or unsupported rescan; 413 upload limit; 422 invalid source/request/unsupported patch; 429 admission/rate limit; 502/503 unavailable provider or service. Internal scanner exceptions are replaced by a fixed safe message and exception class, never their source-bearing text.
