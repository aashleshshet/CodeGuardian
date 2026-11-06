# API

The browser uses `/api/backend/*`; the Next.js route proxies to server-only `API_URL`. Direct API endpoints are identical without that prefix. Authenticated mutations require `cg_session`, matching `Origin` and `X-CSRF-Token` from `/auth/me`. IDs are tenant-authorized, never authorization by possession.

| Endpoint | Purpose |
| --- | --- |
| `GET /health`, `GET /ready` | Liveness; DB/broker/worker readiness |
| `GET /capabilities` | Actual configured feature availability |
| `GET /auth/github/start`, `GET /auth/github/callback` | PKCE OAuth, one-use state and session |
| `GET /auth/me`, `POST /auth/logout` | Identity/CSRF; session termination |
| `GET /github/installations`, `POST /github/sync` | Installation status and authorized metadata synchronization |
| `GET /github/repositories` | Repositories accessible to the user and App |
| `POST /repositories/github` | Connect `{full_name, installation_id}` without starting a scan |
| `GET /repositories?offset=0&limit=50` | Owned repositories with latest scan summaries; maximum 100 |
| `GET /repositories/{id}/branches?page=1` | Authorized branch page (100) |
| `GET /repositories/{id}/commits?branch=main&page=1` | Authorized commit page (30) |
| `GET /repositories/{id}/scans?offset=0&limit=30` | Paginated scan history |
| `POST /repositories/{id}/scans` | Queue `{branch, ref}` at a resolved commit |
| `POST /repositories/upload` | ZIP multipart `file` and `authorized=true` |
| `PATCH /repositories/{id}` | Automation, schedule and explicit check policy |
| `DELETE /repositories/{id}` | Remove repository and associated stored data |
| `GET /scans/{id}`, `GET /scans/{id}/compare/{baseline_id}` | Redacted source/evidence and reliable baseline comparison |
| `POST /scans/{id}/cancel`, `POST /scans/{id}/retry` | Cancel; bounded retry of failed/partial GitHub scans |
| `POST /scans/{id}/findings/{fingerprint}/explanation` | `{use_llm:false}` curated or configured model guidance |
| `POST /scans/{id}/findings/{fingerprint}/patch` | Bounded, unapplied suggestion; unavailable rules return a reason |
| `POST /scans/{id}/findings/{fingerprint}/patch/export` | Require `{digest, reviewed:true}` and audit export |
| `PATCH /scans/{id}/findings/{fingerprint}/review` | `{status:open|confirmed|dismissed,note}` durable triage |
| `GET /scans/{id}/report?format=json|sarif|md` | Redacted security report |
| `GET /dashboard` | Persisted counts, activity and per-scan trend |
| `GET/PATCH /preferences` | In-app notification preferences |
| `GET /notifications`, `PATCH /notifications/{id}` | Notifications and read status |
| `DELETE /github/connection`, `DELETE /account` | Revoke connection/purge data; full account deletion |
| `POST /webhooks/github` | Bounded raw body, HMAC signature and delivery deduplication |

A 401 means reauthenticate; 403 means access denied/revoked; 409 indicates state/configuration conflicts; 410 indicates expired source; 429 includes retry guidance for GitHub throttling; 503 signals temporary service/capacity failure. Unexpected errors expose only a generic message and request ID. Production has no fixture import or test login endpoint.
