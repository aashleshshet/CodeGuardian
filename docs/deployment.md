# Deployment

## 1. Vercel frontend

Import `aashleshshet/CodeGuardian` as a **new** Vercel project using the Next.js framework, repository root, Node.js 22, install `pnpm install --frozen-lockfile`, and build `pnpm build`. `vercel.json` supplies the build configuration.

The frontend deploys without service credentials and initially exposes only the redacted, reproducible fixture explorer. It clearly labels fixture results and directs users to connect the review service before imports/new scans. Do not call this state a connected production scanner.

Set **server-only** `API_URL=https://api.your-domain.example` in Vercel after the backend is reachable, then redeploy. Never use `NEXT_PUBLIC_` for this value or any credential. Backend `PUBLIC_URL` must exactly match the canonical Vercel/custom origin to pass CSRF checks. Use a stable deployment domain for OAuth callbacks; arbitrary preview URLs will not pass the production origin policy.

## 2. Dedicated container host

Use a Linux host with Docker Engine/Compose, preferably a rootless daemon. The worker needs Docker CLI/daemon access to create restricted scanner containers. The API must never have socket access. Use a dedicated host; daemon access is powerful even though individual scanner containers are constrained.

```bash
cp .env.example .env
mkdir -p data/jobs
```

Populate `.env` locally or through a secret manager:

```dotenv
ENVIRONMENT=production
PUBLIC_URL=https://your-project.vercel.app
SECRET_KEY=<random 48-byte-url-safe value>
TOKEN_ENCRYPTION_KEY=<Fernet key>
POSTGRES_PASSWORD=<generated URL-safe database password>
SCANNER_JOBS_DIR=/absolute/path/to/CodeGuardian/data/jobs
WORKER_UID=<UID that owns the job directory>
DOCKER_GID=<group allowed to access the Docker socket>
DOCKER_SOCKET=/var/run/docker.sock
SCANNER_MODE=docker
TASKS_EAGER=false
ALLOW_DEMO_LOGIN=false
```

Use the same absolute staging path on the worker and Docker host. Bind mounts are resolved by the daemon, not by the worker's container namespace. For rootless Docker, set `DOCKER_SOCKET` to the rootless socket path and grant only the worker identity access. Set staging-directory ownership to the worker UID. Do not loosen permissions on the Docker socket for the API or other users.

Generate keys **locally**; do not paste them into chat or commit them:

```bash
.venv/bin/python -c 'import secrets; print(secrets.token_urlsafe(48))'
.venv/bin/python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'
```

Build the scanner image before accepting jobs, then start the services:

```bash
docker build -f backend/Dockerfile --target scanner -t codeguardian-scanner:local .
docker compose up --build -d
docker compose ps
curl http://127.0.0.1:8000/health
```

Compose waits for PostgreSQL, runs Alembic migrations, then starts API and workers. Redis/PostgreSQL have no published ports. Only the API binds to host loopback. Put a TLS reverse proxy in front of it with a 10 MB upload cap, rate limits, appropriate timeouts and body/credential logging disabled. Allow GitHub to reach `/webhooks/github` only if checks are enabled. Configure database and Redis authentication/TLS explicitly if either leaves the private single-host network.

Run maintenance on a schedule:

```bash
docker compose exec api python scripts/maintenance.py
```

The container includes the maintenance script. Review scan staging leftovers after hard worker crashes, excluding active jobs. Use a secret manager and encrypted backups. See [SECURITY.md](../SECURITY.md).

## 3. GitHub App

Create your own GitHub App:

- Homepage: canonical frontend URL.
- Callback: `https://your-project.vercel.app/api/backend/auth/github/callback`.
- Repository permissions: **Metadata: read**, **Contents: read**.
- Optional checks: **Checks: write**; subscribe to `pull_request` and set a webhook secret.
- Do **not** grant contents write, pull requests write, actions write, or administration permissions.
- Install on selected repositories. User authorization and installation access must both permit the repository.

Set `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, `GITHUB_APP_ID`, `GITHUB_APP_SLUG`, and `TOKEN_ENCRYPTION_KEY`. For checks also set `GITHUB_PRIVATE_KEY` (PEM, escaped newlines supported), `GITHUB_WEBHOOK_SECRET`, and `GITHUB_CHECKS_ENABLED=true`. Webhook URL is the **API host** `/webhooks/github`, not the Next.js BFF; the BFF intentionally does not forward webhook authentication headers.

The OAuth user token is encrypted in PostgreSQL. The MVP requires reconnection after token expiration; it does not store/refresh long-lived refresh tokens. PR checks use short-lived, repository-scoped installation tokens. Fork heads are skipped. All repository writes remain outside the application.

Relevant contracts: [GitHub App user tokens](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-user-access-token-for-a-github-app), [installation access](https://docs.github.com/en/rest/apps/installations), [webhook validation](https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries).

## 4. Optional LLM provider

Set `LLM_ENABLED=true`, `LLM_BASE_URL`, `LLM_API_KEY` and `LLM_MODEL` on the API service only. The provider must implement `/chat/completions` with JSON object responses. No provider or model is silently selected. Without these variables, curated CWE guidance works normally.

Requests contain redacted findings and a small source excerpt. Repository documentation is never placed into trusted instructions. Responses must match the schema and cite retrieved CWE IDs. Source privacy, gateway logging and provider retention are operator decisions; approve them before enabling LLM egress. There is no remote tool invocation or AI patch application.

## 5. Release verification

1. Run backend tests, TypeScript checking, production build, Playwright, and the Docker scanner CI check.
2. Verify `/health`, sign in, import a repository you control, and confirm the exact SHA and engines in the UI.
3. Verify missing permissions fail closed; revoke access and confirm subsequent imports fail.
4. Inspect a secret fixture value: source, report and AI request must show a redaction.
5. Review a supported patch and confirm export is disabled until acknowledgment; no branch or PR should be created.
6. Enable optional checks on a test repository and confirm high evidence yields action required, partial coverage never yields success, and unsigned webhooks are rejected.

GitHub/LLM live flows and Docker isolation must be validated with your actual deployment credentials/runtime. Unit tests and local fixture execution do not substitute for those checks.

## Troubleshooting

| Symptom | Check |
|---|---|
| Fixture works, imports do not | `API_URL`, backend availability, GitHub App settings and current session |
| Scan stays queued | Redis/worker health; expired jobs are marked failed by maintenance |
| Docker runner fails | Scanner image exists; worker daemon access; matching absolute job mount path; host capacity |
| Semgrep unavailable locally on macOS | The runner sets `SSL_CERT_FILE` to certifi's CA bundle; use the project venv and put its `bin` on PATH |
| CSRF rejected | Backend `PUBLIC_URL` exactly matches frontend origin and current CSRF token |
| No AI button | LLM settings are intentionally disabled or incomplete |
| No patch for a finding | Only bounded templates exist; secret-bearing files are excluded; author a context-aware fix locally |
| Partial coverage | Parser errors, timeouts, unavailable analyzer or output limits; never interpret as a clean scan |

## CI/CD

GitHub Actions runs unit/integration tests, production build, browser tests and a Docker scanner smoke test with read-only repository permissions. Vercel Git integration builds the frontend from the connected branch. Configure Vercel Deployment Checks/branch protections if production must wait for GitHub CI; the default Git connection alone does not enforce that ordering. No secret-bearing job runs untrusted repository application code.
