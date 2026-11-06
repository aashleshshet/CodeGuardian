# Deployment and live activation

The frontend is hosted on Vercel. API, PostgreSQL, Redis, scheduler and scanner workers require a Docker-capable Linux host; ordinary Vercel functions are not the scanner runtime. No container host has been chosen, so backend deployment and real GitHub authorization remain operator activation steps.

## 1. Prepare a dedicated scanner host

Use a host with Docker/Compose, outbound HTTPS for GitHub and trusted database updates, and capacity for two 3 GiB scanner containers plus the application services. Keep PostgreSQL and Redis on the internal Compose network. Put the API behind an HTTPS reverse proxy; it binds to `127.0.0.1:8000` by default.

The worker controls a Docker daemon. Isolate this authority from other workloads. A dedicated rootless Docker daemon is preferred; set its socket path and UID/GID explicitly. Rootful Docker also works but grants the worker host-level Docker authority. The API never receives the Docker socket.

```sh
cp .env.example .env
python3 -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'
```

Install the Python dependencies first if `cryptography` is unavailable. Store the generated key as `TOKEN_ENCRYPTION_KEY` in the secret store / untracked `.env`. Generate a strong URL-safe `POSTGRES_PASSWORD`. Set:

```dotenv
ENVIRONMENT=production
PUBLIC_URL=https://codeguardian-ai-rho.vercel.app
POSTGRES_PASSWORD=<generated-url-safe-password>
TOKEN_ENCRYPTION_KEY=<fernet-key>
SCANNER_MODE=docker
TASKS_EAGER=false
SCANNER_JOBS_DIR=/srv/codeguardian/jobs
SCANNER_CACHE_DIR=/srv/codeguardian/scanner-data
WORKER_UID=1000
DOCKER_GID=<socket-group-id>
DOCKER_SOCKET=<dedicated-daemon-socket-path>
```

Create both absolute directories and give the worker UID write access to `jobs` and the cache updater write access to `scanner-data`. Workers mount them at the same absolute host paths so sibling scanner bind mounts resolve correctly. Cache directories/files must be readable by scanner UID 65532. The Compose file sets internal `DATABASE_URL`, `REDIS_URL`, `SCAN_ROOT` and `SCANNER_CACHE`.

## 2. Create the GitHub App

Use the deployed frontend URL as the homepage. Configure:

- Callback: `https://codeguardian-ai-rho.vercel.app/api/backend/auth/github/callback`
- Setup URL: `https://codeguardian-ai-rho.vercel.app/#integrations`
- Webhook: `https://YOUR-API-HOST/webhooks/github` (or the frontend BFF path `/api/backend/webhooks/github`)
- Enable expiring user access tokens. Configure user authorization during installation if desired.
- Repository permissions: **Contents: read**, **Metadata: read**, **Pull requests: read** for PR event context. **Checks: write** is optional and only needed when publishing checks.
- No Contents write, PR write, administration, workflows write or organization-wide write permission is needed.
- Subscribe to `push`, `pull_request`, `installation`, `installation_repositories`.
- Install on **selected repositories**. Private repositories work only within the user and installation’s overlapping access.

Set `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, `GITHUB_APP_ID`, `GITHUB_APP_SLUG`, `GITHUB_PRIVATE_KEY` and `GITHUB_WEBHOOK_SECRET`. Store the PEM securely; escaped `\n` newlines are accepted. Installation tokens request only the selected repository and Contents read; Checks write is requested solely for opted-in check publication.

`GITHUB_CHECKS_ENABLED=false` is the default. Enable it only after granting Checks write. Each repository separately opts into automatic scans and check summaries. A blocking policy is also a separate explicit choice. Branch protection rules are configured manually on GitHub.

## 3. Build, provision scanner data and migrate

```sh
docker build -f backend/Dockerfile --target scanner -t codeguardian-scanner:local .
docker compose build
docker compose --profile tools run --rm scanner-data
# Ensure the dedicated scanner UID can read the database cache.
chmod -R a+rX /srv/codeguardian/scanner-data
docker compose up -d postgres redis
docker compose run --rm migrate
docker compose up -d api worker scheduler
```

The provisioning command downloads public OSV npm/PyPI databases and Trivy vulnerability/check databases. It does not inspect repository source. OSV 2.7 uses `osv/osv-scalibr/{ecosystem}/all.zip` beneath the configured cache. Scanner binaries are pinned and checksum-verified by `scripts/install_scanners.py`.

Refresh trusted scanner databases daily with the `scanner-data` command. A missing manifest or databases older than seven days makes scan coverage incomplete. Updates require network access; the actual scanner container always uses `--network=none`. Maintain binary versions deliberately, then run all tests before release.

Migration `002` is forward-only. Back up PostgreSQL before running it. It removes only legacy repositories explicitly marked as fixtures, backfills real imported finding state, upgrades GitHub IDs to BigInteger, creates lifecycle tables, and purges old source snapshots. Restore the pre-upgrade backup for rollback. Never run `create_all` as a production migration substitute.

## 4. Connect Vercel

Import `aashleshshet/CodeGuardian`, framework Next.js, root directory `.`, install `pnpm install --frozen-lockfile`, build `pnpm build`. Set server-only:

```dotenv
API_URL=https://YOUR-API-HOST
```

Redeploy after changing this value because the page’s backend-configured state is built into the deployment. Never use a `NEXT_PUBLIC_` variable for credentials. GitHub App credentials belong on the backend, not in browser bundles. `PUBLIC_URL` must match the production frontend exactly so CSRF origin checks and secure cookies work. Configure preview deployments separately; do not casually share production sessions or secrets with arbitrary previews.

Without `API_URL`, the website intentionally shows setup information and no sample data. This is not a backend outage simulation or a working account.

## 5. Optional local AI

Run Ollama on a private network reachable by the API. The model must support JSON output and the OpenAI-compatible `/v1/chat/completions` API.

```dotenv
LLM_ENABLED=true
LLM_BASE_URL=http://ollama:11434/v1
LLM_MODEL=<installed-model-name>
LLM_API_KEY=
LLM_ALLOW_REMOTE=false
```

Attach the Ollama service/network explicitly if using Compose; an Ollama service is not provisioned by this repository. Local AI is optional and does not change analyzer classifications. For a remote provider, deliberately set `LLM_ALLOW_REMOTE=true`, use HTTPS and assess the redacted source-sharing boundary. No model or paid AI account is required for scans or curated remediation.

Optional `NVD_API_KEY` increases the NVD request allowance. Advisory enrichment sends only validated public advisory IDs to fixed OSV/NVD endpoints, never source or a dependency inventory. Enrichment failure does not fabricate references.

## 6. Live smoke test

1. Check `/health` for liveness and `/ready` for DB, Redis and worker-heartbeat readiness. Readiness must return 200 before accepting scans.
2. Sign in with GitHub. Install on a disposable repository you own, then sync and connect it. Verify a second account cannot access its scan IDs.
3. Select a branch and commit, run a scan, and observe queued → preparing → scanning → analyzing → completed/partial. Confirm worker/container resource and network limits on the actual host.
4. Inspect source, secret redaction, analyzer evidence and reports. Review a supported patch; export must require the acknowledgement checkbox. Apply/test it locally only.
5. Opt into push scans. Deliver a signed event and redeliver the same delivery ID: it must create only one job. Test PR/base comparison and checks on a same-repository PR. Fork PRs are skipped.
6. Revoke access and verify stored source is purged and new scans fail safely. Test token refresh, installation changes, rate-limit errors, cancellation and a worker restart.
7. If enabling AI, test a source comment that attempts prompt injection and confirm the response remains grounded. No real model was supplied for release verification.
8. Test backup restore and account/repository deletion before customer use.

GitHub does not automatically redeliver every failed webhook. Monitor deliveries and manually redeliver failed/capacity-limited requests. The database outbox recovers accepted jobs if Redis delivery fails; it cannot recover an event GitHub never successfully delivered.

## Retention and operations

- Source defaults to 24 hours (`SOURCE_RETENTION_HOURS`, 1–168). Redacted evidence remains; source and patch access explain expiry.
- Historical results default to 90 days (`RESULT_RETENTION_DAYS`, 1–365). Latest finding state and the scan supporting it are retained until repository/account deletion.
- Celery Beat runs maintenance every minute and worker-health pings every 30 seconds. Run one scheduler. `python scripts/maintenance.py` is the manual equivalent.
- Job admission is serialized per user on PostgreSQL; three active jobs maximum. Workers atomically claim jobs and manually retry failed/partial jobs up to `MAX_SCAN_ATTEMPTS`.
- Monitor incomplete coverage, stale data, broker failures, worker heartbeat, storage, rejected webhooks, authorization failures and check publishing errors. Apply ingress rate limits and observability appropriate to the chosen host.
- Browser BFF requests are capped at 4 MB; use smaller ZIP uploads. Intake additionally limits file count, total source bytes, file size, archive paths, symlinks and compression ratios. Oversized/unsupported repositories are not silently reported as fully analyzed.
- Protect `.env`, key material, backups, database volumes and proxy logs. Use managed encryption at rest and TLS between hosts. Keep API access logs free of OAuth callback query strings. Rotate the Fernet key with a migration of encrypted credentials; replacing it alone invalidates stored tokens.
