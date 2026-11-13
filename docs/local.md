# Run CodeGuardian on your device

No Oracle account, Vercel backend, GitHub App, subscription, or remote AI key is needed. The existing frontend, FastAPI API, PostgreSQL, Redis, worker and scheduler run locally. Upload authorized ZIP archives to run real security scans.

## Start on this Apple Silicon Mac

From the repository directory, using the existing Python 3.12 environment:

```sh
.venv/bin/python scripts/install_local_runtime.py start
.venv/bin/python scripts/local_setup.py up
```

Open **http://localhost:3000/workspace** for the full local scanner workspace. The root page at **http://localhost:3000** is the account-free browser code checker. Copy the access key from `.cache/local/access-key.txt` into the masked **Local access key** field. This is a generated local password, not a GitHub token. Do not commit or share it. The setup script stores this file and `.cache/local/compose.env` with owner-only permissions and does not print their contents. Re-running setup preserves credentials and data.

Choose **Review a source archive**, select your ZIP and confirm that you are authorized to scan it. Results, source review, filters, explanations, suggested diffs, reports and history use the existing application. No fixture repository is preloaded into the workspace.

The first start downloads the open-source Lima runtime, a Linux VM image, Docker images, dependencies and public vulnerability databases. Subsequent scans are offline. Startup can take several minutes and uses several gigabytes of disk. The dedicated Linux VM uses 2 CPUs and 6 GiB RAM by default; reserve sufficient memory for macOS as well. It shares only this project directory with the VM, not your entire home. On Linux, install Docker Engine and the Compose plugin, then run `scripts/local_setup.py up`; the Lima installer is specific to Apple Silicon.

## Manage the local installation

```sh
# Check database, migrations, queue, worker and local authentication capability.
.venv/bin/python scripts/local_setup.py status

# Real end-to-end test: login, ZIP upload, all five scanners, persistence and logout.
# The script removes its own imported test repository after verification.
.venv/bin/python scripts/local_setup.py smoke

# Refresh public offline databases while online (at least weekly).
.venv/bin/python scripts/local_setup.py update-data

# Stop application containers, preserving database volumes.
.venv/bin/python scripts/local_setup.py down

# Release the VM's RAM/CPU while retaining its disk.
.venv/bin/python scripts/install_local_runtime.py stop
```

Restart with the two start commands above. Do not delete `.cache/lima`, Docker volumes, or the encryption key if you want to retain your results. PostgreSQL and Redis volumes are inside the local Docker VM. Encrypted queued uploads and redacted scan evidence never enter a cloud database.

`compose.local.yaml` is separate from the cloud Compose file. Only port 3000 is published, on `127.0.0.1`. PostgreSQL, Redis and the API have no host ports. The API, database, queue and workers use an internal Docker network. A separate bridge lets Docker publish the frontend on localhost. The administrative updater downloads public scanner databases. The worker controls Docker **inside the dedicated VM**; scanner containers retain the existing no-network, read-only, non-root and resource limits. Submitted code is never run as an application.

Local login requires the generated key, a matching localhost Origin and normal expiring sessions. Mutations still enforce CSRF and rate limits. Local authentication cannot be enabled on a public/production deployment. GitHub sign-in and remote advisory enrichment are disabled in local mode. Retention defaults remain 24 hours for source and 90 days for historical results.

## Explanations and optional on-device AI

The optional Ollama profile runs Qwen2.5-Coder 1.5B inside the same VM. Enable it once with this command.

```sh
.venv/bin/python scripts/local_setup.py enable-ai
```

The provisioning container downloads the official Ollama image and the [986 MB model](https://ollama.com/library/qwen2.5-coder:1.5b) into a local volume. The inference service uses only the internal network and has no published port. Source and findings are never mounted into the provisioning container. Ollama cloud features are disabled. The VM uses CPU inference, so a first explanation can take time.

In **Code review**, select a finding and click **Explain with configured AI**. The API supplies limited redacted evidence and trusted CWE guidance. It validates structured output, citation IDs and the original classification before saving the response. The panel identifies the model and prompts the reviewer to verify its suggestions.

`local_setup.py smoke` exercises a real model explanation when AI is enabled. `local_setup.py disable-ai` stops inference and retains the weights for future use. The original scanner findings and curated explanations remain available.

## Troubleshooting

- **Lima not running:** run `install_local_runtime.py start` before `local_setup.py up`.
- **Port 3000 in use:** stop the other local service, then restart CodeGuardian. This bundled launcher uses localhost:3000 consistently for Origin/CSRF checks.
- **Setup still in progress:** run `status`; do not bypass a failed database/schema/queue/worker check.
- **Incomplete scan coverage:** update scanner data, verify available disk/RAM and retry by uploading the archive again. Missing/stale databases are not treated as a clean scan.
- **macOS asks about virtualization or network access:** approve the local runtime only if you intend to run this VM. No public-facing service or cloud resource is required.

The runtime comes from the [official Lima binary distribution](https://lima-vm.io/docs/installation/), pinned to 2.3.0 and SHA-256 verified. Docker is installed inside the VM from its official distribution. The source and operation of the VM remain local; ordinary bootstrap downloads still require internet access.
