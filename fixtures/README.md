# Reproducible security test inputs

`baseline/` and `current/` are intentionally vulnerable source snapshots, not runnable applications. Never execute their code, build their Dockerfiles, install their packages or deploy their manifests.

The baseline additionally contains unsafe pickle deserialization and weak hashing; the current snapshot removes those examples to exercise real finding comparisons. Both snapshots include Python/JavaScript/TypeScript patterns, old npm/PyPI dependency manifests, unsafe Docker/Kubernetes configurations and a deliberately synthetic, invalid credential pattern for redaction tests. There are no install hooks or executable test commands.

Run `RUN_ALL_SCANNERS=true SCANNER_CACHE="$PWD/.cache/scanner-data" pytest backend/tests/test_scanners.py -q` after provisioning the pinned scanners and offline caches as described in the root README. This invokes real analyzer processes only against the exact trusted fixture bytes. Arbitrary repository source requires the Docker runner.

Advisory counts change as the public vulnerability databases evolve. Preserve the cache manifest to reproduce a specific run. Unit-test snapshot data in `backend/tests/data/` is never served to production clients; browser tests produce fresh Semgrep/Bandit evidence and store it in their isolated test database.
