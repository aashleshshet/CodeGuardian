FROM docker:28-cli AS docker_cli
FROM python:3.12-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PYTHONPATH=/app/backend
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates git && rm -rf /var/lib/apt/lists/*
COPY backend/requirements-runtime.txt /app/backend/requirements-runtime.txt
RUN pip install --no-cache-dir -r backend/requirements-runtime.txt
COPY backend /app/backend
COPY scripts /app/scripts
RUN useradd --uid 1000 --create-home guardian

FROM base AS api
USER guardian
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log", "--no-proxy-headers"]

FROM base AS worker
COPY --from=docker_cli /usr/local/bin/docker /usr/local/bin/docker
USER guardian
CMD ["celery", "-A", "app.tasks.celery", "worker", "--loglevel=WARNING", "--concurrency=2", "--without-gossip", "--without-mingle"]

FROM base AS scanner_tools
RUN pip install --no-cache-dir -r backend/requirements.txt
RUN python scripts/install_scanners.py --destination /usr/local/bin
ENV HOME=/tmp SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0

FROM scanner_tools AS scanner
USER 65532:65532
WORKDIR /source
ENTRYPOINT ["python", "-m", "app.scanner"]
