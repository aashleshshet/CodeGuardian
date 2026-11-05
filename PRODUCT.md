# CodeGuardian AI
<!-- impeccable:product-schema 1 -->

## Platform
web

## Stack
User specified: Next.js, TypeScript, Tailwind, Monaco; Python/FastAPI; PostgreSQL; Redis/Celery; Semgrep/Bandit; configurable LLM; GitHub App; Vercel plus container hosting.

## Product Purpose
An evidence-first secure code review platform. Reviewers import authorized source, inspect scanner findings at the affected lines, compare snapshots, understand evidence, and review proposed fixes.

## Users
Developers and application security reviewers (inferred from the requested workflow).

## Capabilities and Constraints
Python, JavaScript, and TypeScript initially. Never execute repository code. Secrets must be redacted. AI explanations cannot promote potential vulnerabilities to verified exploitation. All patches require human review; no automatic repository writes or merges.

## Brand Commitments
CodeGuardian AI. User requests liquid glass, dark/light themes, responsive review screens.

## Evidence on Hand
An intentionally vulnerable, local reproducible test repository. Demonstration findings must come from actual scanner runs and remain labeled as fixture results.
