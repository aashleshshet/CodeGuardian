from fastapi import HTTPException
from datetime import timezone
from .models import now
from sqlmodel import select
from .models import Repository, Scan, FindingRecord, Review
from .scanner import summary, compare


def owned_repo(repo_id, user, db):
    repo = db.get(Repository, repo_id)
    if not repo or repo.owner_id != user.id: raise HTTPException(404, "Repository not found")
    return repo


def owned_scan(scan_id, user, db):
    scan = db.get(Scan, scan_id)
    if not scan: raise HTTPException(404, "Scan not found")
    return scan, owned_repo(scan.repository_id, user, db)


def finding_for(scan, fingerprint):
    finding = next((f for f in scan.findings if f["fingerprint"] == fingerprint), None)
    if not finding: raise HTTPException(404, "Finding not found")
    return finding


def retained_source(scan):
    if scan.source_expires_at and scan.source_expires_at.replace(tzinfo=timezone.utc) <= now(): return {}
    return scan.files


def scan_view(scan, db, with_files=True):
    result = scan.model_dump(exclude={"encrypted_source", "job_key"})
    records = {r.fingerprint: r for r in db.exec(select(FindingRecord).where(FindingRecord.repository_id == scan.repository_id, FindingRecord.branch == scan.branch)).all()}
    result["findings"] = [{**f, "status": records[f["fingerprint"]].status if f["fingerprint"] in records else "open", "review_note": records[f["fingerprint"]].note if f["fingerprint"] in records else "", "first_seen": records[f["fingerprint"]].first_seen.isoformat() if f["fingerprint"] in records else scan.created_at.isoformat(), "last_seen": records[f["fingerprint"]].last_seen.isoformat() if f["fingerprint"] in records else scan.created_at.isoformat()} for f in scan.findings]
    result["summary"] = summary(result["findings"])
    result["files"] = retained_source(scan)
    if not with_files:
        result.pop("files", None)
        result.pop("findings", None)
    if scan.coverage.get("pr_comparison"):
        result["comparison"] = scan.coverage["pr_comparison"]
    elif scan.baseline_id:
        baseline = db.get(Scan, scan.baseline_id)
        if baseline:
            result["comparison"] = {**compare(scan.findings, baseline.findings), "baseline_commit": baseline.commit_sha, "reliable": bool(scan.coverage.get("complete") and baseline.coverage.get("complete"))}
    return result
