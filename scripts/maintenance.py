"""Run from a trusted scheduled job to expire sessions and mark abandoned scans failed."""
import sys
from datetime import timedelta
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
from sqlmodel import Session, select
from app.models import engine, LoginSession, OAuthState, Scan, now

with Session(engine) as db:
    for model in (LoginSession, OAuthState):
        for row in db.exec(select(model).where(model.expires_at < now())).all(): db.delete(row)
    for scan in db.exec(select(Scan).where(Scan.status.in_(["queued", "running"]), Scan.created_at < now() - timedelta(minutes=10))).all():
        scan.status = "failed"
        scan.completed_at = now()
        scan.error = "Worker did not complete within the processing window. Retry the scan."
        db.add(scan)
    db.commit()
