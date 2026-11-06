"""Run the same bounded maintenance task used by Celery Beat from a trusted operator shell."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
from app.tasks import maintenance

if __name__ == "__main__":
    maintenance()
