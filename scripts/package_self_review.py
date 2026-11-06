"""Package committed application code for the same isolated scanner used by customers."""
import subprocess
import sys
from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED
root=Path(__file__).resolve().parents[1]
paths=subprocess.check_output(['git','ls-files','-z'],cwd=root).decode().split('\0')
with ZipFile(sys.argv[1],'w',ZIP_DEFLATED) as archive:
    for name in paths:
        if not name or name.startswith(('fixtures/','backend/tests/','tests/','docs/','.taste-skill/','.impeccable/')):continue
        path=root/name
        if path.is_file() and not path.is_symlink() and path.stat().st_size<1_000_000:archive.write(path,name)
