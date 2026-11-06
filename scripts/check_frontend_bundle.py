"""Prevent accidental shipping of Monaco's obsolete vendored DOMPurify sanitizer."""
from pathlib import Path
import re
chunks=list(Path('.next/static/chunks').rglob('*.js'))
if not chunks: raise SystemExit('Build the frontend before checking its sanitizer')
versions=set()
for path in chunks:
    text=path.read_text()
    if 'DOMPurify' in text:
        versions.update(re.findall(r'version="(3\.[0-9.]+)"',text))
if versions != {'3.4.17'}: raise SystemExit(f'Unexpected bundled DOMPurify versions: {sorted(versions)}')
print('Verified production editor bundle uses DOMPurify 3.4.17')
