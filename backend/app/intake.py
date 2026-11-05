import io
import stat
import zipfile
from pathlib import PurePosixPath
from .config import settings

EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx", ".json", ".yaml", ".yml", ".toml", ".env", ".md", ".txt", ".ini", ".cfg"}
IGNORED = {".git", "node_modules", ".venv", "venv", "vendor", "dist", "build", ".next", "__pycache__"}


def validate_path(name: str) -> PurePosixPath:
    if not name or len(name) > 240 or "\\" in name or any(ord(c) < 32 or ord(c) == 127 for c in name):
        raise ValueError("Invalid source path")
    path = PurePosixPath(name)
    if path.is_absolute() or any(p in {"..", "."} for p in name.split("/")) or ":" in name:
        raise ValueError("Unsafe archive path")
    return path


def extract_sources(data: bytes, strip_root: bool = False) -> tuple[dict[str, str], dict]:
    cfg = settings()
    if len(data) > cfg.max_archive_bytes: raise ValueError("Archive exceeds 10 MB limit")
    files, seen, total, skipped = {}, set(), 0, 0
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            entries = archive.infolist()
            if len(entries) > cfg.max_files * 10: raise ValueError("Too many archive entries")
            roots = {validate_path(e.filename.rstrip("/")).parts[0] for e in entries}
            if strip_root and len(roots) != 1: raise ValueError("Expected one repository archive root")
            for entry in entries:
                path = validate_path(entry.filename.rstrip("/"))
                mode = entry.external_attr >> 16
                if stat.S_ISLNK(mode) or (stat.S_IFMT(mode) not in {0, stat.S_IFREG, stat.S_IFDIR}):
                    raise ValueError("Archive links and special files are forbidden")
                if entry.is_dir(): continue
                if entry.flag_bits & 1: raise ValueError("Encrypted archives are unsupported")
                if strip_root:
                    path = PurePosixPath(*path.parts[1:])
                name = str(path)
                if name.casefold() in seen: raise ValueError("Duplicate archive path")
                seen.add(name.casefold())
                total += entry.file_size
                if total > cfg.max_source_bytes: raise ValueError("Expanded archive exceeds 20 MB limit")
                if any(part in IGNORED for part in path.parts) or (path.suffix not in EXTENSIONS and not path.name.startswith(".env")):
                    skipped += 1
                    continue
                if entry.file_size > cfg.max_file_bytes: raise ValueError("A source file exceeds 250 KB limit")
                if len(files) >= cfg.max_files: raise ValueError("Too many source files")
                content = archive.read(entry)
                if b"\x00" in content:
                    skipped += 1
                    continue
                try: files[name] = content.decode("utf-8")
                except UnicodeDecodeError: skipped += 1
    except zipfile.BadZipFile as exc:
        raise ValueError("A valid ZIP archive is required") from exc
    if not files: raise ValueError("No supported text source files found")
    return files, {"files": len(files), "skipped_files": skipped, "expanded_bytes": total}
