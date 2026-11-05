"""Central secret detection. Raw matches must never leave this module's caller boundary."""
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class SecretMatch:
    start: int
    end: int
    line: int
    kind: str


PATTERNS = [
    ("Private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), 0),
    ("GitHub token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{30,255})\b"), 0),
    ("AWS access key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), 0),
    ("Provider API key", re.compile(r"\bsk[-_](?:live[-_]|test[-_]|proj-)?[A-Za-z0-9_-]{20,255}\b"), 0),
    ("Credential assignment", re.compile(r'''(?im)["']?(?:[\w-]*(?:password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key))["']?\s*[:=]\s*["']([^"'\n]{8,})["']'''), 1),
    ("Credential in URL", re.compile(r"(?i)(?:https?|postgres(?:ql)?|mysql|redis)://[^\s:/]+:([^@\s]+)@"), 1),
    ("Bearer token", re.compile(r"(?i)\bbearer\s+([A-Za-z0-9._~-]{16,})"), 1),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), 0),
]


def detect_secrets(text: str) -> list[SecretMatch]:
    found: list[SecretMatch] = []
    for kind, pattern, group in PATTERNS:
        for match in pattern.finditer(text):
            start, end = match.span(group)
            value = match.group(group)
            if "[REDACTED]" in value or value.startswith(("${", "{{", "<")):
                continue
            if any(start < s.end and end > s.start for s in found):
                continue
            found.append(SecretMatch(start, end, text.count("\n", 0, start) + 1, kind))
    return sorted(found, key=lambda s: s.start)


def redact(text: str) -> str:
    for match in reversed(detect_secrets(text)):
        replacement = "[REDACTED]" + "\n" * text[match.start:match.end].count("\n")
        text = text[:match.start] + replacement + text[match.end:]
    return text


def redact_tree(value):
    if isinstance(value, str): return redact(value)
    if isinstance(value, list): return [redact_tree(v) for v in value]
    if isinstance(value, dict): return {redact(str(k)): redact_tree(v) for k, v in value.items()}
    return value
