"""Scanning logic: walk text/files and yield redacted findings."""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Iterable, Iterator

from .rules import ALLOWLIST_MARKER, PLACEHOLDERS, RULES, Rule

_SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build"}


@dataclass
class Finding:
    path: str
    line_no: int
    rule: str
    severity: str
    secret: str  # redacted

    def __str__(self) -> str:
        return f"{self.path}:{self.line_no}: [{self.severity}] {self.rule} -> {self.secret}"


def redact(value: str) -> str:
    value = value.strip().strip("'\"")
    if len(value) <= 6:
        return "****"
    return f"{value[:4]}…{value[-2:]} ({len(value)} chars)"


def _is_false_positive(rule: Rule, line: str) -> bool:
    if ALLOWLIST_MARKER in line:
        return True
    if rule.name == "Generic secret assignment":
        lowered = line.lower()
        return any(ph in lowered for ph in PLACEHOLDERS)
    return False


def scan_text(text: str, path: str = "<stdin>") -> list[Finding]:
    findings: list[Finding] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        for rule in RULES:
            match = rule.pattern.search(line)
            if match and not _is_false_positive(rule, line):
                findings.append(
                    Finding(path, line_no, rule.name, rule.severity, redact(match.group(0)))
                )
    return findings


def scan_file(path: str) -> list[Finding]:
    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            return scan_text(fh.read(), path)
    except (OSError, UnicodeError):
        return []


def iter_files(paths: Iterable[str]) -> Iterator[str]:
    for p in paths:
        if os.path.isfile(p):
            yield p
        elif os.path.isdir(p):
            for root, dirs, files in os.walk(p):
                dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
                for f in files:
                    yield os.path.join(root, f)


def scan_paths(paths: Iterable[str]) -> list[Finding]:
    findings: list[Finding] = []
    for file_path in iter_files(paths):
        findings.extend(scan_file(file_path))
    return findings
