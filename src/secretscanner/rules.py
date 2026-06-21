"""Detection rules. Each rule is a name, severity and a compiled regex."""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    name: str
    severity: str
    pattern: re.Pattern


RULES: list[Rule] = [
    Rule("AWS Access Key ID", "high", re.compile(r"AKIA[0-9A-Z]{16}")),
    Rule(
        "AWS Secret Access Key",
        "high",
        re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})"),
    ),
    Rule("Private Key", "high", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    Rule("GitHub Token", "high", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}")),
    Rule("Slack Token", "high", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    Rule("Google API Key", "medium", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    Rule(
        "Generic secret assignment",
        "medium",
        re.compile(r"(?i)(api[_-]?key|secret|token|passwd|password)\s*[=:]\s*['\"][^'\"]{8,}['\"]"),
    ),
    Rule("JWT", "low", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
]

# Values that clearly aren't real secrets (placeholders), used to cut noise on the generic rule.
PLACEHOLDERS = ("your_", "your-", "xxx", "changeme", "example", "<", "placeholder", "dummy", "redacted")
ALLOWLIST_MARKER = "pragma: allowlist secret"
