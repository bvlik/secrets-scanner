<div align="center">

# 🔑 secrets-scanner

**Catch secrets before they hit your git history.**
A lightweight, dependency-light secrets scanner that runs as a CLI or a **pre-commit hook** — detects API keys, cloud credentials, private keys and tokens, with redacted output and a non-zero exit so commits are blocked.

[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
![Python](https://img.shields.io/badge/Python-3.10+-0A1929?style=for-the-badge&logo=python&logoColor=12ABDB)
![pre--commit](https://img.shields.io/badge/pre--commit-hook-0A1929?style=for-the-badge)

</div>

---

## Why

This project was born from a real lesson: I once had to rewrite git history to scrub a leaked address. The fix is to **never let secrets in** — so here's a scanner you can wire into `pre-commit` that blocks the commit when it spots a credential.

## Detects

| Rule | Example |
|------|---------|
| AWS Access Key ID | `AKIA…` |
| AWS Secret Access Key | `aws_secret_access_key = …` |
| Private keys | `-----BEGIN … PRIVATE KEY-----` |
| GitHub tokens | `ghp_…` / `gho_…` |
| Slack tokens | `xoxb-…` |
| Google API keys | `AIza…` |
| Generic `key/secret/token/password = "…"` | assignments |
| JWT | `eyJ….….…` |

Mark an intentional value with a trailing `# pragma: allowlist secret` to skip it.

## Use it

```bash
pip install .
secrets-scanner path/to/dir          # scan files/dirs
secrets-scanner --staged             # scan git-staged files (pre-commit)
```

### As a pre-commit hook
```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/bvlik/secrets-scanner
    rev: v0.1.0
    hooks:
      - id: secrets-scanner
```

Exit code is non-zero when a secret is found, so the commit is blocked.

## Roadmap
- [ ] Shannon-entropy detection for high-entropy blobs
- [ ] Baseline file to accept known/legacy findings
- [ ] SARIF output for code scanning
