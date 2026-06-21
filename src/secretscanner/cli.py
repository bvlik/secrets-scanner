"""CLI entrypoint: scan paths or git-staged files."""
from __future__ import annotations

import argparse
import subprocess
import sys

from rich.console import Console

from .scanner import scan_paths


def _staged_files() -> list[str]:
    out = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
        capture_output=True,
        text=True,
        check=False,
    )
    return [line for line in out.stdout.splitlines() if line.strip()]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="secrets-scanner", description="Detect secrets in files")
    parser.add_argument("paths", nargs="*", help="files or directories to scan")
    parser.add_argument("--staged", action="store_true", help="scan git-staged files (pre-commit)")
    args = parser.parse_args(argv)

    paths = _staged_files() if args.staged else (args.paths or ["."])
    findings = scan_paths(paths)

    console = Console()
    if not findings:
        console.print("[bold green]No secrets found.[/]")
        return 0

    console.print(f"[bold red]Found {len(findings)} potential secret(s):[/]")
    for f in sorted(findings, key=lambda x: x.path):
        console.print(f"  [red]•[/] {f}")
    console.print("\n[dim]Use `# pragma: allowlist secret` to allow an intentional value.[/]")
    return 1


if __name__ == "__main__":
    sys.exit(main())
