"""Tests for the CLI, including the normalized JSON output."""
import json

from secretscanner.cli import main, to_normalized
from secretscanner.scanner import scan_text


def test_to_normalized_schema():
    findings = scan_text("key = AKIAIOSFODNN7EXAMPLE", path="conf.env")
    payload = to_normalized(findings)
    assert payload["source"] == "secrets-scanner"
    assert len(payload["findings"]) == 1
    item = payload["findings"][0]
    assert set(item) == {"id", "severity", "message", "location"}
    assert item["id"] == "AWS Access Key ID"
    assert item["severity"] == "high"
    assert item["location"] == "conf.env:1"
    # the raw secret must stay redacted in the message
    assert "IOSFODNN" not in item["message"]


def test_to_normalized_empty():
    assert to_normalized([]) == {"source": "secrets-scanner", "findings": []}


def test_cli_json_clean_dir_exits_zero(tmp_path, capsys):
    (tmp_path / "ok.txt").write_text("nothing secret here\n", encoding="utf-8")
    rc = main(["--json", str(tmp_path)])
    out = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert out == {"source": "secrets-scanner", "findings": []}


def test_cli_json_with_secret_exits_one(tmp_path, capsys):
    (tmp_path / "leak.env").write_text("token: ghp_0123456789abcdefghijklmnopqrstuvwxyz\n", encoding="utf-8")
    rc = main(["--json", str(tmp_path)])
    out = json.loads(capsys.readouterr().out)
    assert rc == 1
    assert out["source"] == "secrets-scanner"
    assert any(f["id"] == "GitHub Token" for f in out["findings"])
