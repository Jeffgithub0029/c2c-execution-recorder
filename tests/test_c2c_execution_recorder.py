from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
import pytest

from scripts.validation.c2c_execution_recorder import (
    sanitize_text,
    infer_project_type,
    parse_test_summary,
    collect_target_file_hashes,
    compute_file_sha256,
)


def test_sanitize_text_redacts_tokens_and_keys():
    raw = "Authorization: Bearer sk-1234567890abcdef123456, api_key='secret_key_12345678'"
    sanitized, redactions = sanitize_text(raw)
    assert "[REDACTED]" in sanitized
    assert "sk-1234567890abcdef123456" not in sanitized
    assert redactions >= 2


def test_infer_project_type():
    assert infer_project_type(["pytest", "-q"]) == "python"
    assert infer_project_type(["python3", "-m", "unittest"]) == "python"
    assert infer_project_type(["npm", "test"]) == "node"
    assert infer_project_type(["pnpm", "vitest", "run"]) == "node"
    assert infer_project_type(["go", "test", "./..."]) == "go"
    assert infer_project_type(["bash", "scripts/check.sh"]) == "bash_probe"
    assert infer_project_type(["./run_probe.sh"]) == "bash_probe"
    assert infer_project_type(["curl", "-s", "http://localhost:8000"]) == "generic"


def test_parse_test_summary_pytest():
    out = "====== 34 passed, 2 skipped, 1 failed in 1.45s ======"
    counts = parse_test_summary(out, "python", 1)
    assert counts == {"passed": 34, "failed": 1, "skipped": 2}


def test_parse_test_summary_node_vitest():
    out = "Tests  18 passed (18)\nDuration 500ms"
    counts = parse_test_summary(out, "node", 0)
    assert counts == {"passed": 18, "failed": 0, "skipped": 0}

    out_failed = "Tests  10 passed | 2 failed (12)"
    counts_f = parse_test_summary(out_failed, "node", 1)
    assert counts_f == {"passed": 10, "failed": 2, "skipped": 0}


def test_parse_test_summary_go():
    out = "=== RUN   TestEngine\n--- PASS: TestEngine (0.00s)\n=== RUN   TestFail\n--- FAIL: TestFail (0.00s)\nFAIL"
    counts = parse_test_summary(out, "go", 1)
    assert counts == {"passed": 1, "failed": 1, "skipped": 0}


def test_parse_test_summary_generic_fallback():
    counts_ok = parse_test_summary("Everything looks good", "generic", 0)
    assert counts_ok == {"passed": 1, "failed": 0, "skipped": 0}

    counts_fail = parse_test_summary("Command failed", "generic", 2)
    assert counts_fail == {"passed": 0, "failed": 1, "skipped": 0}


def test_collect_target_file_hashes(tmp_path: Path):
    src = tmp_path / "engine.py"
    test_file = tmp_path / "test_engine.py"
    src.write_text("print('hello')", encoding="utf-8")
    test_file.write_text("assert True", encoding="utf-8")

    hashes = collect_target_file_hashes(
        cwd=tmp_path,
        explicit_targets=None,
        cmd=["pytest", "test_engine.py"],
        modified_files=["engine.py", "test_engine.py"],
    )

    assert "test_engine.py" in hashes
    assert "engine.py" in hashes
    assert hashes["engine.py"].startswith("sha256:")
    assert hashes["engine.py"] == compute_file_sha256(src)


def test_e2e_recorder_execution(tmp_path: Path):
    out_json = tmp_path / "execution_summary.json"
    cmd = [
        sys.executable,
        "scripts/validation/c2c_execution_recorder.py",
        "--output",
        str(out_json),
        "--",
        sys.executable,
        "-c",
        "print('=== 5 passed in 0.01s ===')",
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    assert res.returncode == 0
    assert out_json.is_file()

    payload = json.loads(out_json.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "2.0"
    assert "project_type" in payload
    assert payload["commands"][0]["exit_code"] == 0
    assert payload["commands"][0]["tests"]["passed"] == 5


def test_scope_gate_fails_closed_when_git_is_unavailable(tmp_path: Path):
    recorder = Path(__file__).resolve().parents[1] / "scripts" / "validation" / "c2c_execution_recorder.py"
    receipt = tmp_path / "receipt.json"
    result = subprocess.run(
        [sys.executable, str(recorder), "--output", str(receipt),
         "--allowed-scope", "src/", "--", sys.executable, "-c", "print('ok')"],
        cwd=tmp_path, env={**os.environ, "PATH": ""}, capture_output=True, text=True,
    )
    assert result.returncode == 2
    assert json.loads(receipt.read_text())["working_tree_fingerprint"]["scope_containment"] == "failed"
