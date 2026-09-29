"""Disposable Git repos prove optional ignored-path snapshot coverage."""
import json
import subprocess
import sys
from pathlib import Path

import pytest

RECORDER = Path(__file__).resolve().parents[1] / "scripts" / "validation" / "c2c_execution_recorder.py"


def run_case(tmp_path: Path, ignore: str, command: str, seed: bool = False):
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    (tmp_path / ".gitignore").write_text(ignore, encoding="utf-8")
    if seed:
        (tmp_path / "outside").mkdir()
        (tmp_path / "outside" / "item.txt").write_text("old", encoding="utf-8")
    subprocess.run(["git", "add", ".gitignore"], cwd=tmp_path, check=True)
    subprocess.run(["git", "-c", "user.name=Test", "-c", "user.email=test@example.com",
                    "commit", "-qm", "ignore"], cwd=tmp_path, check=True)
    receipt = tmp_path / "receipt.json"
    result = subprocess.run(
        [sys.executable, str(RECORDER), "--output", str(receipt), "--audit-ignored",
         "--allowed-scope", "src/", "--", sys.executable, "-c", command],
        cwd=tmp_path, capture_output=True, text=True,
    )
    return result, json.loads(receipt.read_text(encoding="utf-8"))["working_tree_fingerprint"]


@pytest.mark.parametrize("ignored_path", [
    "tmp/result.txt", ".pytest_cache/result.txt", "outside/__pycache__/result.pyc", "outside/result.pyc",
])
def test_new_ignored_out_of_scope(tmp_path: Path, ignored_path: str):
    command = ("from pathlib import Path; p=Path('" + ignored_path + "'); "
               "p.parent.mkdir(parents=True, exist_ok=True); p.write_text('out of scope')")
    result, fp = run_case(tmp_path, "tmp/\n.pytest_cache/\n__pycache__/\n*.pyc\n", command)
    assert result.returncode == 2
    assert ignored_path in fp["post_run_delta"]
    assert ignored_path in fp["scope_violations"]


@pytest.mark.parametrize("operation", ["modify", "delete"])
def test_existing_ignored_out_of_scope(tmp_path: Path, operation: str):
    command = ("from pathlib import Path; Path('outside/item.txt').write_text('new')"
               if operation == "modify" else "from pathlib import Path; Path('outside/item.txt').unlink()")
    result, fp = run_case(tmp_path, "outside/\n", command, seed=True)
    assert result.returncode == 2
    assert "outside/item.txt" in fp["post_run_delta"]


def test_in_scope_ignored_write(tmp_path: Path):
    command = "from pathlib import Path; p=Path('src/generated.txt'); p.parent.mkdir(); p.write_text('ok')"
    result, fp = run_case(tmp_path, "src/\n", command)
    assert result.returncode == 0
    assert fp["scope_containment"] == "passed"
    assert "src/generated.txt" in fp["post_run_delta"]


def test_requires_scope_before_running_command(tmp_path: Path):
    marker = tmp_path / "should_not_exist"
    result = subprocess.run(
        [sys.executable, str(RECORDER), "--audit-ignored", "--", sys.executable,
         "-c", f"from pathlib import Path; Path({str(marker)!r}).touch()"],
        cwd=tmp_path, capture_output=True, text=True,
    )
    assert result.returncode == 2
    assert not marker.exists()


def test_ignored_audit_failure_blocks_before_command(tmp_path: Path):
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    (tmp_path / ".gitignore").write_text("tmp/\n", encoding="utf-8")
    subprocess.run(["git", "add", ".gitignore"], cwd=tmp_path, check=True)
    subprocess.run(["git", "-c", "user.name=Test", "-c", "user.email=test@example.com",
                    "commit", "-qm", "ignore"], cwd=tmp_path, check=True)
    (tmp_path / "tmp").mkdir()
    for index in range(10001):
        (tmp_path / "tmp" / str(index)).touch()
    marker = tmp_path / "should_not_exist"
    result = subprocess.run(
        [sys.executable, str(RECORDER), "--audit-ignored", "--allowed-scope", "src/",
         "--", sys.executable, "-c", f"from pathlib import Path; Path({str(marker)!r}).touch()"],
        cwd=tmp_path, capture_output=True, text=True,
    )
    assert result.returncode == 2
    assert "exceeds 10000 entries" in result.stderr
    assert not marker.exists()


def test_audit_rejects_non_root_cwd_before_command(tmp_path: Path):
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "-c", "user.name=Test", "-c", "user.email=test@example.com",
                    "commit", "--allow-empty", "-qm", "initial"], cwd=tmp_path, check=True)
    child = tmp_path / "child"
    child.mkdir()
    marker = tmp_path / "should_not_exist"
    result = subprocess.run(
        [sys.executable, str(RECORDER), "--audit-ignored", "--allowed-scope", "child/",
         "--", sys.executable, "-c", f"from pathlib import Path; Path({str(marker)!r}).touch()"],
        cwd=child, capture_output=True, text=True,
    )
    assert result.returncode == 2
    assert "repository root" in result.stderr
    assert not marker.exists()


def test_ignored_nested_git_directory_fails_closed(tmp_path: Path):
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    (tmp_path / ".gitignore").write_text("vendor/\n", encoding="utf-8")
    subprocess.run(["git", "add", ".gitignore"], cwd=tmp_path, check=True)
    subprocess.run(["git", "-c", "user.name=Test", "-c", "user.email=test@example.com",
                    "commit", "-qm", "ignore vendor"], cwd=tmp_path, check=True)
    nested = tmp_path / "vendor" / "lib"
    nested.mkdir(parents=True)
    subprocess.run(["git", "init", "-q"], cwd=nested, check=True)
    marker = tmp_path / "should_not_exist"
    result = subprocess.run(
        [sys.executable, str(RECORDER), "--audit-ignored", "--allowed-scope", "src/",
         "--", sys.executable, "-c", f"from pathlib import Path; Path({str(marker)!r}).touch()"],
        cwd=tmp_path, capture_output=True, text=True,
    )
    assert result.returncode == 2
    assert "not a regular file or symlink" in result.stderr
    assert not marker.exists()
