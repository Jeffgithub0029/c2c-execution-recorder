"""A trusted local consumer must reject receipts that only look successful."""
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
RECORDER = ROOT / "scripts/validation/c2c_execution_recorder.py"
VERIFIER = ROOT / "scripts/validation/verify_receipt.py"


def init_repo(path):
    subprocess.run(["git", "init", "-q"], cwd=path, check=True)
    (path / "src").mkdir()
    (path / "src" / "engine.py").write_text("value = 1\n", encoding="utf-8")
    (path / ".gitignore").write_text("receipt.json\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=path, check=True)
    subprocess.run(["git", "-c", "user.name=Test", "-c", "user.email=test@example.com",
                    "commit", "-qm", "initial"], cwd=path, check=True)


def record(path, *, audit=False, code="print('ok')", output="receipt.json"):
    command = [sys.executable, "-c", code]
    args = [sys.executable, str(RECORDER), "--output", output,
            "--allowed-scope", "src/", "--target-files", "src/engine.py"]
    if audit:
        args.append("--audit-ignored")
    result = subprocess.run(args + ["--"] + command, cwd=path, capture_output=True, text=True)
    return result, command


def verify(path, command, *extra, recorder_exit=0, receipt="receipt.json"):
    expected = path.parent / (path.name + "-expected-argv.json")
    expected.write_text(json.dumps(command), encoding="utf-8")
    return subprocess.run(
        [sys.executable, str(VERIFIER), "--receipt", receipt, "--repo", str(path),
         "--recorder-exit", str(recorder_exit), "--expected-argv-file", str(expected),
         "--expected-file", "src/engine.py", "--allowed-scope", "src/"] + list(extra),
        cwd=path, capture_output=True, text=True,
    )


def test_accepts_matching_local_receipt(tmp_path):
    init_repo(tmp_path)
    result, command = record(tmp_path, audit=True)
    assert result.returncode == 0, result.stderr
    accepted = verify(tmp_path, command, "--require-ignored")
    assert accepted.returncode == 0, accepted.stderr


@pytest.mark.parametrize("mutation", [
    "no_scope", "scope_failed", "ignored_missing", "command_failed", "target_missing",
    "wrong_hash", "wrong_head", "changed_head", "invalid_hash", "violations",
])
def test_rejects_unverified_receipt(tmp_path, mutation):
    init_repo(tmp_path)
    result, command = record(tmp_path)
    assert result.returncode == 0, result.stderr
    path = tmp_path / "receipt.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    fp = data["working_tree_fingerprint"]
    if mutation == "no_scope":
        fp.pop("allowed_scope")
    elif mutation == "scope_failed":
        fp["scope_containment"] = "failed"
    elif mutation == "ignored_missing":
        pass
    elif mutation == "command_failed":
        data["commands"][0]["exit_code"] = 1
    elif mutation == "target_missing":
        fp["target_file_hashes"].clear()
    elif mutation == "wrong_hash":
        fp["target_file_hashes"]["src/engine.py"] = "sha256:" + "0" * 64
    elif mutation == "wrong_head":
        data["git_commit"] = "0" * 40
    elif mutation == "changed_head":
        fp["head_changed"] = True
    elif mutation == "invalid_hash":
        fp["invalid_target_hashes"] = ["src/engine.py"]
    elif mutation == "violations":
        fp["scope_violations"] = ["elsewhere"]
    path.write_text(json.dumps(data), encoding="utf-8")
    extra = ("--require-ignored",) if mutation == "ignored_missing" else ()
    accepted = verify(tmp_path, command, *extra)
    assert accepted.returncode == 2, (mutation, accepted.stdout, accepted.stderr)


def test_rejects_recorder_failure_even_when_wrapped_command_succeeded(tmp_path):
    init_repo(tmp_path)
    result, command = record(tmp_path, code="from pathlib import Path; Path('outside').touch()")
    assert result.returncode == 2
    data = json.loads((tmp_path / "receipt.json").read_text(encoding="utf-8"))
    assert data["commands"][0]["exit_code"] == 0
    assert verify(tmp_path, command, recorder_exit=result.returncode).returncode == 2


def test_rejects_changed_checkout_or_command(tmp_path):
    init_repo(tmp_path)
    result, command = record(tmp_path)
    assert result.returncode == 0
    assert verify(tmp_path, command + ["--different"]).returncode == 2
    (tmp_path / "src" / "engine.py").write_text("value = 2\n", encoding="utf-8")
    assert verify(tmp_path, command).returncode == 2


def test_rejects_late_out_of_scope_write_when_checkout_already_dirty(tmp_path):
    init_repo(tmp_path)
    result, command = record(tmp_path, code="from pathlib import Path; Path('src/engine.py').write_text('value = 2\\n')")
    assert result.returncode == 0
    (tmp_path / "backdoor.sh").write_text("late write\n", encoding="utf-8")
    assert verify(tmp_path, command).returncode == 2


def test_accepts_receipt_created_as_untracked_after_snapshot(tmp_path):
    init_repo(tmp_path)
    (tmp_path / ".gitignore").write_text("", encoding="utf-8")
    subprocess.run(["git", "add", ".gitignore"], cwd=tmp_path, check=True)
    subprocess.run(["git", "-c", "user.name=Test", "-c", "user.email=test@example.com",
                    "commit", "-qm", "unignore receipt"], cwd=tmp_path, check=True)
    result, command = record(tmp_path)
    assert result.returncode == 0
    assert verify(tmp_path, command).returncode == 0


@pytest.mark.parametrize("bad", ["[]", "null", '"abc"'])
def test_invalid_json_shape_is_not_verified_without_traceback(tmp_path, bad):
    init_repo(tmp_path)
    result, command = record(tmp_path)
    assert result.returncode == 0
    (tmp_path / "receipt.json").write_text(bad, encoding="utf-8")
    checked = verify(tmp_path, command)
    assert checked.returncode == 2
    assert "Traceback" not in checked.stderr


def test_command_argument_boundaries_are_not_collapsible(tmp_path):
    init_repo(tmp_path)
    result, command = record(tmp_path, code="print('a b')")
    assert result.returncode == 0
    # Same joined text, distinct argv. A string comparison would accept it.
    assert verify(tmp_path, [command[0], "-c print('a", "b')"]).returncode == 2


def test_redacted_command_cannot_be_accepted_as_an_exact_command(tmp_path):
    init_repo(tmp_path)
    result, command = record(tmp_path, code="api_key='secret12345678'; print('ok')")
    assert result.returncode == 0
    assert "[REDACTED]" in json.loads((tmp_path / "receipt.json").read_text())["commands"][0]["command"]
    assert verify(tmp_path, command).returncode == 2
    assert verify(tmp_path, [*command[:-1], "api_key='different12345'; print('ok')"]).returncode == 2


def test_accepts_receipt_written_outside_checkout(tmp_path):
    init_repo(tmp_path)
    external = tmp_path.parent / (tmp_path.name + "-receipt.json")
    try:
        result, command = record(tmp_path, output=str(external))
        assert result.returncode == 0
        assert verify(tmp_path, command, receipt=str(external)).returncode == 0
    finally:
        external.unlink(missing_ok=True)


def test_rejects_reported_test_failure_even_with_wrapper_exit_zero(tmp_path):
    init_repo(tmp_path)
    result, command = record(tmp_path, code="print('=== 1 failed, 5 passed in 0.1s ===')")
    assert result.returncode == 2
    receipt = json.loads((tmp_path / "receipt.json").read_text())
    assert receipt["commands"][0]["tests"]["failed"] == 1
    assert verify(tmp_path, command, recorder_exit=result.returncode).returncode == 2
    assert verify(tmp_path, command, recorder_exit=0).returncode == 2


def test_rejects_second_mutation_of_dirty_in_scope_nontarget(tmp_path):
    init_repo(tmp_path)
    other = tmp_path / "src" / "other.py"
    other.write_text("initial\n", encoding="utf-8")
    subprocess.run(["git", "add", "src/other.py"], cwd=tmp_path, check=True)
    subprocess.run(["git", "-c", "user.name=Test", "-c", "user.email=test@example.com",
                    "commit", "-qm", "other"], cwd=tmp_path, check=True)
    result, command = record(tmp_path, code="from pathlib import Path; Path('src/other.py').write_text('first\\n')")
    assert result.returncode == 0
    assert verify(tmp_path, command).returncode == 0
    other.write_text("late tamper\n", encoding="utf-8")
    assert verify(tmp_path, command).returncode == 2


def test_rejects_noninteger_command_exit_code(tmp_path):
    init_repo(tmp_path)
    result, command = record(tmp_path)
    assert result.returncode == 0
    path = tmp_path / "receipt.json"
    data = json.loads(path.read_text())
    data["commands"][0]["exit_code"] = False
    path.write_text(json.dumps(data))
    assert verify(tmp_path, command).returncode == 2


@pytest.mark.parametrize("option", ["--target-files", "--allowed-scope"])
def test_recorder_rejects_git_metadata_targets_and_scopes_before_run(tmp_path, option):
    init_repo(tmp_path)
    marker = tmp_path / "src" / "ran.txt"
    args = [sys.executable, str(RECORDER), "--output", "receipt.json"]
    if option == "--target-files":
        args += ["--target-files", ".git/config", "--allowed-scope", "src/"]
    else:
        args += ["--allowed-scope", ".git/"]
    result = subprocess.run(
        args + ["--", sys.executable, "-c",
                "from pathlib import Path; Path('src/ran.txt').touch()"],
        cwd=tmp_path, capture_output=True, text=True,
    )
    assert result.returncode == 2
    assert not marker.exists()
