"""Expected-pass demonstrations of three blind spots; never call them containment tests."""
import json
import subprocess
import sys
import time
from pathlib import Path

RECORDER = Path(__file__).resolve().parents[1] / "scripts/validation/c2c_execution_recorder.py"


def init_repo(path):
    subprocess.run(["git", "init", "-q"], cwd=path, check=True)
    (path / "src").mkdir()
    (path / "src" / "engine.py").write_text("ok\n", encoding="utf-8")
    (path / "forbidden.txt").write_text("original\n", encoding="utf-8")
    (path / ".gitignore").write_text("receipt.json\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=path, check=True)
    subprocess.run(["git", "-c", "user.name=Test", "-c", "user.email=test@example.com",
                    "commit", "-qm", "initial"], cwd=path, check=True)


def run_recorder(path, code):
    result = subprocess.run(
        [sys.executable, str(RECORDER), "--output", "receipt.json", "--audit-ignored",
         "--allowed-scope", "src/", "--target-files", "src/engine.py",
         "--", sys.executable, "-c", code],
        cwd=path, capture_output=True, text=True,
    )
    receipt = json.loads((path / "receipt.json").read_text(encoding="utf-8"))
    return result, receipt["working_tree_fingerprint"]


def assert_snapshot_passed(result, fingerprint):
    assert result.returncode == 0, result.stderr
    assert fingerprint["scope_containment"] == "passed"
    assert fingerprint["ignored_file_audit"] == "completed"


def test_external_path_is_outside_snapshot_even_with_ignored_audit(tmp_path):
    init_repo(tmp_path)
    external = tmp_path.parent / (tmp_path.name + "-external.txt")
    try:
        code = f"from pathlib import Path; Path({str(external)!r}).write_text('external')"
        result, fingerprint = run_recorder(tmp_path, code)
        assert_snapshot_passed(result, fingerprint)
        assert external.read_text(encoding="utf-8") == "external"
        assert not fingerprint["post_run_delta"]
    finally:
        external.unlink(missing_ok=True)


def test_transient_forbidden_write_is_restored_before_snapshot(tmp_path):
    init_repo(tmp_path)
    code = ("from pathlib import Path; p=Path('forbidden.txt'); before=p.read_text(); "
            "p.write_text('changed'); Path('src/witness.txt').write_text(p.read_text()); "
            "p.write_text(before)")
    result, fingerprint = run_recorder(tmp_path, code)
    assert_snapshot_passed(result, fingerprint)
    assert (tmp_path / "src" / "witness.txt").read_text() == "changed"
    assert (tmp_path / "forbidden.txt").read_text() == "original\n"
    assert "forbidden.txt" not in fingerprint["post_run_delta"]


def test_detached_writer_can_write_after_recorder_snapshot(tmp_path):
    init_repo(tmp_path)
    marker = tmp_path.parent / (tmp_path.name + "-release")
    worker = ("import time; from pathlib import Path; release=Path(" + repr(str(marker)) + "); "
              "target=Path('forbidden.txt'); deadline=time.monotonic()+30; "
              "[(time.sleep(0.02)) for _ in range(1500) "
              "if not release.exists() and time.monotonic()<deadline]; "
              "target.write_text('late writer') if release.exists() else None")
    code = ("import subprocess, sys; p=subprocess.Popen([sys.executable, '-c', "
            + repr(worker) + "], cwd='.', stdin=subprocess.DEVNULL, "
            "stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)")
    try:
        result, fingerprint = run_recorder(tmp_path, code)
        assert_snapshot_passed(result, fingerprint)
        assert (tmp_path / "forbidden.txt").read_text() == "original\n"
        marker.touch()
        for _ in range(300):
            if (tmp_path / "forbidden.txt").read_text() == "late writer":
                break
            time.sleep(0.05)
        assert (tmp_path / "forbidden.txt").read_text() == "late writer"
        assert "forbidden.txt" not in fingerprint["post_run_delta"]
    finally:
        marker.touch(exist_ok=True)
        # The detached helper has a finite deadline; leaving the release
        # marker lets it exit even when an earlier assertion fails.
