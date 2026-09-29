import json
import subprocess
import sys
from pathlib import Path


RECORDER = Path(__file__).resolve().parents[1] / "scripts" / "validation" / "c2c_execution_recorder.py"


def _repo(path: Path) -> None:
    subprocess.run(["git", "init", "-q"], cwd=path, check=True)
    subprocess.run(["git", "-c", "user.name=Test", "-c", "user.email=test@example.com",
                    "commit", "--allow-empty", "-qm", "initial"], cwd=path, check=True)


def test_out_of_scope_new_file_blocks_successful_command(tmp_path: Path):
    _repo(tmp_path)
    receipt = tmp_path / "receipt.json"
    result = subprocess.run(
        [sys.executable, str(RECORDER), "--output", str(receipt), "--allowed-scope", "src/",
         "--", sys.executable, "-c", "open('unapproved.txt', 'w').write('new')"],
        cwd=tmp_path, capture_output=True, text=True,
    )
    assert result.returncode == 2
    assert "unapproved.txt" in json.loads(receipt.read_text())["working_tree_fingerprint"]["scope_violations"]


def test_in_scope_new_file_is_recorded(tmp_path: Path):
    _repo(tmp_path)
    (tmp_path / "src").mkdir()
    receipt = tmp_path / "receipt.json"
    result = subprocess.run(
        [sys.executable, str(RECORDER), "--output", str(receipt), "--allowed-scope", "src/",
         "--", sys.executable, "-c", "open('src/output.txt', 'w').write('new')"],
        cwd=tmp_path, capture_output=True, text=True,
    )
    assert result.returncode == 0
    data = json.loads(receipt.read_text())["working_tree_fingerprint"]
    assert data["scope_containment"] == "passed"
    assert "src/output.txt" in data["post_run_delta"]
