"""Public, isolated regressions distilled from an earlier local scope trial."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

RECORDER = Path(__file__).resolve().parents[1] / "scripts" / "validation" / "c2c_execution_recorder.py"


def _repo(path: Path) -> None:
    subprocess.run(["git", "init", "-q"], cwd=path, check=True)
    subprocess.run(
        ["git", "-c", "user.name=Test", "-c", "user.email=test@example.com",
         "commit", "--allow-empty", "-qm", "initial"],
        cwd=path, check=True,
    )


@pytest.mark.parametrize(
    ("tracked", "operation", "changed_paths"),
    [
        (False, "open('outside/item.py', 'w').write('changed')", {"outside/item.py"}),
        (True, "open('outside/item.py', 'w').write('changed')", {"outside/item.py"}),
        (True, "import os; os.unlink('outside/item.py')", {"outside/item.py"}),
        (True, "import os; os.rename('outside/item.py', 'outside/moved.py')",
         {"outside/item.py", "outside/moved.py"}),
    ],
    ids=["existing-untracked-edit", "clean-tracked-edit", "clean-tracked-delete", "clean-tracked-rename"],
)
def test_existing_out_of_scope_changes_fail_closed(tmp_path: Path, tracked: bool,
                                                    operation: str, changed_paths: set[str]):
    _repo(tmp_path)
    (tmp_path / "outside").mkdir()
    (tmp_path / "outside" / "item.py").write_text("original", encoding="utf-8")
    if tracked:
        subprocess.run(["git", "add", "outside/item.py"], cwd=tmp_path, check=True)
        subprocess.run(
            ["git", "-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "-qm", "seed"],
            cwd=tmp_path, check=True,
        )

    receipt = tmp_path / "receipt.json"
    result = subprocess.run(
        [sys.executable, str(RECORDER), "--output", str(receipt), "--allowed-scope", "src/",
         "--", sys.executable, "-c", operation],
        cwd=tmp_path, capture_output=True, text=True,
    )
    assert result.returncode == 2
    fingerprint = json.loads(receipt.read_text(encoding="utf-8"))["working_tree_fingerprint"]
    assert fingerprint["scope_containment"] == "failed"
    assert changed_paths <= set(fingerprint["scope_violations"])
    assert changed_paths <= set(fingerprint["post_run_delta"])


@pytest.mark.parametrize("ignored_path", [
    "tmp/result.txt", ".pytest_cache/result.txt", "outside/__pycache__/result.pyc", "outside/result.pyc",
])
@pytest.mark.xfail(strict=True, reason="Default Git-status mode cannot observe ignored writes; use --audit-ignored for net changes")
def test_ignored_out_of_scope_write_is_not_yet_contained(tmp_path: Path, ignored_path: str):
    _repo(tmp_path)
    (tmp_path / ".gitignore").write_text("tmp/\n.pytest_cache/\n__pycache__/\n*.pyc\n", encoding="utf-8")
    subprocess.run(["git", "add", ".gitignore"], cwd=tmp_path, check=True)
    subprocess.run(
        ["git", "-c", "user.name=Test", "-c", "user.email=test@example.com",
         "commit", "-qm", "ignore generated files"],
        cwd=tmp_path, check=True,
    )
    receipt = tmp_path / "receipt.json"
    command = (
        "from pathlib import Path; p=Path('" + ignored_path + "'); "
        "p.parent.mkdir(parents=True, exist_ok=True); p.write_text('out of scope')"
    )
    result = subprocess.run(
        [sys.executable, str(RECORDER), "--output", str(receipt), "--allowed-scope", "src/",
         "--", sys.executable, "-c", command],
        cwd=tmp_path, capture_output=True, text=True,
    )
    assert result.returncode == 2
