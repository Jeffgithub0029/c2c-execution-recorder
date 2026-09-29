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


def test_committed_change_during_command_fails_closed(tmp_path: Path):
    _repo(tmp_path)
    (tmp_path / "src").mkdir()
    receipt = tmp_path / "receipt.json"
    cmd = (
        "echo bad > unapproved.txt && git add unapproved.txt && "
        "git -c user.name=T -c user.email=t@e commit -qm 'sneak commit'"
    )
    result = subprocess.run(
        [sys.executable, str(RECORDER), "--output", str(receipt), "--allowed-scope", "src/",
         "--", "sh", "-c", cmd],
        cwd=tmp_path, capture_output=True, text=True,
    )
    assert result.returncode == 2
    data = json.loads(receipt.read_text())["working_tree_fingerprint"]
    assert data["scope_containment"] == "failed"
    assert any(v.startswith("HEAD_CHANGED:") for v in data["scope_violations"])


def test_head_change_without_allowed_scope_fails_closed(tmp_path: Path):
    _repo(tmp_path)
    receipt = tmp_path / "receipt.json"
    cmd = "git -c user.name=T -c user.email=t@e commit --allow-empty -qm 'empty commit'"
    result = subprocess.run(
        [sys.executable, str(RECORDER), "--output", str(receipt),
         "--", "sh", "-c", cmd],
        cwd=tmp_path, capture_output=True, text=True,
    )
    assert result.returncode == 2
    assert "Git HEAD changed" in result.stderr


def test_command_writing_to_declared_output_outside_scope_fails_closed(tmp_path: Path):
    _repo(tmp_path)
    (tmp_path / "src").mkdir()
    # Output path is declared at unapproved.txt (outside allowed scope src/)
    receipt = tmp_path / "unapproved.txt"
    result = subprocess.run(
        [sys.executable, str(RECORDER), "--output", str(receipt), "--allowed-scope", "src/",
         "--", sys.executable, "-c", "open('unapproved.txt', 'w').write('sneak')"],
        cwd=tmp_path, capture_output=True, text=True,
    )
    assert result.returncode == 2
    data = json.loads(receipt.read_text())["working_tree_fingerprint"]
    assert data["scope_containment"] == "failed"
    assert "unapproved.txt" in data["scope_violations"]


def test_command_writing_basename_matching_external_output_fails_closed(tmp_path: Path):
    _repo(tmp_path)
    (tmp_path / "src").mkdir()
    # Output is outside repo, but command writes a file with same basename inside repo
    ext_receipt = tmp_path.parent / "escape_receipt.json"
    result = subprocess.run(
        [sys.executable, str(RECORDER), "--output", str(ext_receipt), "--allowed-scope", "src/",
         "--", sys.executable, "-c", "open('escape_receipt.json', 'w').write('sneak')"],
        cwd=tmp_path, capture_output=True, text=True,
    )
    assert result.returncode == 2
    data = json.loads(ext_receipt.read_text())["working_tree_fingerprint"]
    assert data["scope_containment"] == "failed"
    assert "escape_receipt.json" in data["scope_violations"]


def test_target_file_hash_reflects_post_run_content(tmp_path: Path):
    _repo(tmp_path)
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    target_file = src_dir / "app.py"
    target_file.write_text("initial_content", encoding="utf-8")
    subprocess.run(["git", "add", "src/app.py"], cwd=tmp_path, check=True)
    subprocess.run(["git", "-c", "user.name=T", "-c", "user.email=t@e", "commit", "-qm", "add app"], cwd=tmp_path, check=True)

    receipt = tmp_path / "receipt.json"
    result = subprocess.run(
        [sys.executable, str(RECORDER), "--output", str(receipt),
         "--target-files", "src/app.py", "--allowed-scope", "src/",
         "--", sys.executable, "-c", "open('src/app.py', 'w').write('updated_content')"],
        cwd=tmp_path, capture_output=True, text=True,
    )
    assert result.returncode == 0
    data = json.loads(receipt.read_text())["working_tree_fingerprint"]
    assert data["scope_containment"] == "passed"
    import hashlib
    expected_sha = "sha256:" + hashlib.sha256(b"updated_content").hexdigest()
    assert data["target_file_hashes"]["src/app.py"] == expected_sha


def test_explicit_target_deleted_during_command_fails_closed(tmp_path: Path):
    _repo(tmp_path)
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "target.py").write_text("old", encoding="utf-8")
    subprocess.run(["git", "add", "src/target.py"], cwd=tmp_path, check=True)
    subprocess.run(["git", "-c", "user.name=T", "-c", "user.email=t@e",
                    "commit", "-qm", "add target"], cwd=tmp_path, check=True)
    receipt = tmp_path / "receipt.json"
    result = subprocess.run(
        [sys.executable, str(RECORDER), "--output", str(receipt),
         "--target-files", "src/target.py", "--allowed-scope", "src/",
         "--", sys.executable, "-c", "import os; os.unlink('src/target.py')"],
        cwd=tmp_path, capture_output=True, text=True,
    )
    assert result.returncode == 2
    data = json.loads(receipt.read_text())["working_tree_fingerprint"]
    assert data["target_file_hashes"]["src/target.py"] == "sha256:file_not_found"
    assert "TARGET_HASH_UNAVAILABLE:src/target.py" in data["scope_violations"]


def test_target_file_symlink_rejected(tmp_path: Path):
    _repo(tmp_path)
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    real_file = src_dir / "real.py"
    real_file.write_text("print('real')", encoding="utf-8")
    symlink_file = src_dir / "sym.py"
    symlink_file.symlink_to(real_file)

    receipt = tmp_path / "receipt.json"
    result = subprocess.run(
        [sys.executable, str(RECORDER), "--output", str(receipt),
         "--target-files", "src/sym.py", "--allowed-scope", "src/",
         "--", sys.executable, "-c", "print('ok')"],
        cwd=tmp_path, capture_output=True, text=True,
    )
    assert result.returncode == 2
    assert "is a symlink" in result.stderr


def test_target_file_outside_repo_rejected(tmp_path: Path):
    _repo(tmp_path)
    receipt = tmp_path / "receipt.json"
    result = subprocess.run(
        [sys.executable, str(RECORDER), "--output", str(receipt),
         "--target-files", "../outside.py", "--allowed-scope", "src/",
         "--", sys.executable, "-c", "print('ok')"],
        cwd=tmp_path, capture_output=True, text=True,
    )
    assert result.returncode == 2
    assert "resolves outside repository root" in result.stderr


def test_git_status_porcelain_z_whitespace_quotes_and_renames(tmp_path: Path):
    _repo(tmp_path)
    (tmp_path / "src").mkdir()
    orig = tmp_path / "src" / 'my file "with quotes".txt'
    orig.write_text("content", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)
    subprocess.run(["git", "-c", "user.name=T", "-c", "user.email=t@e", "commit", "-qm", "add quoted"], cwd=tmp_path, check=True)

    # Git rename to a name with space and quotes
    renamed = tmp_path / "src" / 'renamed "quote" file.txt'
    subprocess.run(["git", "mv", str(orig), str(renamed)], cwd=tmp_path, check=True)

    receipt = tmp_path / "receipt.json"
    result = subprocess.run(
        [sys.executable, str(RECORDER), "--output", str(receipt), "--allowed-scope", "src/",
         "--", sys.executable, "-c", "print('verified')"],
        cwd=tmp_path, capture_output=True, text=True,
    )
    assert result.returncode == 0
    data = json.loads(receipt.read_text())["working_tree_fingerprint"]
    assert data["scope_containment"] == "passed"
    assert 'src/renamed "quote" file.txt' in data["modified_files"]
    assert 'src/my file "with quotes".txt' in data["modified_files"]
