#!/usr/bin/env python3
"""Check a local recorder handoff against a trusted caller's expected context.

Not an authenticator: the caller must preserve the recorder exit status and choose
expected command, files, scope and checkout independently of the receipt.
"""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

from c2c_execution_recorder import get_git_state


def git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=repo, capture_output=True, text=True,
                          check=True).stdout.strip()


def checked_file(repo: Path, name: str) -> Path:
    path = repo / name
    if Path(name).is_absolute() or ".git" in Path(name).parts or path.is_symlink() or not path.is_file():
        raise ValueError(f"missing or unsafe target: {name}")
    if not path.resolve().is_relative_to(repo.resolve()):
        raise ValueError(f"target escapes checkout: {name}")
    return path


def validate(receipt: dict, repo: Path, receipt_path: Path, recorder_exit: int,
             expected_argv: list[str], expected_files: list[str],
             allowed_scope: list[str], require_ignored: bool) -> None:
    if recorder_exit != 0:
        raise ValueError("recorder process did not exit 0")
    if not isinstance(receipt, dict):
        raise ValueError("receipt must be a JSON object")
    if receipt.get("schema_version") != "2.0":
        raise ValueError("unknown receipt schema")
    commands = receipt.get("commands")
    if not isinstance(commands, list) or len(commands) != 1 or not isinstance(commands[0], dict):
        raise ValueError("expected exactly one command")
    if not isinstance(expected_argv, list) or not expected_argv or not all(isinstance(arg, str) for arg in expected_argv):
        raise ValueError("expected argv must be an array of strings")
    argv_bytes = json.dumps(expected_argv, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if (type(commands[0].get("exit_code")) is not int or commands[0]["exit_code"] != 0
            or commands[0].get("command_args_redacted") is not False
            or commands[0].get("command_argv_sha256") != "sha256:" + hashlib.sha256(argv_bytes).hexdigest()):
        raise ValueError("command differs or failed")
    tests = commands[0].get("tests")
    if (not isinstance(tests, dict) or type(tests.get("failed")) is not int
            or tests["failed"] != 0):
        raise ValueError("test summary missing or reports failures")
    if receipt.get("failures"):
        raise ValueError("receipt contains failures")
    fp = receipt.get("working_tree_fingerprint")
    if not isinstance(fp, dict):
        raise ValueError("missing working-tree fingerprint")
    if (not allowed_scope or fp.get("allowed_scope") != allowed_scope
            or fp.get("scope_containment") != "passed" or fp.get("scope_violations")
            or fp.get("head_changed") is not False or fp.get("invalid_target_hashes")):
        raise ValueError("scope or HEAD check incomplete or failed")
    if require_ignored and fp.get("ignored_file_audit") != "completed":
        raise ValueError("ignored-file audit not completed")
    if fp.get("ignored_file_audit") == "failed":
        raise ValueError("ignored-file audit failed")
    head = git(repo, "rev-parse", "HEAD")
    if (receipt.get("git_commit") != head or fp.get("pre_run_commit") != head
            or fp.get("post_run_commit") != head):
        raise ValueError("checkout HEAD differs from receipt")
    _, dirty, current, manifest = get_git_state(repo)
    if "error" in current:
        raise ValueError("cannot read current Git status")
    recorded_modified = fp.get("modified_files")
    recorded_untracked = fp.get("untracked_files")
    if not isinstance(recorded_modified, list) or not isinstance(recorded_untracked, list):
        raise ValueError("missing post-run status paths")
    actual_modified = set(current["modified_files"])
    actual_untracked = set(current["untracked_files"])
    # The recorder writes its output *after* the post-run snapshot. Only a
    # newly untracked exact receipt path may be subtracted; never a tracked
    # file or a path already present when the command finished.
    resolved_receipt = receipt_path.resolve()
    if resolved_receipt.is_relative_to(repo.resolve()):
        relative_receipt = resolved_receipt.relative_to(repo.resolve()).as_posix()
        if relative_receipt not in recorded_untracked:
            actual_untracked.discard(relative_receipt)
            manifest.pop(relative_receipt, None)
    if actual_modified != set(recorded_modified) or actual_untracked != set(recorded_untracked):
        raise ValueError("post-run Git paths differ from receipt")
    if fp.get("post_run_git_manifest") != manifest or any(
            isinstance(value, str) and value.startswith("sha256:error_") for value in manifest.values()):
        raise ValueError("post-run Git file fingerprints differ or are unreadable")
    for name in actual_modified | actual_untracked:
        if not any(name == scope.rstrip("/*") or name.startswith(scope.rstrip("/*") + "/")
                   or fnmatch.fnmatch(name, scope) for scope in allowed_scope):
            raise ValueError(f"current dirty path outside scope: {name}")
    dirty = bool(actual_modified or actual_untracked)
    if type(receipt.get("dirty_tree")) is not bool or receipt["dirty_tree"] != dirty:
        raise ValueError("checkout dirty state differs from receipt")
    hashes = fp.get("target_file_hashes")
    if not isinstance(hashes, dict) or not expected_files or not set(expected_files).issubset(hashes):
        raise ValueError("missing expected source/test/runner hashes")
    for name, digest in hashes.items():
        if not isinstance(name, str) or not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            raise ValueError("invalid target hash")
        actual = "sha256:" + hashlib.sha256(checked_file(repo, name).read_bytes()).hexdigest()
        if actual != digest:
            raise ValueError(f"target hash differs: {name}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate a trusted-local C2C receipt; not sandbox proof")
    parser.add_argument("--receipt", required=True)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--recorder-exit", type=int, required=True,
                        help="Actual outer recorder process exit code, captured by caller")
    parser.add_argument("--expected-argv-file", required=True,
                        help="Private UTF-8 JSON argv array selected independently by reviewer")
    parser.add_argument("--expected-file", action="append", required=True,
                        help="Expected source/test/runner path; repeat for every required file")
    parser.add_argument("--allowed-scope", action="append", required=True,
                        help="Scope selected independently; repeat for each path")
    parser.add_argument("--require-ignored", action="store_true")
    args = parser.parse_args()
    try:
        repo = Path(args.repo).resolve(strict=True)
        if repo != Path(git(repo, "rev-parse", "--show-toplevel")).resolve():
            raise ValueError("--repo must be the Git repository root")
        path = Path(args.receipt)
        if not path.is_absolute():
            path = repo / path
        receipt = json.loads(path.read_text(encoding="utf-8"))
        expected_argv = json.loads(Path(args.expected_argv_file).read_text(encoding="utf-8"))
        validate(receipt, repo, path, args.recorder_exit, expected_argv,
                 args.expected_file, args.allowed_scope, args.require_ignored)
    except (OSError, ValueError, TypeError, KeyError, subprocess.CalledProcessError) as exc:
        print(f"receipt_consumer_gate: NOT VERIFIED: {exc}", file=sys.stderr)
        return 2
    print("receipt_consumer_gate: verified local receipt (not write-prevention or sandbox proof)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
