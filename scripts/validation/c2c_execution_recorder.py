#!/usr/bin/env python3
"""c2c_execution_recorder.py — C2C Protocol v2.0 Execution Record 生成器.

作用：
1. 包装任意测试或探针执行命令（pytest, npm test, vitest, go test, bash probe 等），
2. 捕获真实命令、耗时、退出码与用例统计，
3. 提取当前 git 身份指纹（commit + dirty 状态 + pre/post 内容与状态级哈希清单），
4. 验证任务范围遏制（Scope Containment）：
   - 支持新增、修改、以及对已有 clean tracked 文件的删除与重命名捕获；
   - 对 Git 可见的最终状态越界变动强制以 exit_code=2 异常退出；忽略文件及瞬态变动不在此范围；
5. 计算被测代码、测试文件以及 recorder 自身的 SHA-256 密码学指纹，
6. 执行本地脱敏，将结构化产物写入指定路径（默认 tmp/execution_summary.json）。
"""

from __future__ import annotations

import argparse
import datetime
import fnmatch
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple


SENSITIVE_PATTERNS = [
    re.compile(r"(?i)(api[_-]?key|secret|token|password|passwd|bearer)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-\.]{8,})['\"]?"),
    re.compile(r"(?i)bearer\s+[^\s,;'\"]{3,}"),
    re.compile(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+ PRIVATE KEY-----"),
]

SOURCE_EXTENSIONS = (
    ".py",
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
    ".go",
    ".rs",
    ".sh",
    ".json",
    ".sql",
    ".yaml",
    ".yml",
    ".md",
)


def sanitize_text(text: str) -> Tuple[str, int]:
    """对输出文本脱敏，屏蔽 Token、私钥及敏感参数，截断超大输出至 40KB 以内."""
    redactions = 0
    sanitized = text

    for pat in SENSITIVE_PATTERNS:
        matches = list(pat.finditer(sanitized))
        if matches:
            redactions += len(matches)
            sanitized = pat.sub("[REDACTED]", sanitized)

    # 40KB 截断保护
    max_bytes = 40 * 1024
    encoded = sanitized.encode("utf-8")
    if len(encoded) > max_bytes:
        redactions += 1
        keep_head = 20 * 1024
        keep_tail = 20 * 1024
        head_part = encoded[:keep_head].decode("utf-8", errors="ignore")
        tail_part = encoded[-keep_tail:].decode("utf-8", errors="ignore")
        sanitized = (
            head_part
            + f"\n\n... [TRUNCATED BY C2C RECORDER: {len(encoded)} bytes exceeded 40KB limit] ...\n\n"
            + tail_part
        )

    return sanitized, redactions


def compute_file_sha256(file_path: Path) -> str:
    """计算单个文件的 SHA-256（带 sha256: 前缀）."""
    if file_path.is_symlink():
        return "sha256:error_symlink_rejected"
    if not file_path.is_file():
        return "sha256:file_not_found"
    h = hashlib.sha256()
    try:
        with file_path.open("rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return f"sha256:{h.hexdigest()}"
    except Exception as e:
        return f"sha256:error_{e}"


def _check_target_path_security(cwd: Path, p_str: str) -> Path:
    """验证目标文件路径位于仓库内部且非符号链接.

    若为符号链接、路径穿越或超出仓库根目录，直接抛出 ValueError (Fail-Closed).
    """
    raw_path = Path(p_str)
    abs_path = raw_path if raw_path.is_absolute() else (cwd / raw_path)

    if abs_path.is_symlink():
        raise ValueError(
            f"Target file '{p_str}' is a symlink; symlinks are rejected for fingerprinting."
        )

    cwd_resolved = cwd.resolve()
    try:
        resolved = abs_path.resolve()
        relative = resolved.relative_to(cwd_resolved)
    except ValueError:
        raise ValueError(
            f"Target file '{p_str}' resolves outside repository root '{cwd}'."
        )

    if ".git" in relative.parts:
        raise ValueError(f"Target file '{p_str}' is Git metadata, outside snapshot coverage.")
    return abs_path


def get_git_state(cwd: Path) -> Tuple[str, bool, Dict[str, Any], Dict[str, str]]:
    """提取真实 Git commit、工作区状态指纹及所有状态/变更文件的指纹清单."""
    try:
        res_commit = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=cwd,
            capture_output=True,
            text=True,
            check=True,
        )
        git_commit = res_commit.stdout.strip()
    except Exception:
        git_commit = "unknown_commit"

    manifest: Dict[str, str] = {}
    modified_files = []
    untracked_files = []
    dirty = False

    try:
        # 强制使用 --porcelain=v1 与 -z，以 NUL 分隔处理含空格、引号及重命名的路径
        res_status = subprocess.run(
            ["git", "status", "--porcelain=v1", "-z", "-uall"],
            cwd=cwd,
            capture_output=True,
            check=True,
        )
        raw_bytes = res_status.stdout
        dirty = len(raw_bytes) > 0

        entries = raw_bytes.split(b"\x00")
        i = 0
        while i < len(entries):
            entry = entries[i]
            if not entry:
                i += 1
                continue

            # 每个条目前 2 字节为状态码，第 3 字节为空格
            status_code = entry[:2].decode("ascii", errors="replace")
            path_bytes = entry[3:]
            file_name = os.fsdecode(path_bytes)

            # 处理重命名/复制：形如 'R  new_path\0old_path\0'
            if "R" in status_code or "C" in status_code:
                i += 1
                if i < len(entries):
                    orig_file_name = os.fsdecode(entries[i])
                    modified_files.extend([orig_file_name, file_name])
                    manifest[orig_file_name] = f"RENAMED_FROM:{status_code}"
                    fp_new = cwd / file_name
                    if fp_new.is_symlink():
                        try:
                            target = os.readlink(fp_new)
                            manifest[file_name] = f"SYMLINK:{status_code}:{target}"
                        except OSError:
                            manifest[file_name] = f"SYMLINK:{status_code}"
                    elif fp_new.is_file():
                        manifest[file_name] = compute_file_sha256(fp_new)
                    else:
                        manifest[file_name] = f"STATUS:{status_code}"
                i += 1
                continue

            if status_code == "??":
                untracked_files.append(file_name)
            else:
                modified_files.append(file_name)

            fp = cwd / file_name
            if fp.is_symlink():
                try:
                    target = os.readlink(fp)
                    manifest[file_name] = f"SYMLINK:{status_code}:{target}"
                except OSError:
                    manifest[file_name] = f"SYMLINK:{status_code}"
            elif fp.is_file():
                manifest[file_name] = compute_file_sha256(fp)
            else:
                # 文件不存在（如已删除），显式记录状态码作为指纹，防止删除逃逸
                manifest[file_name] = f"DELETED_OR_MISSING:{status_code}"

            i += 1

        fingerprint = {
            "modified_files": sorted(set(modified_files)),
            "untracked_files": sorted(set(untracked_files)),
        }
    except Exception as e:
        dirty = True
        fingerprint = {"error": f"Failed to get git status: {e}"}

    return git_commit, dirty, fingerprint, manifest


def snapshot_ignored_files(cwd: Path) -> Dict[str, str]:
    """Bounded net-state hash audit for Git-ignored files, not an OS sandbox."""
    result = subprocess.run(
        ["git", "ls-files", "--others", "--ignored", "--exclude-standard", "-z"],
        cwd=cwd, capture_output=True, check=True,
    )
    paths = [os.fsdecode(p) for p in result.stdout.split(b"\x00") if p]
    if len(paths) > 10000:
        raise ValueError("Ignored-file audit exceeds 10000 entries")
    manifest: Dict[str, str] = {}
    for path in paths:
        file_path = cwd / path
        if file_path.is_symlink():
            manifest[path] = f"SYMLINK:{os.readlink(file_path)}"
        elif file_path.is_file():
            digest = compute_file_sha256(file_path)
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
                raise ValueError(f"Ignored-file hash unavailable: {path}")
            manifest[path] = digest
        else:
            raise ValueError(f"Ignored-file entry is not a regular file or symlink: {path}")
    return manifest


def collect_target_file_hashes(
    cwd: Path,
    explicit_targets: List[str] | None,
    cmd: List[str],
    modified_files: List[str],
) -> Dict[str, str]:
    """收集关键被审查文件和测试文件的 SHA-256 指纹."""
    cwd_resolved = cwd.resolve()
    hashes: Dict[str, str] = {}

    if explicit_targets:
        for t in explicit_targets:
            abs_p = _check_target_path_security(cwd, t)
            try:
                rel_str = str(abs_p.resolve().relative_to(cwd_resolved))
            except ValueError:
                rel_str = str(abs_p.relative_to(cwd))
            if abs_p.is_file():
                hashes[rel_str] = compute_file_sha256(abs_p)
            else:
                hashes[rel_str] = "sha256:file_not_found"
        return hashes

    candidates = set()
    for arg in cmd:
        if arg.endswith(SOURCE_EXTENSIONS):
            candidates.add(arg)
            p = Path(arg)
            if p.name.startswith("test_") and p.name.endswith(".py"):
                base_name = p.name[5:]
                candidates.add(str(p.parent / base_name))
                candidates.add(f"src/{base_name}")

    if not candidates:
        for m in modified_files:
            if m.endswith(SOURCE_EXTENSIONS):
                candidates.add(m)

    for rel_path in sorted(candidates):
        raw_p = Path(rel_path)
        abs_p = raw_p if raw_p.is_absolute() else (cwd / raw_p)
        if abs_p.is_symlink():
            raise ValueError(
                f"Target file candidate '{rel_path}' is a symlink; symlinks are rejected."
            )
        try:
            resolved_p = abs_p.resolve()
            resolved_p.relative_to(cwd_resolved)
        except ValueError:
            continue

        if abs_p.is_file():
            try:
                rel_str = str(resolved_p.relative_to(cwd_resolved))
            except ValueError:
                rel_str = str(abs_p.relative_to(cwd))
            hashes[rel_str] = compute_file_sha256(abs_p)

    return hashes


def infer_project_type(cmd: List[str]) -> str:
    cmd_str = " ".join(cmd).lower()
    if "pytest" in cmd_str or "python" in cmd_str or "unittest" in cmd_str:
        return "python"
    elif "npm" in cmd_str or "yarn" in cmd_str or "vitest" in cmd_str or "jest" in cmd_str:
        return "node"
    elif "go test" in cmd_str:
        return "go"
    elif "cargo test" in cmd_str:
        return "rust"
    elif "bash" in cmd_str or "sh " in cmd_str or "probe" in cmd_str:
        return "bash_probe"
    return "generic"


def parse_test_summary(output: str, project_type: str, exit_code: int) -> Dict[str, int]:
    counts = {"passed": 0, "failed": 0, "skipped": 0}
    if project_type == "python":
        m = re.search(r"(?:==+\s*)?([0-9]+)\s+passed", output)
        if m:
            counts["passed"] = int(m.group(1))
        m_fail = re.search(r"(?:==+\s*)?([0-9]+)\s+failed", output)
        if m_fail:
            counts["failed"] = int(m_fail.group(1))
        m_skip = re.search(r"(?:==+\s*)?([0-9]+)\s+skipped", output)
        if m_skip:
            counts["skipped"] = int(m_skip.group(1))
        if exit_code != 0 and counts["failed"] == 0:
            counts["failed"] = 1
    elif project_type == "node":
        m_pass = re.search(r"([0-9]+)\s+passed", output)
        if m_pass:
            counts["passed"] = int(m_pass.group(1))
        m_fail = re.search(r"([0-9]+)\s+failed", output)
        if m_fail:
            counts["failed"] = int(m_fail.group(1))
        m_skip = re.search(r"([0-9]+)\s+skipped", output)
        if m_skip:
            counts["skipped"] = int(m_skip.group(1))
        if exit_code != 0 and counts["failed"] == 0:
            counts["failed"] = 1
    elif project_type == "go":
        counts["passed"] = len(re.findall(r"^--- PASS:", output, re.M))
        counts["failed"] = len(re.findall(r"^--- FAIL:", output, re.M))
        counts["skipped"] = len(re.findall(r"^--- SKIP:", output, re.M))
        if exit_code != 0 and counts["failed"] == 0:
            counts["failed"] = 1
    else:
        counts["passed"] = 1 if exit_code == 0 else 0
        counts["failed"] = 0 if exit_code == 0 else 1

    return counts


def run_command_and_record(
    cmd: List[str],
    cwd: Path,
    project_type: str,
    command_id: str = "test-run",
) -> Tuple[Dict[str, Any], List[str], int]:
    """执行命令并捕获脱敏输出及结构化结果."""
    start_time = time.perf_counter()
    proc = subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=True,
        text=True,
    )
    duration = round(time.perf_counter() - start_time, 2)
    raw_output = proc.stdout + ("\n" + proc.stderr if proc.stderr else "")
    sanitized_output, out_redactions = sanitize_text(raw_output)

    # 对记录的命令字符串做尽力脱敏（Best-effort regex redaction）
    raw_command_str = " ".join(cmd)
    sanitized_command_str, cmd_redactions = sanitize_text(raw_command_str)
    sanitized_argv = []
    argv_redactions = 0
    for arg in cmd:
        sanitized_arg, count = sanitize_text(arg)
        sanitized_argv.append(sanitized_arg)
        argv_redactions += count
    argv_bytes = json.dumps(sanitized_argv, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    redactions = out_redactions + cmd_redactions + argv_redactions

    tests_summary = parse_test_summary(sanitized_output, project_type, proc.returncode)
    failures = []
    if tests_summary["failed"] > 0:
        failures.append(f"Test summary reports {tests_summary['failed']} failed")
    if proc.returncode != 0:
        for line in sanitized_output.splitlines():
            clean_line = line.strip()
            if (
                clean_line.startswith("FAILED ")
                or clean_line.startswith("ERROR ")
                or clean_line.startswith("FAIL:")
                or clean_line.startswith("--- FAIL:")
            ):
                failures.append(clean_line)
        if not failures:
            failures.append(f"Command exited with non-zero code {proc.returncode}")

    cmd_record = {
        "command_id": command_id,
        "command": sanitized_command_str,
        "command_argv_sha256": "sha256:" + hashlib.sha256(argv_bytes).hexdigest(),
        "command_args_redacted": bool(cmd_redactions or argv_redactions),
        "exit_code": proc.returncode,
        "duration_sec": duration,
        "tests": tests_summary,
        "output_preview": sanitized_output[-1200:].strip(),
    }
    return cmd_record, failures, redactions


def main() -> int:
    parser = argparse.ArgumentParser(description="Record execution into a sanitized C2C v2.0 summary JSON.")
    parser.add_argument("--output", "-o", default="tmp/execution_summary.json", help="Output path")
    parser.add_argument("--command-id", default="test-targeted", help="Command identifier")
    parser.add_argument("--project-type", choices=["python", "node", "go", "bash_probe", "rust", "generic"], default=None, help="Explicit project type")
    parser.add_argument("--target-files", nargs="*", default=None, help="Explicit files to calculate SHA-256 for")
    parser.add_argument("--allowed-scope", nargs="*", default=None, help="Allowed directory or file scopes for scope containment gate")
    parser.add_argument("--audit-ignored", action="store_true", help="Hash up to 10000 Git-ignored files before/after (requires --allowed-scope)")
    parser.add_argument("cmd", nargs=argparse.REMAINDER, help="Test command to run (after --)")

    args = parser.parse_args()
    if not args.cmd:
        print("Error: No command specified. Usage: c2c_execution_recorder.py -- pytest ...", file=sys.stderr)
        return 1

    command = args.cmd
    if command[0] == "--":
        command = command[1:]
    if not command:
        print("Error: Empty command after --", file=sys.stderr)
        return 1

    if args.audit_ignored and not args.allowed_scope:
        print("[C2C Record v2.0] ERROR: --audit-ignored requires --allowed-scope", file=sys.stderr)
        return 2

    if args.allowed_scope and any(".git" in Path(scope).parts for scope in args.allowed_scope):
        print("[C2C Record v2.0] ERROR: Git metadata is outside snapshot coverage", file=sys.stderr)
        return 2

    cwd = Path.cwd()
    if args.audit_ignored:
        try:
            repo_root = subprocess.run(
                ["git", "rev-parse", "--show-toplevel"], cwd=cwd,
                capture_output=True, text=True, check=True,
            ).stdout.strip()
        except (OSError, subprocess.CalledProcessError) as exc:
            print(f"[C2C Record v2.0] FAIL-CLOSED ERROR: Cannot determine repository root: {exc}", file=sys.stderr)
            return 2
        if cwd.resolve() != Path(repo_root).resolve():
            print("[C2C Record v2.0] FAIL-CLOSED ERROR: --audit-ignored requires running from repository root", file=sys.stderr)
            return 2
    this_script = Path(__file__).resolve()
    recorder_hash = compute_file_sha256(this_script)

    project_type = args.project_type or infer_project_type(command)

    # 0. Early validation of explicit target files
    if args.target_files:
        for tf in args.target_files:
            try:
                _check_target_path_security(cwd, tf)
            except ValueError as e:
                print(f"[C2C Record v2.0] ERROR: Invalid target file: {e}", file=sys.stderr)
                return 2

    # 1. Pre-run baseline status and content hash manifest
    pre_commit, pre_dirty, pre_fingerprint, pre_manifest = get_git_state(cwd)
    pre_ignored: Dict[str, str] = {}
    if args.audit_ignored:
        try:
            pre_ignored = snapshot_ignored_files(cwd)
            pre_manifest.update(pre_ignored)
        except (OSError, subprocess.CalledProcessError, ValueError) as exc:
            print(f"[C2C Record v2.0] FAIL-CLOSED ERROR: Pre-run ignored-file audit failed: {exc}", file=sys.stderr)
            return 2

    # 2. Execute command
    cmd_record, failures, redactions = run_command_and_record(
        command, cwd, project_type=project_type, command_id=args.command_id
    )

    # 3. Post-run status and content hash manifest
    post_commit, post_dirty, post_fingerprint, post_manifest = get_git_state(cwd)
    post_git_manifest = post_manifest.copy()
    ignored_audit_error = None
    if args.audit_ignored:
        try:
            post_ignored = snapshot_ignored_files(cwd)
            post_manifest.update(post_ignored)
        except (OSError, subprocess.CalledProcessError, ValueError) as exc:
            ignored_audit_error = str(exc)

    # 4. Target file hashes collected post-run (保证哈希反映最终产物真实状态)
    try:
        target_hashes = collect_target_file_hashes(
            cwd,
            args.target_files,
            command,
            post_fingerprint.get("modified_files", []) + post_fingerprint.get("untracked_files", []),
        )
    except ValueError as e:
        print(f"[C2C Record v2.0] ERROR: Target file validation failed: {e}", file=sys.stderr)
        return 2

    # 基于内容哈希精确比对：任何新增、删除、重命名或既有文件内容变动均计入 delta
    all_status_keys = set(pre_manifest.keys()) | set(post_manifest.keys())
    changed_delta = sorted([
        k for k in all_status_keys
        if pre_manifest.get(k) != post_manifest.get(k)
    ])

    # Only the net pre/post HEAD state is observable, not transient revisions.
    head_changed = (pre_commit != post_commit)

    fingerprint = post_fingerprint
    fingerprint["pre_run_dirty"] = pre_dirty
    fingerprint["post_run_delta"] = changed_delta
    fingerprint["post_run_git_manifest"] = post_git_manifest
    fingerprint["target_file_hashes"] = target_hashes
    fingerprint["pre_run_commit"] = pre_commit
    fingerprint["post_run_commit"] = post_commit
    fingerprint["head_changed"] = head_changed
    if args.audit_ignored:
        fingerprint["ignored_file_audit"] = "failed" if ignored_audit_error else "completed"
    invalid_targets = [p for p, h in target_hashes.items()
                       if h == "sha256:file_not_found" or h.startswith("sha256:error_")]
    if invalid_targets:
        fingerprint["invalid_target_hashes"] = invalid_targets

    # 5. Scope containment verification (B3, 内容与状态级全闭环比对)
    if args.allowed_scope:
        fingerprint["allowed_scope"] = args.allowed_scope
        fingerprint["task_target_files"] = sorted(target_hashes.keys())

        # 检验集包含：显式 target 文件 + 命令执行期间发生内容/状态变动的所有文件。
        # 绝不隐藏任何目录或文件后缀全局豁免，亦不给 output 产物路径任何白名单豁免；
        # 命令若写出越界文件，即使路径与 output 相同亦判定越界。
        all_eval_paths = set(target_hashes.keys()) | set(changed_delta)

        # Git is the scope oracle. Without a valid pre/post status (or a commit),
        # an empty delta is not proof that the command stayed in bounds.
        git_unavailable = (
            pre_commit == "unknown_commit"
            or post_commit == "unknown_commit"
            or "error" in pre_fingerprint
            or "error" in post_fingerprint
        )
        scope_passed = not git_unavailable
        violations = ["GIT_STATE_UNAVAILABLE"] if git_unavailable else []

        if head_changed:
            scope_passed = False
            violations.append(f"HEAD_CHANGED:{pre_commit}->{post_commit}")

        if invalid_targets:
            scope_passed = False
            violations.extend(f"TARGET_HASH_UNAVAILABLE:{p}" for p in invalid_targets)

        if ignored_audit_error:
            scope_passed = False
            violations.append("IGNORED_FILE_AUDIT_FAILED")

        for tf in sorted(all_eval_paths):
            matched = False
            for scope in args.allowed_scope:
                clean_scope = scope.rstrip("/*")
                if tf == clean_scope or tf.startswith(clean_scope + "/") or fnmatch.fnmatch(tf, scope):
                    matched = True
                    break
            if not matched:
                scope_passed = False
                violations.append(tf)

        fingerprint["scope_containment"] = "passed" if scope_passed else "failed"
        if not scope_passed:
            fingerprint["scope_violations"] = violations

    out_path = Path(args.output)
    if not out_path.is_absolute():
        out_path = cwd / out_path
    out_path.parent.mkdir(parents=True, exist_ok=True)

    record_payload = {
        "schema_version": "2.0",
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "recorder_sha256": recorder_hash,
        "project_type": project_type,
        "git_commit": post_commit,
        "dirty_tree": post_dirty,
        "working_tree_fingerprint": fingerprint,
        "commands": [cmd_record],
        "failures": failures,
        "sanitization": {
            "status": "passed",
            "redactions": redactions,
            "size_bytes": 0,
        },
    }

    # 循环收敛计算 size_bytes，确保元数据大小与最终 UTF-8 JSON 字节数严格一致
    size = 0
    serialized = ""
    for _ in range(5):
        record_payload["sanitization"]["size_bytes"] = size
        serialized = json.dumps(record_payload, indent=2, ensure_ascii=False)
        new_size = len(serialized.encode("utf-8"))
        if new_size == size:
            break
        size = new_size

    out_path.write_text(serialized, encoding="utf-8")

    print(f"[C2C Record v2.0] Wrote execution summary to {out_path}")
    print(
        f"[C2C Record v2.0] Type: {project_type}, Commit: {post_commit[:8]}, Dirty: {post_dirty}, Exit: {cmd_record['exit_code']}, Tests: {cmd_record['tests']}"
    )

    # Fail-Closed 铁律：命令执行期间若变更 HEAD，即使未指定 allowed_scope 亦强制以 exit code 2 阻断
    if head_changed and not args.allowed_scope:
        print(
            f"[C2C Record v2.0] FAIL-CLOSED ERROR: Git HEAD changed during command execution ({pre_commit} -> {post_commit})",
            file=sys.stderr,
        )
        return 2

    if invalid_targets and not args.allowed_scope:
        print("[C2C Record v2.0] FAIL-CLOSED ERROR: Target hash unavailable", file=sys.stderr)
        return 2

    # Fail-Closed 铁律：若 scope_containment 失败，强制返回 exit code 2 阻断
    if args.allowed_scope and fingerprint.get("scope_containment") != "passed":
        print(
            f"[C2C Record v2.0] FAIL-CLOSED ERROR: Scope containment failed! Violations: {fingerprint.get('scope_violations')}",
            file=sys.stderr,
        )
        return 2

    if cmd_record["tests"]["failed"] > 0:
        print("[C2C Record v2.0] FAIL-CLOSED ERROR: Test summary reports failures", file=sys.stderr)
        return 2

    return cmd_record["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
