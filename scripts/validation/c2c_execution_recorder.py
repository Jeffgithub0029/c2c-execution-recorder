#!/usr/bin/env python3
"""c2c_execution_recorder.py — C2C Protocol v2.0 Execution Record 生成器.

作用：
1. 包装任意测试或探针执行命令（pytest, npm test, vitest, go test, bash probe 等），
2. 捕获真实命令、耗时、退出码与用例统计，
3. 提取当前 git 身份指纹（commit + dirty 状态 + pre/post 内容与状态级哈希清单），
4. 验证任务范围遏制（Scope Containment）：
   - 支持新增、修改、以及对已有 clean tracked 文件的删除与重命名捕获；
   - 发生任何越界变动时强制以 exit_code=2 异常退出（Fail-Closed）；
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
        # 强制使用 -uall，逐文件递归展开所有 untracked 路径
        res_status = subprocess.run(
            ["git", "status", "--porcelain", "-uall"],
            cwd=cwd,
            capture_output=True,
            text=True,
            check=True,
        )
        status_lines = res_status.stdout.splitlines()
        dirty = len(status_lines) > 0

        for line in status_lines:
            if not line.strip():
                continue
            status_code = line[:2]
            raw_path = line[3:].strip()

            # 处理重命名：形如 "R  old_path -> new_path"
            if " -> " in raw_path:
                parts = raw_path.split(" -> ")
                old_p = parts[0].strip().strip('"')
                new_p = parts[1].strip().strip('"')
                modified_files.extend([old_p, new_p])
                manifest[old_p] = f"RENAMED_FROM:{status_code}"
                fp_new = cwd / new_p
                manifest[new_p] = compute_file_sha256(fp_new) if fp_new.is_file() else f"STATUS:{status_code}"
                continue

            file_name = raw_path.strip('"')
            if status_code == "??":
                untracked_files.append(file_name)
            else:
                modified_files.append(file_name)

            fp = cwd / file_name
            if fp.is_file():
                manifest[file_name] = compute_file_sha256(fp)
            else:
                # 文件不存在（如已删除），显式记录状态码作为指纹，防止删除逃逸
                manifest[file_name] = f"DELETED_OR_MISSING:{status_code}"

        fingerprint = {
            "modified_files": sorted(set(modified_files)),
            "untracked_files": sorted(set(untracked_files)),
        }
    except Exception as e:
        dirty = True
        fingerprint = {"error": f"Failed to get git status: {e}"}

    return git_commit, dirty, fingerprint, manifest


def collect_target_file_hashes(
    cwd: Path,
    explicit_targets: List[str] | None,
    cmd: List[str],
    modified_files: List[str],
) -> Dict[str, str]:
    """收集关键被审查文件和测试文件的 SHA-256 指纹."""
    candidates = set()
    if explicit_targets:
        candidates.update(explicit_targets)

    # 从命令行参数提取可能的目标文件
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

    hashes = {}
    for rel_path in sorted(candidates):
        target_path = Path(rel_path)
        if not target_path.is_absolute():
            target_path = cwd / target_path
        if target_path.is_file():
            try:
                rel_str = str(target_path.relative_to(cwd))
            except ValueError:
                rel_str = target_path.name
            hashes[rel_str] = compute_file_sha256(target_path)

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
    sanitized_output, redactions = sanitize_text(raw_output)

    tests_summary = parse_test_summary(sanitized_output, project_type, proc.returncode)
    failures = []
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
        "command": " ".join(cmd),
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

    cwd = Path.cwd()
    this_script = Path(__file__).resolve()
    recorder_hash = compute_file_sha256(this_script)

    project_type = args.project_type or infer_project_type(command)

    # 1. Pre-run baseline status and content hash manifest
    git_commit, dirty, pre_fingerprint, pre_manifest = get_git_state(cwd)

    # 2. Target file hashes
    target_hashes = collect_target_file_hashes(cwd, args.target_files, command, pre_fingerprint.get("modified_files", []))

    # 3. Execute command
    cmd_record, failures, redactions = run_command_and_record(
        command, cwd, project_type=project_type, command_id=args.command_id
    )

    # 4. Post-run status and content hash manifest
    _, _, post_fingerprint, post_manifest = get_git_state(cwd)

    # 基于内容哈希精确比对：任何新增、删除、重命名或既有文件内容变动均计入 delta
    all_status_keys = set(pre_manifest.keys()) | set(post_manifest.keys())
    changed_delta = sorted([
        k for k in all_status_keys
        if pre_manifest.get(k) != post_manifest.get(k)
    ])

    fingerprint = post_fingerprint
    fingerprint["pre_run_dirty"] = dirty
    fingerprint["post_run_delta"] = changed_delta
    fingerprint["target_file_hashes"] = target_hashes

    # 5. Scope containment verification (B3, 内容与状态级全闭环比对)
    if args.allowed_scope:
        fingerprint["allowed_scope"] = args.allowed_scope
        fingerprint["task_target_files"] = sorted(target_hashes.keys())

        # 检验集包含：显式 target 文件 + 命令执行期间发生内容/状态变动的所有文件
        all_eval_paths = set(target_hashes.keys()) | set(changed_delta)
        out_path_eval = Path(args.output)
        if not out_path_eval.is_absolute():
            out_path_eval = cwd / out_path_eval
        try:
            recorder_out_rel = str(out_path_eval.relative_to(cwd))
        except ValueError:
            recorder_out_rel = out_path_eval.name

        # 零隐式白名单：仅精确排除 recorder 自身声明的 output 单个产物文件。
        # 绝不隐藏任何目录或文件后缀全局豁免（如 tmp/、.pytest_cache/、__pycache__、*.pyc），
        # 真正做到“任何越界工作树变动均 Fail-Closed”。
        all_eval_paths = {
            p for p in all_eval_paths
            if p != recorder_out_rel
        }

        # Git is the scope oracle. Without a valid pre/post status (or a commit),
        # an empty delta is not proof that the command stayed in bounds.
        git_unavailable = (
            git_commit == "unknown_commit"
            or "error" in pre_fingerprint
            or "error" in post_fingerprint
        )
        scope_passed = not git_unavailable
        violations = ["GIT_STATE_UNAVAILABLE"] if git_unavailable else []
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
        "git_commit": git_commit,
        "dirty_tree": dirty,
        "working_tree_fingerprint": fingerprint,
        "commands": [cmd_record],
        "failures": failures,
        "sanitization": {
            "status": "passed",
            "redactions": redactions,
            "size_bytes": 0,
        },
    }

    content_str = json.dumps(record_payload, indent=2, ensure_ascii=False)
    record_payload["sanitization"]["size_bytes"] = len(content_str.encode("utf-8"))
    out_path.write_text(json.dumps(record_payload, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"[C2C Record v2.0] Wrote execution summary to {out_path}")
    print(
        f"[C2C Record v2.0] Type: {project_type}, Commit: {git_commit[:8]}, Dirty: {dirty}, Exit: {cmd_record['exit_code']}, Tests: {cmd_record['tests']}"
    )

    # Fail-Closed 铁律：若 scope_containment 失败，强制返回 exit code 2 阻断
    if args.allowed_scope and fingerprint.get("scope_containment") != "passed":
        print(
            f"[C2C Record v2.0] FAIL-CLOSED ERROR: Scope containment failed! Violations: {fingerprint.get('scope_violations')}",
            file=sys.stderr
        )
        return 2

    return cmd_record["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
