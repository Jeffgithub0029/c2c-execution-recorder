# C2C Execution Recorder

A standalone, standard-library Python CLI for running one verification command and recording its real exit code, test summary, Git working-tree fingerprint, selected file hashes, and pre/post scope changes in a JSON receipt. Intended for local review handoffs; **not** an authentication authority or a sandbox.

**Python 3.10+; Git required.** Run inside a Git repository with a commit. If a command makes a detectable net change outside `--allowed-scope`, the recorder returns exit code 2 even when that command itself succeeds. Without `--allowed-scope`, no containment decision is made. By default it detects changes visible to `git status` (tracked/untracked). Optional `--audit-ignored` also compares ignored files; neither mode prevents writes, sees outside-repository files, or contains malicious same-user processes.

## Example

```sh
python3 scripts/validation/c2c_execution_recorder.py \
  --output tmp/execution_summary.json \
  --target-files src/engine.py tests/test_engine.py \
  --allowed-scope src/ tests/ \
  -- python3 -B -m pytest -q -p no:cacheprovider tests/test_engine.py
```

Choose scope for *all legitimate writes*, including generated artifacts. The receipt is **local evidence only**: check its hashes against the reviewed files, read `commands[0].exit_code` and `working_tree_fingerprint.scope_containment`, and never treat a `passed` text field alone as authorization. Use a clean scratch repo for examples before running against a production checkout.

To also detect *net* changes to ignored files, run from the **Git repository root** and add `--audit-ignored` with `--allowed-scope`. It hashes at most 10,000 ignored files before and after the foreground command; a failed, oversized, or ambiguous audit (including an ignored directory reported as one Git entry) returns exit code 2. This is opt-in because large ignored dependency/build trees are expensive to hash. The receipt reports `working_tree_fingerprint.ignored_file_audit` as `completed` or `failed`; `post_run_delta` includes any detected ignored paths. The default mode deliberately does **not** claim this coverage.

## Scope containment and integrity model

1. **Git-observable worktree tracking**: Uses `git status --porcelain=v1 -z -uall` to reliably capture modified, untracked, deleted, and renamed files without filename or quote mangling.
2. **Net HEAD change fails closed**: If pre-run and post-run `HEAD` differ (for example, a command commits or checks out another revision and leaves it there), the recorder exits with code 2 and records a `HEAD_CHANGED` violation. A transient change followed by a return to the original `HEAD` cannot be proven by these snapshots.
3. **No output receipt exemption**: The output JSON receipt is written by the recorder *after* the post-run Git snapshot is evaluated. The command under test receives no blanket exemption for the output path — if the command modifies or creates a file at `--output` outside `--allowed-scope`, it is caught as a scope violation.
4. **Target files and symlinks**: Target files must be regular files within the repository root. Paths that resolve outside the repository or point to symlinks are rejected upfront with exit code 2 to prevent fingerprint ambiguity. Target file SHA-256 hashes are computed on the post-run state; a missing or unreadable target fails closed rather than producing an apparently valid receipt.
5. **Exact metadata sizing**: Receipt `sanitization.size_bytes` is computed iteratively to match the exact byte size of the written UTF-8 JSON receipt.

## Privacy, security limits, and threat model

The recorder operates under a **trusted local agent** model: it generates local evidence for handoffs, but is **not** an OS sandbox, container jail, or authorization authority.

- **Ignored files**: By default they are invisible to containment. `--audit-ignored` enumerates Git-ignored files and compares content hashes across two snapshots, including changes to existing files and deleted files. It detects *net state*, not write attempts, and does not stop a command from writing. It does not scan external paths, linked targets, or transient writes that are later restored.
- **Background writers**: The recorder waits for the direct foreground process to exit, then takes the post-run Git snapshot. Any detached child processes, background daemons, or asynchronous workers that continue writing after the foreground process exits cannot be trapped by a point-in-time snapshot.
- **Transient Git changes**: A command may commit or check out another revision, then restore the original `HEAD` and final worktree before the post-run snapshot. The recorder observes net state only, not every intermediate action. Use an isolated checkout and review the command itself when intermediate effects matter.
- **Best-effort credential redaction**: Regex pattern matching is applied to both the captured command string and stdout/stderr to redact common secret formats (Bearer tokens, API keys, private keys). This is **best-effort pattern matching**, NOT comprehensive secret scanning. Command arguments, file paths, and diffs can still leak sensitive data. **Always manually review receipts and logs before sharing.**

## Test

```sh
python3 -m pip install pytest
PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -q -p no:cacheprovider
```

The tests use disposable Git repositories and test credentials only. MIT licensed. This public extraction excludes the original private workspace, its execution receipts and state.

The scope regressions retain four **strict XFAIL** cases for default-mode ignored paths (temporary files, pytest cache and Python bytecode). Separate opt-in audit tests verify the same paths are caught with `--audit-ignored`. These are observations after command exit, **not** OS sandbox coverage.
