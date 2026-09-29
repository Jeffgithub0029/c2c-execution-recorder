# C2C Execution Recorder

A standalone, standard-library Python CLI for running one verification command and recording its real exit code, test summary, Git working-tree fingerprint, selected file hashes, and pre/post scope changes in a JSON receipt. Intended for **trusted-local** review handoffs; **not** an authentication authority, write-prevention mechanism, or sandbox.

**Python 3.10+; Git required.** Run inside a Git repository with a commit. If a command makes a detectable net change outside `--allowed-scope`, the recorder returns exit code 2 even when that command itself succeeds. Without `--allowed-scope`, no containment decision is made. By default it detects changes visible to `git status` (tracked/untracked). Optional `--audit-ignored` also compares ignored files; neither mode prevents writes, sees outside-repository files, or contains malicious same-user processes.

## Example

```sh
python3 scripts/validation/c2c_execution_recorder.py \
  --output tmp/execution_summary.json \
  --target-files src/engine.py tests/test_engine.py \
  --allowed-scope src/ tests/ \
  -- python3 -B -m pytest -q -p no:cacheprovider tests/test_engine.py
```

Choose scope for *all legitimate writes*, including generated artifacts. The receipt is **local evidence only**: apply the [consumer acceptance checklist](#consumer-acceptance-checklist) and never treat a `passed` text field alone as authorization. Use a clean scratch repo for examples before running against a production checkout.

To also detect *net* changes to ignored files, run from the **Git repository root** and add `--audit-ignored` with `--allowed-scope`. It hashes at most 10,000 ignored files before and after the foreground command; a failed, oversized, or ambiguous audit (including an ignored directory reported as one Git entry) returns exit code 2. This is opt-in because large ignored dependency/build trees are expensive to hash. The receipt reports `working_tree_fingerprint.ignored_file_audit` as `completed` or `failed`; `post_run_delta` includes any detected ignored paths. The default mode deliberately does **not** claim this coverage.

## Consumer acceptance checklist

This is a review checklist, **not** a trust decision made by the recorder. Before accepting a receipt, independently:

1. Confirm that the receipt came from the intended run and repository, and that the recorder process itself exited with code 0. A copied JSON file is not authenticated evidence; the wrapped command's `commands[0].exit_code == 0` alone is insufficient (the recorder can exit 2 after a successful command). A parsed `tests.failed > 0` also blocks acceptance even if a wrapper exits 0. Preserve the **outer** process exit code separately; the receipt does not contain it.
2. Require the expected `schema_version`, a nonempty `--allowed-scope` from the reviewed invocation, `working_tree_fingerprint.scope_containment == "passed"`, and no `scope_violations`. If ignored-file coverage is required, require the reviewed invocation to include `--audit-ignored` **and** `ignored_file_audit == "completed"`; an absent field means it was not audited. Do not infer coverage from a clean delta.
3. Verify `git_commit`, the exact post-run Git status paths **and content fingerprints**, and `dirty_tree` against the actual checkout (the recorder's newly created untracked receipt itself may be excluded once). Compare the *complete expected list* of reviewed source, test, and runner paths with `target_file_hashes`, and recompute every expected file hash from the checkout. Hashes in JSON are not self-authenticating and a missing target must not be silently accepted.
4. Review the command and the code under test. The snapshot only observes net changes at two times; neither `scope_containment == "passed"` nor matching hashes proves that no out-of-scope write occurred. Manually inspect the local receipt and logs for sensitive content before sharing.

Treat absent/ambiguous fields, mismatched files or run identity, a failed audit, or an unreviewed command as **not verified**. The reviewer—not this CLI—decides whether the evidence supports the specific claim.

`scripts/validation/verify_receipt.py` implements a strict **local** subset of these checks. Supply `--repo` (Git root), `--receipt` (inside or outside the checkout), the separately captured `--recorder-exit`, the independently chosen `--expected-argv-file` (UTF-8 JSON array of command arguments), one `--expected-file` per required source/test/runner and one `--allowed-scope` per reviewed scope; add `--require-ignored` when needed. It rejects command arguments redacted by the recorder, missing argv commitments, failed test summaries, changed checkout paths/content and untrusted JSON shapes with exit code 2. Pass real arguments through a private file, **not** a CLI string; better, do not put credentials in command arguments at all. The argv commitment is SHA-256 of a JSON array of individually sanitized arguments; it does not reveal original redacted values, and a redacted invocation cannot pass exact-command verification. The file, outer exit code and list of expected paths must come from the trusted reviewer, not be copied out of the receipt. Scope spellings/order are compared exactly; no automatic scope expansion. A passing verifier is still not proof against post-verification writes, ignored-path changes after the recorder's snapshot, or receipt forgery by a process with the same user privileges.

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

## Release boundary

This tool may be released as a **trusted-local net-change evidence recorder** after the consumer checklist and [known-limit demonstrations](tests/test_known_limits.py) pass. Running untrusted commands, proving prevention of arbitrary writes, observing detached writers, and protecting paths outside the repository require a separately designed and platform-validated isolation layer. Availability of `sandbox-exec` on one macOS host does not establish a portable isolation guarantee. Four strict XFAIL tests in the default mode document the deliberate ignored-file boundary; turning them green by weakening the assertions would hide it.

## Test

```sh
python3 -m pip install pytest
PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -q -p no:cacheprovider
```

The tests use disposable Git repositories and test credentials only. MIT licensed. This public extraction excludes the original private workspace, its execution receipts and state.

The scope regressions retain four **strict XFAIL** cases for default-mode ignored paths (temporary files, pytest cache and Python bytecode). Separate opt-in audit tests verify the same paths are caught with `--audit-ignored`. These are observations after command exit, **not** OS sandbox coverage.
