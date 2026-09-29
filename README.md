# C2C Execution Recorder

A standalone, standard-library Python CLI for running one verification command and recording its real exit code, test summary, Git working-tree fingerprint, selected file hashes, and pre/post scope changes in a JSON receipt. Intended for local review handoffs; **not** an authentication authority or a sandbox.

**Python 3.10+; Git required.** Run inside a Git repository with a commit. If a command changes a file outside `--allowed-scope`, the recorder returns exit code 2 even when that command itself succeeds. Without `--allowed-scope`, no containment decision is made. It detects changes visible to `git status` (tracked/untracked), not ignored files, outside-repository files, or malicious same-user processes.

## Example

```sh
python3 scripts/validation/c2c_execution_recorder.py \
  --output tmp/execution_summary.json \
  --target-files src/engine.py tests/test_engine.py \
  --allowed-scope src/ tests/ \
  -- python3 -B -m pytest -q -p no:cacheprovider tests/test_engine.py
```

Choose scope for *all legitimate writes*, including generated artifacts. `tmp/execution_summary.json` is excluded exactly as the declared output file. The receipt is **local evidence only**: check its hashes against the reviewed files, read `commands[0].exit_code` and `working_tree_fingerprint.scope_containment`, and never treat a `passed` text field alone as authorization. Use a clean scratch repo for examples before running against a production checkout.

## Privacy and security limits

**Do not pass credentials in command arguments or input/output files. Do not upload receipts or logs without manual review.** The recorder redacts selected secret-shaped strings in captured stdout/stderr, but the command line, paths, file names and Git fingerprint can contain sensitive material; pattern redaction is not comprehensive. It does not neutralize a malicious shell command or prove that an external service accepted a write. Keep the output under an ignored local directory and independently inspect it before sharing.

## Test

```sh
python3 -m pip install pytest
PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -q -p no:cacheprovider
```

The tests use disposable Git repositories and test credentials only. MIT licensed. This public extraction excludes the original private workspace, its execution receipts and state.
