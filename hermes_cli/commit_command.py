"""Prompt builder for the ``/commit`` slash command.

The command intentionally delegates repository inspection and mutation to the
normal agent tool loop. This keeps the gateway and CLI on the same execution
path, preserves approval policy, and prevents the command from inventing a
commit result when the repository is dirty or unsafe.
"""


def build_commit_prompt(extra: str = "") -> str:
    """Build the deterministic instructions used by ``/commit``."""
    context = extra.strip()
    suffix = f"\n\nAdditional user context: {context}" if context else ""
    return (
        "Run the repository commit workflow in the current working directory. "
        "First inspect `git status --short --branch`, unstaged diff, staged diff, "
        "untracked files, and `git diff --check`. Check for secrets or unrelated "
        "files before staging anything. If there are no intended changes, report "
        "that clearly and do not create an empty commit. If the diff is mixed, "
        "unsafe, or unclear, stop and report the issue instead of guessing. "
        "For a clean intended change, generate a concise Conventional Commit title, "
        "stage only the intended files, re-check the cached diff and `git diff "
        "--cached --check`, create the local commit, and push the current branch "
        "to its configured origin. Execute the workflow with real tools and report "
        "the actual status, commit ID, and push result; never fabricate success."
        + suffix
    )
