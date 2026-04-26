#!/usr/bin/env python3
"""
pre_commit.py — Orchestrator / Git Pre-Commit Hook Entry Point
==============================================================
This is the script that Git calls automatically on every 'git commit'.

It is installed at: .git/hooks/pre-commit  (no .py extension — Git requirement)

Workflow:
  1. Get list of staged files
  2. Load policy rulebook (config/policy.yaml)
  3. For each staged IaC file → parse → evaluate against policies
  4. For all staged files → scan for secrets
  5. Scan git history for ghost secrets
  6. Print findings via reporter.py
  7. sys.exit(1) if CRITICAL/HIGH found, sys.exit(0) if clean

Exit codes:
  0 = all clear — Git proceeds with commit
  1 = violations found — Git aborts commit
"""

import sys
import subprocess
from pathlib import Path

# ── Ensure project root is on sys.path ────────────────────────────────────────
# This file lives in hooks/ — we need the parent directory to import engine/
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

# ── Engine imports ─────────────────────────────────────────────────────────────
try:
    import git
    from engine.iac_parser    import parse_file
    from engine.policy_engine import load_policies, run_policy_engine
    from engine.secret_scanner import (
        scan_staged_files,
        scan_commit_history,
        scan_text,
    )
    from engine import reporter
except ImportError as exc:
    # If imports fail, print a helpful message and block the commit safely
    print(f"\n  [SECURE-COMMIT] Import error: {exc}")
    print("  Run 'python install.py' to set up the environment.\n")
    sys.exit(1)


# ─────────────────────────────────────────────────────────────────────────────
#  MAIN ORCHESTRATOR
# ─────────────────────────────────────────────────────────────────────────────

def main():
    """
    Entry point called by the Git pre-commit hook.

    Returns:
        int: 0 = pass, 1 = block.
    """
    reporter.print_banner()

    # ── Step 1: Open the Git repository ───────────────────────────────────
    try:
        repo = git.Repo(_PROJECT_ROOT, search_parent_directories=True)
    except git.InvalidGitRepositoryError:
        reporter.print_error("Not inside a Git repository.")
        return 1
    except Exception as exc:
        reporter.print_error(f"Could not open Git repository: {exc}")
        return 1

    # ── Step 2: Load the policy rulebook ──────────────────────────────────
    try:
        policies = load_policies()
    except FileNotFoundError as exc:
        reporter.print_error(str(exc))
        return 1
    except Exception as exc:
        reporter.print_error(f"Failed to load policy.yaml: {exc}")
        return 1

    settings = policies.get("settings", {})
    history_depth = int(settings.get("history_scan_depth", 50))

    # ── Step 3: Get the list of staged files ──────────────────────────────
    staged_files = _get_staged_files()

    if not staged_files:
        print("  Nothing staged for commit. Exiting.\n")
        return 0

    reporter.print_scanning_info(staged_files)

    # ── Step 4: IaC Policy Scan ───────────────────────────────────────────
    iac_findings = []

    for file_str in staged_files:
        file_path = _PROJECT_ROOT / file_str

        parsed = parse_file(file_path)
        if parsed is None:
            continue   # Not an IaC file — skip policy check

        file_findings = run_policy_engine(parsed, policies)
        iac_findings.extend(file_findings)

    # ── Step 5: Secret Scan (staged files via GitPython) ──────────────────
    secret_pattern_list = policies.get("secret_patterns", [])
    staged_secret_findings = scan_staged_files(repo, secret_pattern_list)

    # Fallback: if GitPython staged scan returns nothing (e.g., first commit),
    # read staged files directly from disk and scan their text content
    if not staged_secret_findings:
        for file_str in staged_files:
            file_path = _PROJECT_ROOT / file_str
            if not file_path.exists():
                continue
            try:
                content = file_path.read_text(encoding="utf-8", errors="replace")
                file_findings = scan_text(content, file_str, secret_pattern_list)
                staged_secret_findings.extend(file_findings)
            except Exception:
                continue

    # ── Step 6: Forensic History Scan ─────────────────────────────────────
    reporter.print_history_scan_header(history_depth)
    history_findings = scan_commit_history(repo, secret_pattern_list, depth=history_depth)

    # ── Step 7: Aggregate all findings ────────────────────────────────────
    all_findings = iac_findings + staged_secret_findings + history_findings

    # ── Step 8: Print each finding ────────────────────────────────────────
    for finding in all_findings:
        reporter.print_finding(finding)

    # ── Step 9: Separate blocking vs warning ──────────────────────────────
    blocking = [f for f in all_findings if f.get("severity", "").upper() in ("CRITICAL", "HIGH")]
    warnings = [f for f in all_findings if f.get("severity", "").upper() in ("MEDIUM", "LOW")]

    reporter.print_summary(blocking, warnings)

    # ── Step 10: Exit code decision ───────────────────────────────────────
    if blocking:
        return 1   # sys.exit(1) → Git aborts the commit
    return 0       # sys.exit(0) → Git proceeds with the commit


# ─────────────────────────────────────────────────────────────────────────────
#  HELPER — GET STAGED FILES
# ─────────────────────────────────────────────────────────────────────────────

def _get_staged_files():
    """
    Return a list of file paths currently staged for commit.

    Uses: git diff --cached --name-only --diff-filter=ACM
      --cached       = staging area (not working tree)
      --name-only    = just file paths, no diff content
      --diff-filter  = only Added (A), Copied (C), Modified (M) files
                       excludes Deleted (D) files — nothing to scan there

    Returns:
        list[str]: Relative file paths, e.g. ['src/config.py', 'Dockerfile']
    """
    try:
        result = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
            capture_output=True,
            text=True,
            cwd=str(_PROJECT_ROOT),
        )
        if result.returncode != 0:
            return []

        lines = result.stdout.strip().splitlines()
        return [line.strip() for line in lines if line.strip()]

    except FileNotFoundError:
        # Git not found in PATH
        reporter.print_error("'git' command not found. Ensure Git is installed and in PATH.")
        return []
    except Exception as exc:
        reporter.print_error(f"Could not get staged files: {exc}")
        return []


# ─────────────────────────────────────────────────────────────────────────────
#  HOOK ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    sys.exit(main())
