"""
secret_scanner.py — Credential & Secret Detector
=================================================
Detects hardcoded secrets in:
  1. Files currently staged for commit (via GitPython index)
  2. Past commit history (forensic scan, last N commits)

Detection methods:
  A. Regex DFA patterns  — match known secret formats (AWS keys, tokens, etc.)
  B. Shannon entropy      — flag high-randomness strings as possible unknowns

Public interface:
    scan_staged_files(repo, policy_patterns)           -> list[dict]
    scan_commit_history(repo, policy_patterns, depth)  -> list[dict]
    scan_text(text, filename, policy_patterns)         -> list[dict]
"""

import re
import math
from pathlib import Path


# ─────────────────────────────────────────────────────────────────────────────
#  FILE EXTENSIONS TO SKIP  (binary / non-scannable)
# ─────────────────────────────────────────────────────────────────────────────

_BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg",
    ".pdf", ".zip", ".tar", ".gz", ".7z", ".rar",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".whl",
    ".pyc", ".pyo", ".class",
    ".lock",          # poetry.lock, package-lock.json
    ".sum",           # go.sum
}

# Variable names that produce common false positives for the entropy check
_ENTROPY_SAFE_NAMES = re.compile(
    r"(?i)(hash|checksum|uuid|md5|sha\d*|digest|fingerprint|nonce|salt)",
    re.IGNORECASE,
)


# ─────────────────────────────────────────────────────────────────────────────
#  PUBLIC INTERFACE
# ─────────────────────────────────────────────────────────────────────────────

def scan_staged_files(repo, policy_patterns):
    """
    Scan files currently staged in the Git index for secrets.

    Reads blob content directly from Git's staging area — this is the exact
    content that will be stored in the commit if allowed to proceed.

    Args:
        repo             (git.Repo): GitPython Repo object for the current repo.
        policy_patterns  (list)    : secret_patterns list from policy.yaml.

    Returns:
        list[dict]: All findings across all staged files.
    """
    findings = []

    try:
        # Get staged blobs that differ from HEAD
        # On a brand-new repo with no commits, diff against None (empty tree)
        try:
            diff_index = repo.index.diff("HEAD")
        except Exception:
            # First commit — diff the entire index against empty tree
            diff_index = repo.index.diff(None)

        for diff_item in diff_index:
            blob = diff_item.a_blob
            if blob is None:
                continue   # Deleted file — nothing to scan

            file_path = diff_item.a_path
            if _should_skip(file_path):
                continue

            try:
                content = blob.data_stream.read().decode("utf-8", errors="replace")
            except Exception:
                continue   # Unreadable binary — skip

            file_findings = scan_text(content, file_path, policy_patterns)
            findings.extend(file_findings)

    except Exception as exc:
        print(f"  [WARN] Staged file scan error: {exc}")

    return findings


def scan_commit_history(repo, policy_patterns, depth=50):
    """
    Walk the last `depth` commits and scan every diff for secrets.

    Detects "ghost secrets" — credentials that were added in a past commit
    and later deleted. They still exist in the repository's object store.

    Args:
        repo             (git.Repo): GitPython Repo object.
        policy_patterns  (list)    : secret_patterns list from policy.yaml.
        depth            (int)     : Number of commits to scan (default 50).

    Returns:
        list[dict]: All findings across all scanned commit diffs.
    """
    findings    = []
    seen        = set()   # De-duplicate identical findings across commits

    try:
        commits = list(repo.iter_commits(max_count=depth))
    except Exception as exc:
        print(f"  [WARN] History scan error: {exc}")
        return findings

    for commit in commits:
        parent = commit.parents[0] if commit.parents else None

        try:
            diffs = commit.diff(parent)
        except Exception:
            continue

        for diff_item in diffs:
            # Only scan added/modified blobs (the + side of the diff)
            blob = diff_item.b_blob
            if blob is None:
                continue

            file_path = diff_item.b_path
            if _should_skip(file_path):
                continue

            try:
                patch = diff_item.diff
                if isinstance(patch, bytes):
                    patch_text = patch.decode("utf-8", errors="replace")
                else:
                    patch_text = str(patch)

                # Only check lines that were added (prefix +)
                added_lines = "\n".join(
                    line[1:] for line in patch_text.splitlines()
                    if line.startswith("+") and not line.startswith("+++")
                )
            except Exception:
                continue

            if not added_lines.strip():
                continue

            commit_findings = scan_text(
                added_lines,
                f"{file_path} (commit: {commit.hexsha[:8]})",
                policy_patterns,
            )

            for f in commit_findings:
                # Deduplicate by rule_id + file to avoid flooding the report
                dedup_key = (f["rule_id"], file_path, f.get("matched_value", ""))
                if dedup_key not in seen:
                    seen.add(dedup_key)
                    f["source"] = "history"
                    findings.append(f)

    return findings


def scan_text(text, filename, policy_patterns):
    """
    Run all detection methods against a string of text.

    This is the core scanning function used by both staged-file and
    history scanners. It can also be called directly in unit tests.

    Args:
        text             (str)  : Text content to scan.
        filename         (str)  : File name/path (used in findings for context).
        policy_patterns  (list) : secret_patterns from policy.yaml.

    Returns:
        list[dict]: Findings from regex + entropy checks.
    """
    findings = []

    for line_no, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue

        # ── Method A: Regex DFA pattern matching ──────────────────────────
        for pattern_rule in policy_patterns:
            # Skip entropy-only rules here (handled below)
            if pattern_rule.get("check_type") == "entropy":
                continue

            regex_str = pattern_rule.get("pattern")
            if not regex_str:
                continue

            try:
                compiled = re.compile(regex_str, re.IGNORECASE)
                match    = compiled.search(stripped)
            except re.error:
                continue   # Malformed regex in YAML — skip

            if match:
                matched_val = match.group(0)
                # Mask middle of matched value for safe display
                safe_val = _mask_secret(matched_val)

                # Normalise multi-line YAML description to a single line
                raw_desc = pattern_rule.get("description", "")
                if isinstance(raw_desc, str):
                    raw_desc = " ".join(raw_desc.split())

                findings.append({
                    "rule_id":       pattern_rule.get("id", "SEC-???"),
                    "rule_name":     pattern_rule.get("name", "Secret Detected"),
                    "severity":      pattern_rule.get("severity", "HIGH"),
                    "standard":      pattern_rule.get("standard", "OWASP A02:2021"),
                    "description":   raw_desc,
                    "file":          filename,
                    "line":          line_no,
                    "detail":        f"Matched pattern [{pattern_rule.get('id')}]: {safe_val}",
                    "fix":           pattern_rule.get("fix", "Remove secret from code."),
                    "matched_value": matched_val,
                    "source":        "staged",
                })

        # ── Method B: Shannon entropy check ───────────────────────────────
        # Find all long token-like strings in this line
        tokens = re.findall(r"['\"]([A-Za-z0-9+/=_\-]{20,})['\"]", stripped)
        for token in tokens:
            entropy = _shannon_entropy(token)
            if entropy > 4.5:
                # Check if variable name suggests it's a hash/checksum (false positive)
                if _ENTROPY_SAFE_NAMES.search(stripped):
                    continue

                findings.append({
                    "rule_id":       "SEC-010",
                    "rule_name":     "High-Entropy String Detected",
                    "severity":      "MEDIUM",
                    "standard":      "OWASP A02:2021",
                    "description":   "A high-randomness string was found near a suspicious variable name. This may be an unrecognized secret format.",
                    "file":          filename,
                    "line":          line_no,
                    "detail":        (
                        f"High-entropy string found (H={entropy:.2f} bits/char, "
                        f"len={len(token)}): {_mask_secret(token)}"
                    ),
                    "fix":           "If this is a secret, move it to environment variables.",
                    "matched_value": token,
                    "source":        "staged",
                })

    return findings


# ─────────────────────────────────────────────────────────────────────────────
#  INTERNAL HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _shannon_entropy(string):
    """
    Calculate Shannon entropy of a string in bits per character.

    Formula:  H = -Σ p(c) × log₂(p(c))
    where p(c) is the probability of character c appearing in the string.

    A string of all identical characters has entropy 0.
    A perfectly random string has entropy approaching log₂(alphabet_size).

    Args:
        string (str): The string to measure.

    Returns:
        float: Entropy value in bits per character. Higher = more random.
    """
    if not string:
        return 0.0

    length     = len(string)
    char_count = {}
    for char in string:
        char_count[char] = char_count.get(char, 0) + 1

    entropy = 0.0
    for count in char_count.values():
        probability = count / length
        entropy    -= probability * math.log2(probability)

    return entropy


def _should_skip(file_path):
    """
    Return True if the file should be excluded from scanning.

    Skips binary files, lock files, and image files based on extension.
    """
    ext = Path(file_path).suffix.lower()
    return ext in _BINARY_EXTENSIONS


def _mask_secret(value):
    """
    Partially mask a secret value for safe display in reports.

    Shows first 4 and last 4 characters; masks the middle with asterisks.

    Example:  "AKIAIOSFODNN7EXAMPLE" → "AKIA**********MPLE"
    """
    if len(value) <= 8:
        return "****"
    return value[:4] + ("*" * (len(value) - 8)) + value[-4:]
