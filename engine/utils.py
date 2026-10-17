"""
utils.py — Shared Utilities
=============================
Contains common utility functions, shared constants, and reusable features 
used across the Secure-Commit engine. This helps prevent code duplication 
and improper private imports between modules.

Rules for Variables & Functions in this module:
- Use type hints where appropriate.
- All public functions should have clear docstrings explaining their parameters and return types.
- Avoid using global state that changes at runtime.
"""

from pathlib import Path

# ─────────────────────────────────────────────────────────────────────────────
#  FILE EXTENSIONS TO SKIP  (binary / non-scannable)
# ─────────────────────────────────────────────────────────────────────────────

BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg",
    ".pdf", ".zip", ".tar", ".gz", ".7z", ".rar",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".whl",
    ".pyc", ".pyo", ".class",
    ".lock",          # poetry.lock, package-lock.json
    ".sum",           # go.sum
}


def should_skip_file(file_path: str | Path) -> bool:
    """
    Determine if a file should be excluded from scanning based on its extension.

    This function skips binary files, lock files, and image files to prevent
    wasting CPU cycles on non-text files and to avoid UnicodeDecodeErrors.

    Args:
        file_path (str | Path): The path to the file to check.

    Returns:
        bool: True if the file should be skipped, False if it is scannable text.
    """
    ext = Path(file_path).suffix.lower()
    return ext in BINARY_EXTENSIONS

import re

def parse_suppressions(text: str) -> tuple[bool, set[str]]:
    """
    Parse inline # nosec comments from text to determine suppressed rules.

    Args:
        text (str): The source code or configuration text.

    Returns:
        tuple[bool, set[str]]: A tuple of (skip_all, suppressed_rules_set).
    """
    skip_all = False
    suppressed_rules = set()
    
    for line in text.splitlines():
        # Match "# nosec" or "// nosec"
        nosec_match = re.search(r'(?:#|//)\s*nosec\b(.*)', line, re.IGNORECASE)
        if nosec_match:
            rest = nosec_match.group(1).strip()
            if not rest:
                skip_all = True
            else:
                suppressed_rules.update(r.strip().upper() for r in rest.split())
                
    return skip_all, suppressed_rules

