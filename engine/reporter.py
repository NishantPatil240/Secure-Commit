"""
reporter.py — CLI Output Formatter
====================================
Formats and prints all scan findings to the terminal using ANSI color codes.
No external libraries required — pure Python standard library only.

Public interface:
    print_banner()
    print_scanning_info(file_count)
    print_finding(finding)
    print_summary(blocking, warnings)
    enable_windows_ansi()
"""

import os
import sys

# Force UTF-8 output — required on Windows (cp1252 default breaks box chars)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


# ─────────────────────────────────────────────────────────────────────────────
#  ANSI COLOR PALETTE
#  Standard escape sequences — supported by all modern terminals.
#  Windows 10+ : enabled via enable_windows_ansi() below.
# ─────────────────────────────────────────────────────────────────────────────

RESET   = "\033[0m"
BOLD    = "\033[1m"
DIM     = "\033[2m"

RED     = "\033[91m"    # CRITICAL
ORANGE  = "\033[93m"    # HIGH
CYAN    = "\033[96m"    # MEDIUM
WHITE   = "\033[97m"    # LOW
GREEN   = "\033[92m"    # All clear
YELLOW  = "\033[33m"    # Warnings / informational

GREY    = "\033[90m"    # Dimmed secondary text
BLUE    = "\033[94m"    # Accents

LINE_SINGLE = "─" * 64
LINE_DOUBLE = "═" * 64


# ─────────────────────────────────────────────────────────────────────────────
#  SEVERITY → COLOR + ICON MAPPING
# ─────────────────────────────────────────────────────────────────────────────

_SEVERITY_STYLE = {
    "CRITICAL": (RED,    "[✗]", "CRITICAL"),
    "HIGH":     (ORANGE, "[✗]", "HIGH    "),
    "MEDIUM":   (CYAN,   "[⚠]", "MEDIUM  "),
    "LOW":      (WHITE,  "[⚠]", "LOW     "),
}

_BLOCKING_SEVERITIES = {"CRITICAL", "HIGH"}


# ─────────────────────────────────────────────────────────────────────────────
#  PUBLIC FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

def enable_windows_ansi():
    """
    Activate ANSI escape code processing on Windows 10+ terminals.

    Windows CMD and PowerShell support ANSI since Windows 10 v1511,
    but it must be explicitly enabled. The os.system("") trick triggers
    the Windows console to enter ANSI mode with zero side-effects.
    """
    if sys.platform == "win32":
        os.system("")  # noqa: S605


def print_banner():
    """Print the Secure-Commit header banner."""
    enable_windows_ansi()
    print()
    print(f"{BOLD}{BLUE}╔{LINE_DOUBLE}╗{RESET}")
    print(f"{BOLD}{BLUE}║{RESET}{BOLD}      SECURE-COMMIT  │  GOVERNANCE ENGINE  v1.0          {BLUE}       ║{RESET}")
    print(f"{BOLD}{BLUE}╚{LINE_DOUBLE}╝{RESET}")
    print()


def print_scanning_info(staged_files):
    """
    Print which files are being scanned.

    Args:
        staged_files (list[str]): List of staged file paths.
    """
    count = len(staged_files)
    print(f"  {DIM}Scanning {count} staged file(s)...{RESET}")
    for f in staged_files:
        print(f"  {GREY}  • {f}{RESET}")
    print()


def print_finding(finding):
    """
    Print a single violation or warning finding.

    CRITICAL and HIGH findings use the block marker [✗].
    MEDIUM and LOW findings use the warning marker [⚠].

    Args:
        finding (dict): A finding dict produced by policy_engine or
                        secret_scanner. Expected keys:
                        rule_id, rule_name, severity, standard,
                        file, detail, fix.
                        Optional: line, source.
    """
    severity = finding.get("severity", "MEDIUM").upper()
    color, icon, label = _SEVERITY_STYLE.get(severity, (WHITE, "[?]", severity))

    source_tag = ""
    if finding.get("source") == "history":
        source_tag = f"  {GREY}[HISTORY SCAN]{RESET}"

    # ── Header line ──────────────────────────────────────────────────────
    print(f"  {color}{BOLD}{icon} {label}{RESET}  —  "
          f"{BOLD}{finding.get('rule_id', '???')}{RESET}: "
          f"{finding.get('rule_name', 'Unknown')}{source_tag}")

    # ── File + optional line number ───────────────────────────────────────
    file_info = finding.get("file", "unknown")
    line_no   = finding.get("line")
    if line_no:
        file_info += f"  (line {line_no})"
    print(f"  {GREY}  File    :{RESET}  {file_info}")

    # ── Standard reference ────────────────────────────────────────────────
    print(f"  {GREY}  Standard:{RESET}  {finding.get('standard', 'N/A')}")

    # ── Policy description (why this rule exists) ─────────────────────────
    description = finding.get("description", "")
    if description:
        print(f"  {GREY}  Policy  :{RESET}  {YELLOW}{description}{RESET}")

    # ── Detail (what was found) ───────────────────────────────────────────
    detail = finding.get("detail", "")
    if detail:
        # Wrap long detail lines
        if len(detail) > 70:
            detail = detail[:70] + "…"
        print(f"  {GREY}  Detail  :{RESET}  {detail}")

    # ── Fix guidance ──────────────────────────────────────────────────────
    fix = finding.get("fix", "")
    if fix:
        print(f"  {color}  Fix     :{RESET}  {fix}")

    print()


def print_summary(blocking_findings, warning_findings):
    """
    Print the final pass/fail summary block.

    Args:
        blocking_findings (list[dict]): CRITICAL + HIGH findings.
        warning_findings  (list[dict]): MEDIUM + LOW findings.
    """
    print(f"  {GREY}{LINE_SINGLE}{RESET}")

    if blocking_findings:
        b_count = len(blocking_findings)
        w_count = len(warning_findings)

        print(f"  {RED}{BOLD}RESULT:  ✗  COMMIT BLOCKED{RESET}  — "
              f"{RED}{b_count} blocking violation(s) found{RESET}")

        if w_count:
            print(f"           {YELLOW}⚠  {w_count} warning(s) — review recommended{RESET}")

        print()
        print(f"  {DIM}Run: git diff --cached   to review your staged changes{RESET}")
        print(f"  {DIM}Fix all CRITICAL/HIGH issues, then run git commit again.{RESET}")

    else:
        w_count = len(warning_findings)
        print(f"  {GREEN}{BOLD}RESULT:  ✓  ALL CLEAR{RESET}  — "
              f"{GREEN}No blocking violations found{RESET}")

        if w_count:
            print(f"           {YELLOW}⚠  {w_count} warning(s) — review recommended{RESET}")

        print()
        print(f"  {DIM}Commit approved. Proceeding to Git...{RESET}")

    print(f"  {GREY}{LINE_SINGLE}{RESET}")
    print()


def print_history_scan_header(depth):
    """Print a header before the forensic history scan section."""
    print(f"  {YELLOW}Forensic history scan — last {depth} commits...{RESET}")
    print()


def print_error(message):
    """Print a fatal error message (used by orchestrator for unrecoverable errors)."""
    enable_windows_ansi()
    print()
    print(f"  {RED}{BOLD}[FATAL ERROR]{RESET}  {message}")
    print(f"  {DIM}Secure-Commit encountered an unrecoverable error.{RESET}")
    print(f"  {DIM}Commit blocked as a safety measure.{RESET}")
    print()
