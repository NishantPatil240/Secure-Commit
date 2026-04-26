# reporter.py — The Output Formatter

## What Is This File?

`engine/reporter.py` is responsible for **everything the developer sees** in the
terminal when Secure-Commit runs.

It takes raw finding data (Python dicts from the scanners) and formats them into
a clean, readable, color-coded report that tells the developer:
- What went wrong
- Which file and line has the problem
- Which security standard was violated
- Exactly how to fix it

---

## Why A Separate Reporter?

Keeping output formatting in its own module follows the **Separation of Concerns**
principle:

```
secret_scanner.py   → finds problems
policy_engine.py    → evaluates rules
reporter.py         → presents results   ← this file
```

If we ever want to change the output format (e.g., add JSON output for CI systems),
we only change `reporter.py` — nothing else.

---

## What The Output Looks Like

### When violations are found (commit BLOCKED):

```
╔══════════════════════════════════════════════════════════════╗
║           SECURE-COMMIT  |  GOVERNANCE ENGINE v1.0          ║
╚══════════════════════════════════════════════════════════════╝

Scanning 3 staged file(s)...

  [✗] CRITICAL  —  AWS-002: SSH Port Open to the Internet
      File    : infra/main.tf
      Standard: AWS Well-Architected SEC-5
      Detail  : ingress rule allows 0.0.0.0/0 on port 22
      Fix     : Restrict cidr_blocks to your IP, e.g. "203.0.113.0/24"

  [✗] CRITICAL  —  SEC-001: AWS Access Key Detected
      File    : src/config.py  (line 7)
      Standard: OWASP A02:2021 — Cryptographic Failures
      Detail  : Pattern matched AKIA[0-9A-Z]{16}
      Fix     : Remove key. Use IAM roles or environment variables.

  [⚠] MEDIUM   —  DOCK-004: Docker Image Uses :latest Tag
      File    : Dockerfile
      Standard: CIS Docker Benchmark 4.8
      Detail  : FROM ubuntu:latest is non-deterministic
      Fix     : Pin to a specific version, e.g. ubuntu:22.04

──────────────────────────────────────────────────────────────
  RESULT:  ✗  COMMIT BLOCKED  —  2 critical violation(s) found
           ⚠  1 warning(s) — review recommended
  Run: git diff --cached   to review your staged changes
──────────────────────────────────────────────────────────────
```

### When everything is clean (commit ALLOWED):

```
╔══════════════════════════════════════════════════════════════╗
║           SECURE-COMMIT  |  GOVERNANCE ENGINE v1.0          ║
╚══════════════════════════════════════════════════════════════╝

Scanning 2 staged file(s)...

──────────────────────────────────────────────────────────────
  RESULT:  ✓  ALL CLEAR  —  No violations found
  Commit approved. Proceeding to Git...
──────────────────────────────────────────────────────────────
```

---

## ANSI Color Codes

The terminal colors are produced using **ANSI escape codes** — standard sequences
that terminals interpret as color/formatting instructions.

We use these WITHOUT any external library (no `colorama`, no `rich`):

| Color | Code | Used For |
|---|---|---|
| Red | `\033[91m` | CRITICAL findings |
| Yellow | `\033[93m` | HIGH findings / warnings |
| Cyan | `\033[96m` | MEDIUM findings |
| White | `\033[97m` | LOW findings |
| Green | `\033[92m` | All clear / pass |
| Bold | `\033[1m` | Headers |
| Reset | `\033[0m` | End of colored section |

**Example:**
```python
RED   = "\033[91m"
RESET = "\033[0m"
print(f"{RED}[✗] CRITICAL{RESET} — violation found")
```

---

## Windows ANSI Support

Windows 10 (version 1511+) supports ANSI codes in its terminal.

We enable it with a one-line check at startup:

```python
import os, sys
if sys.platform == "win32":
    os.system("")   # triggers ANSI mode in Windows console
```

This tiny trick activates ANSI color processing in `cmd.exe` and PowerShell
without requiring any third-party library.

---

## Severity Color Mapping

| Severity | Color | Icon | Action |
|---|---|---|---|
| `CRITICAL` | 🔴 Red | `[✗]` | Blocks commit |
| `HIGH` | 🟠 Yellow | `[✗]` | Blocks commit |
| `MEDIUM` | 🔵 Cyan | `[⚠]` | Warning only |
| `LOW` | ⚪ White | `[⚠]` | Warning only |

---

## Functions Inside reporter.py

| Function | What It Does |
|---|---|
| `print_banner()` | Prints the top header box |
| `print_finding(finding)` | Prints one violation with all details |
| `print_summary(findings)` | Prints the final BLOCKED / ALL CLEAR line |
| `format_severity(severity)` | Returns the colored severity label |
| `enable_windows_ansi()` | Activates ANSI mode on Windows |

---

## Key Python Concepts Used

| Concept | Where Used |
|---|---|
| ANSI escape codes | Terminal color formatting |
| f-strings | Clean string formatting with variables |
| `sys.platform` | Detect Windows vs Linux/macOS |
| `os.system("")` | Enable ANSI on Windows terminal |
| Separation of Concerns | All output lives here, nowhere else |
