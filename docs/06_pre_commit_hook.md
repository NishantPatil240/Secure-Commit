# pre_commit.py — The Orchestrator (Entry Point)

## What Is This File?

`hooks/pre_commit.py` is the **main script** that Git calls automatically
every time a developer runs `git commit`.

It does not do the scanning itself — instead it **coordinates** all the other
modules, collects their results, and makes the final decision: block or allow.

Think of it as the **conductor of an orchestra** — it doesn't play any instrument,
but it tells every instrument when to play and combines their output into
a single result.

---

## How Git Calls This File

When you run `git commit`, Git looks for a file at exactly this path:

```
.git/hooks/pre-commit        ← no .py extension (Git requirement)
```

Our `install.py` copies `hooks/pre_commit.py` to `.git/hooks/pre-commit` and
makes it executable. After that, Git calls it automatically — the developer
never has to run it manually.

---

## Execution Flow (Step by Step)

```
git commit
    │
    ▼
.git/hooks/pre-commit  (Git calls this)
    │
    ▼
hooks/pre_commit.py
    │
    ├─── Step 1: Get list of staged files
    │            └─► git diff --cached --name-only
    │
    ├─── Step 2: Route each file to the right scanner
    │            ├─► Dockerfile / .tf → iac_parser → policy_engine
    │            └─► All files        → secret_scanner
    │
    ├─── Step 3: Collect all findings from both scanners
    │
    ├─── Step 4: reporter.py formats and prints the results
    │
    └─── Step 5: Decision
             ├─► Any CRITICAL or HIGH?  → sys.exit(1)  → commit BLOCKED
             └─► Only MEDIUM/LOW or none? → sys.exit(0)  → commit ALLOWED
```

---

## Getting the Staged File List

```python
import subprocess

result = subprocess.run(
    ["git", "diff", "--cached", "--name-only"],
    capture_output=True,
    text=True
)
staged_files = result.stdout.strip().splitlines()
```

**What this command does:**
- `git diff` — show differences
- `--cached` — only look at the staging area (not working tree)
- `--name-only` — only return file names, not the actual diff content

**Result:**
```
['src/config.py', 'infra/main.tf', 'Dockerfile']
```

---

## Smart File Routing

Not every scanner runs on every file. The orchestrator routes files intelligently:

```python
for file_path in staged_files:

    path = Path(file_path)

    # IaC Policy Check
    if path.name == "Dockerfile" or path.suffix == ".tf":
        parsed = parse_file(path)
        if parsed:
            iac_findings += run_policy_engine(parsed)

    # Secret Scan (runs on ALL files)
    secret_findings += scan_for_secrets(path)
```

**Why scan all files for secrets?**
Secrets can appear in any file type: `.py`, `.js`, `.env`, `.yaml`, `.json`, `.sh`.
So the secret scanner is not restricted to specific extensions.

---

## The Exit Code Decision

```python
all_findings = iac_findings + secret_findings

blocking = [f for f in all_findings if f["severity"] in ("CRITICAL", "HIGH")]
warnings = [f for f in all_findings if f["severity"] in ("MEDIUM", "LOW")]

reporter.print_summary(blocking, warnings)

if blocking:
    sys.exit(1)   # ← Git reads this and aborts the commit
else:
    sys.exit(0)   # ← Git reads this and proceeds with the commit
```

**Why `sys.exit()` and not `return`?**

`sys.exit()` terminates the **entire Python process** with a specific exit code.
Git reads the exit code of the hook process:
- `0` = success → commit proceeds
- `1` (or any non-zero) = failure → commit is aborted

`return` only exits a function, not the whole process — Git would never see it.

---

## What Happens to the Commit When Blocked

When `sys.exit(1)` runs:
1. Git receives exit code 1
2. Git prints: `"pre-commit hook: script returned non-zero status"`
3. Git does NOT write the commit object to the database
4. The staging area is left intact — the developer can fix the problem and try again

**Nothing is lost.** The developer's files are untouched. They just need to fix the
flagged issue and run `git commit` again.

---

## Edge Cases Handled

| Situation | What Happens |
|---|---|
| Empty staging area | Script exits 0 (nothing to scan) |
| Binary file staged (image, PDF) | Skipped — not decodable as text |
| First commit (no parent) | History scanner skips diff; staged scanner still runs |
| Corrupted Git repo | Error caught, message printed, exits 1 (safe fail) |
| Policy YAML missing | Critical error printed, exits 1 |

---

## Key Python Concepts Used

| Concept | Where Used |
|---|---|
| `subprocess.run()` | Execute Git commands from Python |
| `sys.exit(0)` / `sys.exit(1)` | Communicate pass/fail to Git |
| `pathlib.Path` | File path handling cross-platform |
| List comprehension with filter | Separate blocking vs warning findings |
| Try/except | Graceful handling of errors in any sub-module |
