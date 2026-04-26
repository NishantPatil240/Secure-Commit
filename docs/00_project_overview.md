# Secure-Commit — Project Overview

## What Is This Project?

**Secure-Commit** is a Python-based security tool that automatically checks your code for
security problems *before* you can commit it to Git.

Think of it as a **security guard** that stands at the door of your Git repository.
Every time you run `git commit`, this guard checks your files. If it finds something
dangerous, it physically blocks the commit from happening.

---

## The Core Problem It Solves

Developers accidentally:
1. **Leave secrets in code** — AWS keys, passwords, API tokens hardcoded in `.py` or `.env` files
2. **Write insecure cloud configs** — S3 buckets open to the public, Docker containers running as root
3. **Forget about old commits** — A secret deleted today might still exist in commit history

Secure-Commit catches **all three** before the code ever reaches GitHub/GitLab.

---

## How It Works (Simple Version)

```
You type: git commit

   │
   ▼
[Pre-Commit Hook Fires]  ← our Python script runs automatically
   │
   ├──► Scan IaC files (Terraform, Dockerfile) against policy rules
   │
   └──► Scan all files for leaked secrets (regex patterns + entropy)
   │
   ▼
 Found problems?
   ├── YES → Print error report → Block commit (exit code 1)
   └── NO  → Print "All Clear" → Allow commit (exit code 0)
```

---

## The Three Features

| Feature | What It Does |
|---|---|
| **Secret Scanner** | Finds AWS keys, passwords, API tokens using regex patterns |
| **IaC Policy Engine** | Checks Terraform & Dockerfile configs against security rules |
| **Forensic History Scan** | Looks through old commits for secrets that were "deleted" |

---

## Key Design Principles

- **100% Offline** — zero internet connection needed, ever
- **Zero manual commands** — runs automatically on every `git commit`
- **Deterministic** — same input always gives same output, no randomness
- **Blocks with exit codes** — uses `sys.exit(1)` which Git understands as "abort"

---

## Technology Used

| Tool | Why |
|---|---|
| `Python 3.x` | Main language |
| `GitPython` | Read Git commit history and staged files |
| `PyYAML` | Load the policy rules from `policy.yaml` |
| `re` (regex) | Pattern matching for secret detection |
| `sys` | Exit codes to block/allow commits |
| `pathlib` | Cross-platform file paths (works on Windows too) |

---

## Environment Setup

This project uses a **local virtual environment** (`.venv` folder inside the project).
This means:
- Dependencies are isolated — nothing affects your global Python
- Anyone cloning the repo runs `install.py` once and they're set up
- Deleting `.venv` completely removes all dependencies cleanly

---

## File Map

```
secure-commit-freamework/
├── config/policy.yaml        ← ALL security rules live here
├── engine/
│   ├── secret_scanner.py     ← Finds leaked secrets
│   ├── iac_parser.py         ← Reads Terraform/Dockerfile files
│   ├── policy_engine.py      ← Applies rules to parsed files
│   └── reporter.py           ← Formats and prints results
├── hooks/pre_commit.py       ← Main script Git calls
├── tests/                    ← Test files and sample fixtures
├── docs/                     ← This documentation folder
├── install.py                ← One-time setup script
└── requirements.txt          ← gitpython, pyyaml
```

---

## Severity Levels

| Severity | Action |
|---|---|
| `CRITICAL` | ❌ Always blocks the commit |
| `HIGH` | ❌ Always blocks the commit |
| `MEDIUM` | ⚠️ Warning shown, commit allowed |
| `LOW` | ⚠️ Warning shown, commit allowed |
