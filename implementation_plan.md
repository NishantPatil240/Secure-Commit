# Secure-Commit: Automated Governance Framework for Infrastructure-as-Code

## Project Overview

**Secure-Commit** is a deterministic, offline-first Git pre-commit hook engine. It intercepts the developer's commit workflow *before* any code leaves the local machine, applying two classes of checks simultaneously:

1. **Secret Detection** — Regex/DFA-based scanning of staged files and Git history for leaked credentials.
2. **IaC Policy Enforcement** — YAML-driven policy engine that parses Terraform (`.tf`) and Dockerfiles against CIS/OWASP/AWS Well-Architected rules.

The tool is language-agnostic at the policy level, requires **zero internet connectivity**, and physically blocks commits by returning `sys.exit(1)`.

---

## Architectural Thinking

### Why This Approach Is Sound

| Decision | Rationale |
|---|---|
| **Git hook (pre-commit)** | Zero friction — no CLI commands needed; runs automatically on every `git commit` |
| **Single `policy.yaml`** | One file to audit, one file to update; parsed once into memory — zero disk I/O overhead after load |
| **Regex DFA (not ML)** | 100% deterministic, reproducible results; no GPU, no model downloads |
| **GitPython** | Native Pythonic interface to Git objects — reads diffs, blobs, and commit trees without shelling out |
| **In-memory dict (Lexical Parser)** | HCL/Dockerfile → Python dict avoids writing temp files; keeps the attack surface minimal |
| **`sys.exit(1)` as the enforcement mechanism** | POSIX-standard; Git itself interprets a non-zero hook exit as "abort commit" |

### What We Are NOT Doing (and Why)

- ❌ No Trivy / Snyk / external DB downloads — violates Offline-First constraint
- ❌ No async/threading for "simultaneous" checks — adds complexity; sequential scans on small staged sets are fast enough
- ❌ No web dashboard, no gamification, no scores
- ❌ No network calls of any kind

---

## Component Breakdown

### Component 1 — Entry Point & Orchestrator (`hooks/pre_commit.py`)

This is the script Git calls. It:
1. Reads the list of staged files via `git diff --cached --name-only`
2. Routes each file to the correct scanner
3. Aggregates all findings into a single report
4. Exits `0` (pass) or `1` (block)

**Key concepts taught here:**
- `subprocess` vs `GitPython` — when to use which
- POSIX exit codes and how Git interprets them
- Python's `argparse`-free CLI pattern for hooks

---

### Component 2 — Secret Scanner (`engine/secret_scanner.py`)

**Two sub-modes:**

**A. Staged File Scanner**
Reads staged blob content from Git's index (not the working tree) using GitPython's `repo.index`. This ensures we scan exactly what will be committed.

**B. Forensic History Scanner**
Walks the Git commit graph using `repo.iter_commits()`, extracts diffs per commit via `commit.diff(parent)`, and applies regex patterns to each diff chunk.

**Regex DFA Patterns (the "math" behind it):**

| Secret Type | Pattern Logic |
|---|---|
| AWS Access Key | `AKIA[0-9A-Z]{16}` |
| AWS Secret Key | High-entropy 40-char alphanumeric adjacent to `aws_secret` keyword |
| Generic API Key | `(?i)(api_key\|apikey\|api-key)\s*[:=]\s*['"]?[A-Za-z0-9\-_]{20,}` |
| Stripe Token | `sk_live_[0-9a-zA-Z]{24}` |
| GitHub PAT | `ghp_[A-Za-z0-9]{36}` |
| Private Key Header | `-----BEGIN (RSA\|EC\|OPENSSH) PRIVATE KEY-----` |
| Generic Password | `(?i)(password\|passwd\|pwd)\s*[:=]\s*['"]?[^\s'"]{8,}` |

**Shannon Entropy check** (bonus layer): For strings that look like random tokens, we calculate Shannon entropy `H = -Σ p(c) log2 p(c)`. Strings with H > 4.5 bits/char that match no known format are flagged as "possible high-entropy secret."

---

### Component 3 — IaC Lexical Parser (`engine/iac_parser.py`)

**Two parsers, one interface:**

**Terraform HCL Parser**
HCL is not valid Python/JSON, but for our policy-check use case, we only need to extract key-value pairs and block structures. We implement a *line-by-line lexical tokenizer*:

```
token types:  BLOCK_START, BLOCK_END, ASSIGNMENT, STRING_VALUE, BOOL_VALUE, LIST_VALUE
```

This converts:
```hcl
resource "aws_s3_bucket" "my_bucket" {
  acl = "public-read"
}
```
into:
```python
{
  "resource": {
    "aws_s3_bucket": {
      "my_bucket": {
        "acl": "public-read"
      }
    }
  }
}
```

**Dockerfile Parser**
Dockerfiles follow a simple `INSTRUCTION argument` grammar. We tokenize by splitting on the first whitespace of each non-comment line.

```python
{
  "FROM": ["ubuntu:latest"],
  "USER": ["root"],         # ← policy violation
  "EXPOSE": ["22", "80"],   # ← port 22 flagged
  "ENV": ["SECRET_KEY=abc"] # ← inline secret
}
```

**Key concept taught here:** Lexical analysis, tokenization, AST-lite representations — the same concepts used in production compilers, applied to a real DevSecOps problem.

---

### Component 4 — Policy Engine (`engine/policy_engine.py`)

This is the "brain." It:
1. Loads `policy.yaml` once into memory
2. Receives a parsed dict from the IaC parser
3. Routes to the correct policy block based on file extension
4. Evaluates each rule using a **Rule Evaluator** pattern

**Rule Evaluator Design:**

Each rule in `policy.yaml` has a `check_type`. The engine dispatches to the correct evaluator function:

| `check_type` | What it does |
|---|---|
| `key_value_match` | Checks if `parsed[path] == forbidden_value` |
| `key_value_not_match` | Checks if `parsed[path] != required_value` |
| `key_absent` | Flags if a required key is missing entirely |
| `cidr_check` | Parses CIDR blocks and flags `0.0.0.0/0` on sensitive ports |
| `image_tag_check` | Flags Docker `FROM` with `:latest` tag (non-deterministic builds) |
| `port_check` | Flags sensitive exposed ports (22, 3389, 23) |
| `env_secret_check` | Regex-scans `ENV` values for inline secrets |

---

### Component 5 — Policy Rulebook (`config/policy.yaml`)

The **Single Source of Truth**. Structured as:

```yaml
version: "1.0"
metadata:
  framework_references:
    - "CIS Docker Benchmark v1.6"
    - "OWASP Top 10 2021"
    - "AWS Well-Architected Framework 2023"

docker_policies:
  - id: "DOCK-001"
    name: "No Root User"
    severity: "CRITICAL"
    standard: "CIS Docker 4.1"
    check_type: "key_value_match"
    ...

aws_policies:
  - id: "AWS-001"
    name: "S3 Bucket Not Public"
    severity: "CRITICAL"
    standard: "AWS Well-Architected SEC-1"
    ...
```

**Rule IDs follow a naming standard:**
- `DOCK-XXX` — Docker rules
- `AWS-XXX` — Terraform/AWS rules
- `SEC-XXX` — Cross-cutting secret detection rules

---

### Component 6 — Reporter (`engine/reporter.py`)

Produces clean, human-readable CLI output with ANSI color codes (no external libraries):

```
╔══════════════════════════════════════════════════════╗
║         SECURE-COMMIT: GOVERNANCE ENGINE             ║
╚══════════════════════════════════════════════════════╝

[✗] CRITICAL — AWS-002: SSH Port 22 Open to World
    File    : infra/main.tf (line 14)
    Standard: AWS Well-Architected SEC-5
    Detail  : ingress rule allows 0.0.0.0/0 on port 22
    Fix     : Restrict to specific IP range, e.g. 10.0.0.0/8

[✗] HIGH    — SEC-003: AWS Access Key Detected
    File    : src/config.py (line 7)
    Standard: OWASP A02:2021 Cryptographic Failures
    Detail  : Pattern matched: AKIA...
    Fix     : Remove key, use IAM roles or environment variables

──────────────────────────────────────────────────────
  RESULT: ✗ COMMIT BLOCKED — 2 violation(s) found
  Run `git diff --cached` to review staged changes
──────────────────────────────────────────────────────
```

---

### Component 7 — Installer (`install.sh` / `install.py`)

A one-time setup script that:
1. Validates Python 3.x is available
2. Installs `gitpython` and `pyyaml` via pip (local venv)
3. Copies `hooks/pre_commit.py` → `.git/hooks/pre-commit`
4. Sets the execute bit (`chmod +x`) on the hook file
5. Validates the hook is wired correctly with a dry-run

---

## File Structure

```
e:/secure-commit-framework/
│
├── .git/
│   └── hooks/
│       └── pre-commit              ← Auto-installed symlink/copy of our hook
│
├── config/
│   └── policy.yaml                 ← Single Source of Truth for all rules
│
├── engine/
│   ├── __init__.py
│   ├── secret_scanner.py           ← Regex DFA + Entropy + GitPython history
│   ├── iac_parser.py               ← HCL + Dockerfile lexical tokenizer
│   ├── policy_engine.py            ← Rule loader, router, evaluator
│   └── reporter.py                 ← ANSI CLI output formatter
│
├── hooks/
│   └── pre_commit.py               ← Orchestrator / Entry point
│
├── tests/
│   ├── fixtures/
│   │   ├── bad_dockerfile          ← Test fixture: rule violations
│   │   ├── good_dockerfile         ← Test fixture: clean file
│   │   ├── bad_terraform.tf        ← Test fixture: public S3, open SSH
│   │   ├── good_terraform.tf       ← Test fixture: compliant infra
│   │   └── secrets_sample.py       ← Test fixture: hardcoded keys
│   ├── test_secret_scanner.py
│   ├── test_iac_parser.py
│   └── test_policy_engine.py
│
├── docs/
│   ├── architecture.md             ← System design document
│   └── policy_reference.md        ← Rule ID catalog
│
├── install.py                      ← One-time setup script
├── requirements.txt                ← gitpython, pyyaml
└── README.md
```

---

## Implementation Stages (Execution Order)

### Stage 1 — Scaffold & Foundation
- Create directory structure
- Write `requirements.txt`
- Write `install.py`
- Write skeleton `__init__.py` files

### Stage 2 — Policy Rulebook (`config/policy.yaml`)
- Write all Docker rules (CIS Benchmark)
- Write all AWS/Terraform rules (Well-Architected + CIS)
- Define rule schema strictly

### Stage 3 — IaC Parser (`engine/iac_parser.py`)
- Implement Dockerfile tokenizer
- Implement HCL line-by-line lexical parser
- Unit test with fixtures

### Stage 4 — Policy Engine (`engine/policy_engine.py`)
- Implement YAML loader
- Implement rule router (by file extension)
- Implement all `check_type` evaluators
- Unit test against bad/good fixtures

### Stage 5 — Secret Scanner (`engine/secret_scanner.py`)
- Implement regex pattern library
- Implement Shannon entropy checker
- Implement staged-file scanner (GitPython index)
- Implement forensic history walker (GitPython commit tree)
- Unit test against secrets fixture

### Stage 6 — Reporter (`engine/reporter.py`)
- Implement ANSI color palette
- Implement finding formatter
- Implement summary block (pass/fail)

### Stage 7 — Orchestrator (`hooks/pre_commit.py`)
- Wire all engines together
- Implement staged-file routing logic
- Implement exit code logic

### Stage 8 — Tests & Validation
- Run all unit tests against fixtures
- Do a full end-to-end test: `git add bad_dockerfile && git commit`
- Verify commit is blocked with correct output

### Stage 9 — Documentation
- `README.md` — setup guide
- `docs/architecture.md`
- `docs/policy_reference.md`

---

## Open Questions for You

> [!IMPORTANT]
> **Q1: History scan depth** — For the forensic history scanner, how many commits back should we scan by default? Options: last 10, last 50, or all history. All-history can be slow on large repos. I recommend a configurable default of **50 commits**.

> [!IMPORTANT]
> **Q2: Severity thresholds** — Should `HIGH` severity findings block the commit, or only `CRITICAL`? Or should all findings block? I recommend **all severities block** (fail-safe), but we can add a `--warn-only` mode for `MEDIUM` and `LOW`.

> [!NOTE]
> **Q3: Virtual environment** — Should the installer create a project-local `.venv` and install dependencies there, or assume the developer's global Python has `gitpython`/`pyyaml`? A local `.venv` is cleaner for isolation.

> [!NOTE]
> **Q4: Windows compatibility** — The primary target is Linux/macOS for Git hooks. On Windows, Git hooks require Git Bash or WSL. Should I add a Windows-specific `install.bat` / PowerShell variant?

