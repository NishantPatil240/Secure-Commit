# policy.yaml — The Security Rulebook

## What Is This File?

`config/policy.yaml` is the **Single Source of Truth** for all security rules in the project.

Every rule that the tool enforces lives in this one file. If you want to:
- Add a new rule → edit this file
- Disable a rule → comment it out in this file
- Change a severity level → change it in this file

No other file needs to change.

---

## Why One File?

| Approach | Problem |
|---|---|
| Separate file per rule | Hundreds of files, slow to load |
| Rules hardcoded in Python | Can't update rules without changing code |
| **Single YAML file** ✅ | Fast to load once, easy to read/edit, auditable |

The YAML file is loaded **once** into memory at startup. After that, all rule checks
run against the in-memory dictionary — zero disk reads during scanning.

---

## File Structure (Blueprint)

```yaml
# ─────────────────────────────────────────────
# SECURE-COMMIT POLICY RULEBOOK
# ─────────────────────────────────────────────

version: "1.0"

settings:
  history_scan_depth: 50        # How many commits back to scan
  strict_mode: false            # true = MEDIUM also blocks commits

metadata:
  framework_references:
    - "CIS Docker Benchmark v1.6"
    - "OWASP Top 10 2021"
    - "AWS Well-Architected Framework 2023"

# ─── Rules for Dockerfile files ───────────────
docker_policies:
  - id: "DOCK-001"
    ...

# ─── Rules for Terraform .tf files ───────────
aws_policies:
  - id: "AWS-001"
    ...

# ─── Secret detection patterns ────────────────
secret_patterns:
  - id: "SEC-001"
    ...
```

---

## What Each Rule Contains

Every single rule (regardless of type) has these fields:

| Field | What It Means | Example |
|---|---|---|
| `id` | Unique rule identifier | `"DOCK-001"` |
| `name` | Human-readable name | `"No Root User"` |
| `severity` | How dangerous this is | `"CRITICAL"` |
| `standard` | Which framework this comes from | `"CIS Docker 4.1"` |
| `description` | Plain English explanation | `"Containers must not run as root"` |
| `check_type` | How the engine evaluates this rule | `"key_value_match"` |
| `fix` | What the developer should do to fix it | `"Add USER appuser before CMD"` |

---

## Rule ID Naming Convention

| Prefix | Meaning |
|---|---|
| `DOCK-XXX` | Docker / Dockerfile rules |
| `AWS-XXX` | Terraform / AWS infrastructure rules |
| `SEC-XXX` | Secret detection rules (cross-cutting) |

---

## Check Types Explained

The `check_type` field tells the policy engine *how* to test the rule:

| check_type | What It Does | Example Use |
|---|---|---|
| `key_value_match` | Fails if a setting equals a forbidden value | `USER = root` |
| `key_value_not_match` | Fails if a setting does NOT equal required value | encryption must be `true` |
| `key_absent` | Fails if a required key is completely missing | no `HEALTHCHECK` in Dockerfile |
| `cidr_check` | Fails if a network range is `0.0.0.0/0` (world-open) | SSH open to internet |
| `image_tag_check` | Fails if Docker `FROM` uses `:latest` tag | `FROM ubuntu:latest` |
| `port_check` | Fails if a dangerous port is exposed | port 22 (SSH) exposed |
| `env_secret_check` | Fails if `ENV` line contains a secret pattern | `ENV SECRET_KEY=abc123` |

---

## Industry Standards Used

### CIS Benchmarks (Docker)
The **Center for Internet Security** publishes hardening guides.
Our Docker rules follow **CIS Docker Benchmark v1.6**:
- No root user inside containers
- No privileged mode
- No sensitive ports exposed
- Always use specific image tags (not `:latest`)

### OWASP Top 10
The **Open Web Application Security Project** publishes the top 10 most critical
web security risks. Our secret detection rules address:
- **A02:2021** — Cryptographic Failures (hardcoded secrets)
- **A05:2021** — Security Misconfiguration

### AWS Well-Architected Framework
Amazon's best practices for secure cloud infrastructure:
- **SEC-1**: No public S3 buckets
- **SEC-5**: No unrestricted SSH (port 22) access
- **SEC-7**: Encryption enabled on all storage

---

## Settings Explained

```yaml
settings:
  history_scan_depth: 50    # Scan last 50 git commits for secrets
  strict_mode: false        # false = MEDIUM/LOW only warn, don't block
```

Change `strict_mode: true` if you want MEDIUM severity findings to also block commits.

---

## How The Engine Uses This File

```
install.py runs
  └─► Loads policy.yaml into memory (once)
       └─► pre_commit.py gets a file list
            └─► For .tf files  → uses aws_policies block
                For Dockerfile → uses docker_policies block
                For all files  → uses secret_patterns block
```
