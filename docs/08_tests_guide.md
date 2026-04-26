# tests/ — Testing Guide

## What Is This Folder?

The `tests/` directory contains **automated tests** that verify every component
of Secure-Commit works correctly — before you use it in a real project.

Tests also serve as **living documentation**: by reading a test, you can
understand exactly what a function is supposed to do and what inputs it expects.

---

## Folder Structure

```
tests/
├── fixtures/                    ← Sample files used as test inputs
│   ├── bad_dockerfile           ← Dockerfile with intentional violations
│   ├── good_dockerfile          ← Dockerfile that passes all rules
│   ├── bad_terraform.tf         ← Terraform with public S3, open SSH
│   ├── good_terraform.tf        ← Terraform that passes all rules
│   └── secrets_sample.py        ← Python file with hardcoded secrets
│
├── test_secret_scanner.py       ← Tests for secret_scanner.py
├── test_iac_parser.py           ← Tests for iac_parser.py
└── test_policy_engine.py        ← Tests for policy_engine.py
```

---

## Test Fixtures Explained

### `bad_dockerfile`
A Dockerfile that intentionally breaks multiple CIS rules:
```dockerfile
FROM ubuntu:latest          # DOCK-003: :latest tag
USER root                   # DOCK-001: running as root
EXPOSE 22                   # DOCK-002: SSH port exposed
ENV SECRET_KEY=abc123xyz    # DOCK-005: secret in ENV
# No HEALTHCHECK            # DOCK-004: missing healthcheck
```

### `good_dockerfile`
A Dockerfile that passes all rules:
```dockerfile
FROM ubuntu:22.04           # specific version ✓
USER appuser                # non-root user ✓
EXPOSE 8080                 # safe port ✓
HEALTHCHECK CMD curl -f http://localhost/ || exit 1   # ✓
```

### `bad_terraform.tf`
Terraform with AWS security violations:
```hcl
resource "aws_s3_bucket" "bad" {
  acl = "public-read"          # AWS-001: public bucket
}

resource "aws_security_group" "bad" {
  ingress {
    from_port   = 22
    cidr_blocks = ["0.0.0.0/0"]  # AWS-002: SSH open to world
  }
}
```

### `good_terraform.tf`
Terraform that follows all rules:
```hcl
resource "aws_s3_bucket" "good" {
  acl = "private"              # ✓
}

resource "aws_security_group" "good" {
  ingress {
    from_port   = 22
    cidr_blocks = ["10.0.0.0/8"]  # internal only ✓
  }
}
```

### `secrets_sample.py`
Python file with hardcoded credentials:
```python
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
STRIPE_KEY     = "sk_live_abc123xyz789ABCDEF012345"
GITHUB_TOKEN   = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"
DB_PASSWORD    = "SuperSecret@123"
```

---

## How To Run The Tests

From the project root, with the virtual environment active:

```bash
# Run all tests
.venv\Scripts\python.exe -m pytest tests\ -v

# Run only secret scanner tests
.venv\Scripts\python.exe -m pytest tests\test_secret_scanner.py -v

# Run only IaC parser tests
.venv\Scripts\python.exe -m pytest tests\test_iac_parser.py -v
```

---

## What Each Test File Tests

### `test_secret_scanner.py`

| Test Name | What It Checks |
|---|---|
| `test_detects_aws_access_key` | AWS key pattern caught |
| `test_detects_stripe_key` | Stripe live key caught |
| `test_detects_github_pat` | GitHub PAT caught |
| `test_detects_high_entropy_string` | Shannon entropy flagging works |
| `test_clean_file_no_findings` | Clean file returns empty list |
| `test_skips_binary_files` | Binary files are not scanned |

### `test_iac_parser.py`

| Test Name | What It Checks |
|---|---|
| `test_parse_dockerfile_user_root` | USER root is parsed correctly |
| `test_parse_dockerfile_expose` | EXPOSE ports are parsed as list |
| `test_parse_terraform_acl` | S3 ACL value extracted correctly |
| `test_parse_terraform_cidr` | CIDR blocks extracted as list |
| `test_unknown_file_returns_none` | `.xyz` files return None gracefully |

### `test_policy_engine.py`

| Test Name | What It Checks |
|---|---|
| `test_bad_dockerfile_blocked` | bad_dockerfile produces findings |
| `test_good_dockerfile_passes` | good_dockerfile returns empty list |
| `test_bad_terraform_blocked` | bad_terraform.tf produces findings |
| `test_good_terraform_passes` | good_terraform.tf returns empty list |
| `test_severity_levels_correct` | Each finding has correct severity |

---

## Understanding Test Structure

Each test follows the **Arrange → Act → Assert** pattern:

```python
def test_detects_aws_access_key():
    # ARRANGE — set up the input
    content = 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"'

    # ACT — run the function being tested
    findings = scan_text_for_secrets(content, file_path="test.py")

    # ASSERT — verify the output is correct
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "SEC-001"
    assert findings[0]["severity"] == "CRITICAL"
```

---

## Key Concepts Used

| Concept | Where Used |
|---|---|
| `pytest` framework | Test runner (auto-discovers test files) |
| `assert` statements | Verify expected vs actual results |
| Test fixtures | Reusable sample files for consistent testing |
| Arrange-Act-Assert | Standard test structure pattern |
| Negative testing | Verify clean files don't produce false positives |
