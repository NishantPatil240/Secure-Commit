"""
test_secret_scanner.py — Unit tests for engine/secret_scanner.py
"""

import sys
import math
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from engine.secret_scanner import scan_text, _shannon_entropy, _mask_secret, _should_skip
from engine.policy_engine  import load_policies

FIXTURES    = Path(__file__).parent / "fixtures"
POLICY_PATH = Path(__file__).parent.parent / "config" / "policy.yaml"


def _get_patterns():
    policies = load_policies(POLICY_PATH)
    return policies.get("secret_patterns", [])


# ─────────────────────────────────────────────────────────────────────────────
#  SHANNON ENTROPY TESTS
# ─────────────────────────────────────────────────────────────────────────────

def test_entropy_low_for_repeated_chars():
    """A string of identical chars should have entropy 0."""
    assert _shannon_entropy("aaaaaaaaaa") == 0.0


def test_entropy_high_for_random_string():
    """A highly random string should have entropy > 4.0."""
    random_str = "aB3$kL9mQzR2wJalrX"
    assert _shannon_entropy(random_str) > 4.0


def test_entropy_known_value():
    """Shannon entropy of 'ab' (50/50) should be exactly 1.0 bit."""
    assert abs(_shannon_entropy("ab") - 1.0) < 1e-9


def test_entropy_empty_string():
    """Empty string should return 0.0 without error."""
    assert _shannon_entropy("") == 0.0


# ─────────────────────────────────────────────────────────────────────────────
#  SECRET MASKING TESTS
# ─────────────────────────────────────────────────────────────────────────────

def test_mask_secret_normal():
    """Long secrets should be partially masked."""
    masked = _mask_secret("AKIAIOSFODNN7EXAMPLE")
    assert masked.startswith("AKIA")
    assert "****" in masked
    assert masked.endswith("MPLE")


def test_mask_secret_short():
    """Short strings should be fully masked."""
    assert _mask_secret("abc") == "****"


# ─────────────────────────────────────────────────────────────────────────────
#  FILE SKIP TESTS
# ─────────────────────────────────────────────────────────────────────────────

def test_skip_png_file():
    assert _should_skip("image.png") is True

def test_skip_lock_file():
    assert _should_skip("package-lock.json") is False  # .json is not in skip list
    assert _should_skip("poetry.lock") is True          # .lock IS in skip list

def test_dont_skip_python_file():
    assert _should_skip("config.py") is False

def test_dont_skip_terraform_file():
    assert _should_skip("main.tf") is False


# ─────────────────────────────────────────────────────────────────────────────
#  REGEX PATTERN DETECTION TESTS
# ─────────────────────────────────────────────────────────────────────────────

def test_detect_aws_access_key():
    """SEC-001: AWS Access Key ID must be caught."""
    patterns  = _get_patterns()
    content   = 'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"'
    findings  = scan_text(content, "config.py", patterns)
    rule_ids  = [f["rule_id"] for f in findings]
    assert "SEC-001" in rule_ids, f"Expected SEC-001, got: {rule_ids}"


def test_detect_stripe_key():
    """SEC-003: Stripe live key must be caught."""
    patterns  = _get_patterns()
    content   = 'STRIPE = "sk_live_abc123xyz789ABCDEF012345678"'
    findings  = scan_text(content, "payments.py", patterns)
    rule_ids  = [f["rule_id"] for f in findings]
    assert "SEC-003" in rule_ids, f"Expected SEC-003, got: {rule_ids}"


def test_detect_github_pat():
    """SEC-004: GitHub PAT must be caught."""
    patterns  = _get_patterns()
    content   = 'TOKEN = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"'
    findings  = scan_text(content, "deploy.sh", patterns)
    rule_ids  = [f["rule_id"] for f in findings]
    assert "SEC-004" in rule_ids, f"Expected SEC-004, got: {rule_ids}"


def test_detect_private_key_header():
    """SEC-007: Private key header must be caught."""
    patterns  = _get_patterns()
    content   = "-----BEGIN RSA PRIVATE KEY-----"
    findings  = scan_text(content, "id_rsa", patterns)
    rule_ids  = [f["rule_id"] for f in findings]
    assert "SEC-007" in rule_ids, f"Expected SEC-007, got: {rule_ids}"


def test_detect_hardcoded_password():
    """SEC-006: Hardcoded password variable must be caught."""
    patterns  = _get_patterns()
    content   = 'DB_PASSWORD = "SuperSecret@Database123"'
    findings  = scan_text(content, "settings.py", patterns)
    rule_ids  = [f["rule_id"] for f in findings]
    assert "SEC-006" in rule_ids, f"Expected SEC-006, got: {rule_ids}"


def test_clean_file_no_findings():
    """A file with no secrets must return an empty findings list."""
    patterns  = _get_patterns()
    content   = """
# Clean configuration file
import os

DEBUG = False
DATABASE_URL = os.environ.get("DATABASE_URL")
API_KEY      = os.environ.get("API_KEY")
"""
    findings = scan_text(content, "config.py", patterns)
    # Only check regex findings (not entropy which may flag env var names)
    regex_findings = [f for f in findings if f["rule_id"] != "SEC-010"]
    assert len(regex_findings) == 0, (
        f"Expected no findings on clean file, got: {regex_findings}"
    )


def test_scan_secrets_fixture_file():
    """The secrets_sample.py fixture must produce multiple findings."""
    patterns  = _get_patterns()
    content   = (FIXTURES / "secrets_sample.py").read_text(encoding="utf-8")
    findings  = scan_text(content, "secrets_sample.py", patterns)
    assert len(findings) >= 4, (
        f"Expected at least 4 findings in secrets_sample.py, got {len(findings)}"
    )


def test_finding_has_line_number():
    """Each finding must include a line number."""
    patterns = _get_patterns()
    content  = 'line1\nAWS_KEY = "AKIAIOSFODNN7EXAMPLE"\nline3'
    findings = scan_text(content, "test.py", patterns)
    for f in findings:
        assert "line" in f, f"Finding missing 'line' key: {f}"
        assert isinstance(f["line"], int)


def test_secret_finding_has_required_fields():
    """Every secret finding must contain the required output keys including description."""
    patterns = _get_patterns()
    content  = 'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"'
    findings = scan_text(content, "config.py", patterns)
    required = {"rule_id", "rule_name", "severity", "standard", "description", "file", "line", "detail", "fix"}
    for finding in findings:
        if finding["rule_id"] == "SEC-010":
            continue   # Entropy findings use a hardcoded description
        missing = required - set(finding.keys())
        assert not missing, f"Secret finding missing keys {missing}: {finding}"


def test_secret_finding_description_is_non_empty():
    """Every secret finding must have a non-empty policy description."""
    patterns = _get_patterns()
    content  = 'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"'
    findings = scan_text(content, "config.py", patterns)
    for finding in findings:
        assert finding.get("description", "").strip(), (
            f"Secret finding {finding['rule_id']} has empty description"
        )
