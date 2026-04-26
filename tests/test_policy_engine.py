"""
test_policy_engine.py — Unit tests for engine/policy_engine.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from engine.iac_parser    import parse_file
from engine.policy_engine import load_policies, run_policy_engine

FIXTURES = Path(__file__).parent / "fixtures"


def _get_policies():
    return load_policies(Path(__file__).parent.parent / "config" / "policy.yaml")


# ─────────────────────────────────────────────────────────────────────────────
#  POLICY LOADING
# ─────────────────────────────────────────────────────────────────────────────

def test_load_policies_returns_dict():
    """Policy YAML must load successfully and return a dict."""
    policies = _get_policies()
    assert isinstance(policies, dict)
    assert "docker_policies" in policies
    assert "aws_policies" in policies
    assert "secret_patterns" in policies


def test_policies_have_required_fields():
    """Every policy rule must have id, name, severity, fix."""
    policies = _get_policies()
    all_rules = policies["docker_policies"] + policies["aws_policies"]
    for rule in all_rules:
        assert "id"       in rule, f"Rule missing 'id': {rule}"
        assert "name"     in rule, f"Rule missing 'name': {rule}"
        assert "severity" in rule, f"Rule missing 'severity': {rule}"
        assert "fix"      in rule, f"Rule missing 'fix': {rule}"


# ─────────────────────────────────────────────────────────────────────────────
#  DOCKERFILE POLICY CHECKS
# ─────────────────────────────────────────────────────────────────────────────

def test_bad_dockerfile_produces_findings():
    """Bad Dockerfile must generate at least one finding."""
    policies = _get_policies()
    parsed   = parse_file(FIXTURES / "bad_dockerfile")
    findings = run_policy_engine(parsed, policies)
    assert len(findings) > 0, "Expected violations from bad_dockerfile"


def test_bad_dockerfile_detects_root_user():
    """DOCK-001 must fire for USER root."""
    policies = _get_policies()
    parsed   = parse_file(FIXTURES / "bad_dockerfile")
    findings = run_policy_engine(parsed, policies)
    rule_ids = [f["rule_id"] for f in findings]
    assert "DOCK-001" in rule_ids, "Expected DOCK-001 (root user) violation"


def test_bad_dockerfile_detects_port_22():
    """DOCK-002 must fire for EXPOSE 22."""
    policies = _get_policies()
    parsed   = parse_file(FIXTURES / "bad_dockerfile")
    findings = run_policy_engine(parsed, policies)
    rule_ids = [f["rule_id"] for f in findings]
    assert "DOCK-002" in rule_ids, "Expected DOCK-002 (port 22) violation"


def test_bad_dockerfile_detects_latest_tag():
    """DOCK-003 must fire for FROM ubuntu:latest."""
    policies = _get_policies()
    parsed   = parse_file(FIXTURES / "bad_dockerfile")
    findings = run_policy_engine(parsed, policies)
    rule_ids = [f["rule_id"] for f in findings]
    assert "DOCK-003" in rule_ids, "Expected DOCK-003 (latest tag) violation"


def test_good_dockerfile_no_blocking_findings():
    """Good Dockerfile must produce zero CRITICAL or HIGH findings."""
    policies = _get_policies()
    parsed   = parse_file(FIXTURES / "good_dockerfile")
    findings = run_policy_engine(parsed, policies)
    blocking = [f for f in findings if f["severity"] in ("CRITICAL", "HIGH")]
    assert len(blocking) == 0, (
        f"Unexpected blocking violations in good_dockerfile: "
        f"{[f['rule_id'] for f in blocking]}"
    )


# ─────────────────────────────────────────────────────────────────────────────
#  TERRAFORM POLICY CHECKS
# ─────────────────────────────────────────────────────────────────────────────

def test_bad_terraform_produces_findings():
    """Bad Terraform must generate at least one finding."""
    policies = _get_policies()
    parsed   = parse_file(FIXTURES / "bad_terraform.tf")
    findings = run_policy_engine(parsed, policies)
    assert len(findings) > 0, "Expected violations from bad_terraform.tf"


def test_bad_terraform_detects_public_s3():
    """AWS-001 must fire for public-read ACL."""
    policies = _get_policies()
    parsed   = parse_file(FIXTURES / "bad_terraform.tf")
    findings = run_policy_engine(parsed, policies)
    rule_ids = [f["rule_id"] for f in findings]
    assert "AWS-001" in rule_ids, "Expected AWS-001 (public S3) violation"


def test_bad_terraform_detects_open_ssh():
    """AWS-002 must fire for SSH open to 0.0.0.0/0."""
    policies = _get_policies()
    parsed   = parse_file(FIXTURES / "bad_terraform.tf")
    findings = run_policy_engine(parsed, policies)
    rule_ids = [f["rule_id"] for f in findings]
    assert "AWS-002" in rule_ids, "Expected AWS-002 (open SSH) violation"


def test_good_terraform_no_blocking_findings():
    """Good Terraform must produce zero CRITICAL or HIGH findings."""
    policies = _get_policies()
    parsed   = parse_file(FIXTURES / "good_terraform.tf")
    findings = run_policy_engine(parsed, policies)
    blocking = [f for f in findings if f["severity"] in ("CRITICAL", "HIGH")]
    assert len(blocking) == 0, (
        f"Unexpected blocking violations in good_terraform.tf: "
        f"{[f['rule_id'] for f in blocking]}"
    )


def test_finding_has_required_fields():
    """Every finding must contain the required output keys including description."""
    policies = _get_policies()
    parsed   = parse_file(FIXTURES / "bad_terraform.tf")
    findings = run_policy_engine(parsed, policies)
    required = {"rule_id", "rule_name", "severity", "standard", "description", "file", "detail", "fix"}
    for finding in findings:
        missing = required - set(finding.keys())
        assert not missing, f"Finding missing keys {missing}: {finding}"


def test_finding_description_is_non_empty():
    """Every IaC finding must have a non-empty description (the policy reason)."""
    policies = _get_policies()
    parsed   = parse_file(FIXTURES / "bad_terraform.tf")
    findings = run_policy_engine(parsed, policies)
    for finding in findings:
        assert finding.get("description", "").strip(), (
            f"Finding {finding['rule_id']} has empty description"
        )
