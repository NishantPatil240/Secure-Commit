"""
test_iac_parser.py — Unit tests for engine/iac_parser.py
"""

import sys
from pathlib import Path

# Add project root to path so engine/ is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from engine.iac_parser import parse_file, parse_dockerfile, parse_terraform

FIXTURES = Path(__file__).parent / "fixtures"


# ─────────────────────────────────────────────────────────────────────────────
#  DOCKERFILE PARSER TESTS
# ─────────────────────────────────────────────────────────────────────────────

def test_parse_dockerfile_returns_dict():
    """parse_file() on a Dockerfile must return a dict with correct keys."""
    result = parse_file(FIXTURES / "bad_dockerfile")
    assert result is not None
    assert result["file_type"] == "dockerfile"
    assert isinstance(result["parsed_data"], dict)


def test_parse_dockerfile_user_root():
    """USER instruction must be captured correctly."""
    result = parse_file(FIXTURES / "bad_dockerfile")
    data   = result["parsed_data"]
    assert "USER" in data
    assert "root" in data["USER"]


def test_parse_dockerfile_expose_ports():
    """EXPOSE must return a list of port strings."""
    result = parse_file(FIXTURES / "bad_dockerfile")
    data   = result["parsed_data"]
    assert "EXPOSE" in data
    assert "22" in data["EXPOSE"]


def test_parse_dockerfile_env_present():
    """ENV instructions must be captured."""
    result = parse_file(FIXTURES / "bad_dockerfile")
    data   = result["parsed_data"]
    assert "ENV" in data
    # At least one ENV line should contain the secret key
    assert any("SECRET_KEY" in env for env in data["ENV"])


def test_parse_good_dockerfile_healthcheck():
    """Good Dockerfile must have HEALTHCHECK key."""
    result = parse_file(FIXTURES / "good_dockerfile")
    data   = result["parsed_data"]
    assert "HEALTHCHECK" in data


def test_parse_good_dockerfile_user_not_root():
    """Good Dockerfile USER should not be root."""
    result = parse_file(FIXTURES / "good_dockerfile")
    data   = result["parsed_data"]
    assert "root" not in data.get("USER", [])


def test_unknown_file_returns_none():
    """A .txt file is not an IaC file — must return None."""
    result = parse_file(Path("some_random_file.txt"))
    assert result is None


# ─────────────────────────────────────────────────────────────────────────────
#  TERRAFORM PARSER TESTS
# ─────────────────────────────────────────────────────────────────────────────

def test_parse_terraform_returns_dict():
    """parse_file() on a .tf file must return correct structure."""
    result = parse_file(FIXTURES / "bad_terraform.tf")
    assert result is not None
    assert result["file_type"] == "terraform"
    assert isinstance(result["parsed_data"], dict)


def test_parse_terraform_s3_acl():
    """S3 bucket ACL must be parsed from Terraform."""
    result = parse_file(FIXTURES / "bad_terraform.tf")
    data   = result["parsed_data"]
    s3     = data.get("resource", {}).get("aws_s3_bucket", {})
    assert len(s3) > 0
    # At least one bucket has acl = public-read
    found_public = any(
        b.get("acl") == "public-read" for b in s3.values()
    )
    assert found_public, "Expected public-read ACL in bad terraform fixture"


def test_parse_terraform_cidr():
    """Security group CIDR blocks must be parsed as a list."""
    result = parse_file(FIXTURES / "bad_terraform.tf")
    data   = result["parsed_data"]
    sgs    = data.get("resource", {}).get("aws_security_group", {})
    for sg in sgs.values():
        ingress = sg.get("ingress", {})
        cidr    = ingress.get("cidr_blocks", [])
        if "0.0.0.0/0" in cidr:
            return   # Found — test passes
    assert False, "Expected 0.0.0.0/0 CIDR in bad terraform fixture"


def test_parse_good_terraform_private_acl():
    """Good Terraform S3 bucket must have private ACL."""
    result = parse_file(FIXTURES / "good_terraform.tf")
    data   = result["parsed_data"]
    s3     = data.get("resource", {}).get("aws_s3_bucket", {})
    all_private = all(b.get("acl") == "private" for b in s3.values())
    assert all_private, "All S3 buckets in good fixture should be private"
