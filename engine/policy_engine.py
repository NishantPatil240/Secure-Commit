"""
policy_engine.py — IaC Policy Rule Evaluator
=============================================
Loads config/policy.yaml and evaluates parsed IaC dictionaries
(from iac_parser.py) against the applicable rule set.

Public interface:
    load_policies(policy_path: Path)  -> dict
    run_policy_engine(parsed: dict, policies: dict) -> list[dict]
"""

import re
import ipaddress
from pathlib import Path

import yaml


# ─────────────────────────────────────────────────────────────────────────────
#  POLICY LOADER
# ─────────────────────────────────────────────────────────────────────────────

def load_policies(policy_path=None):
    """
    Load and return the policy rulebook from policy.yaml.

    Uses yaml.safe_load() — never yaml.load() — to prevent code execution
    from maliciously crafted YAML content.

    Args:
        policy_path (Path | str | None): Path to policy.yaml.
            Defaults to config/policy.yaml relative to project root.

    Returns:
        dict: Full parsed YAML content including settings, docker_policies,
              aws_policies, and secret_patterns.

    Raises:
        FileNotFoundError: If policy.yaml does not exist at the given path.
        yaml.YAMLError:    If the YAML is malformed.
    """
    if policy_path is None:
        # Resolve relative to this file's location: engine/ -> project root -> config/
        policy_path = Path(__file__).parent.parent / "config" / "policy.yaml"

    policy_path = Path(policy_path)

    if not policy_path.exists():
        raise FileNotFoundError(
            f"Policy file not found: {policy_path}\n"
            "Ensure config/policy.yaml exists in the project root."
        )

    with open(policy_path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


# ─────────────────────────────────────────────────────────────────────────────
#  PUBLIC INTERFACE
# ─────────────────────────────────────────────────────────────────────────────

def run_policy_engine(parsed, policies):
    """
    Evaluate a parsed IaC file against the matching policy block.

    Routes automatically:
        file_type == "dockerfile"  →  docker_policies
        file_type == "terraform"   →  aws_policies

    Args:
        parsed   (dict): Output from iac_parser.parse_file() — contains
                         file_type, file_path, parsed_data.
        policies (dict): Loaded policy rulebook from load_policies().

    Returns:
        list[dict]: List of Finding dicts. Empty list = no violations.
                    Each finding has: rule_id, rule_name, severity,
                    standard, file, detail, fix.
    """
    file_type   = parsed.get("file_type", "")
    file_path   = parsed.get("file_path", "unknown")
    parsed_data = parsed.get("parsed_data", {})
    findings    = []

    # ── Smart Routing ─────────────────────────────────────────────────────
    if file_type == "dockerfile":
        rules = policies.get("docker_policies", [])
    elif file_type == "terraform":
        rules = policies.get("aws_policies", [])
    else:
        return []   # Unknown file type — skip

    # ── Dispatcher: check_type → evaluator function ───────────────────────
    evaluators = {
        "key_value_match":     _eval_key_value_match,
        "key_value_not_match": _eval_key_value_not_match,
        "key_absent":          _eval_key_absent,
        "cidr_check":          _eval_cidr_check,
        "image_tag_check":     _eval_image_tag_check,
        "port_check":          _eval_port_check,
        "env_secret_check":    _eval_env_secret_check,
        "copy_secret_check":   _eval_copy_secret_check,
    }

    for rule in rules:
        check_type = rule.get("check_type")
        evaluator  = evaluators.get(check_type)

        if evaluator is None:
            # Unknown check_type — skip gracefully
            continue

        violation = evaluator(parsed_data, rule, file_path)
        if violation:
            findings.append(violation)

    return findings


# ─────────────────────────────────────────────────────────────────────────────
#  HELPER — BUILD A FINDING DICT
# ─────────────────────────────────────────────────────────────────────────────

def _make_finding(rule, file_path, detail):
    """Construct a standardised finding dictionary."""
    # Strip leading/trailing whitespace from multi-line YAML descriptions
    description = rule.get("description", "")
    if isinstance(description, str):
        description = " ".join(description.split())
    return {
        "rule_id":     rule.get("id", "UNKNOWN"),
        "rule_name":   rule.get("name", "Unnamed Rule"),
        "severity":    rule.get("severity", "MEDIUM"),
        "standard":    rule.get("standard", "N/A"),
        "description": description,
        "file":        file_path,
        "detail":      detail,
        "fix":         rule.get("fix", "No fix guidance available."),
    }


# ─────────────────────────────────────────────────────────────────────────────
#  EVALUATOR FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

def _eval_key_value_match(data, rule, file_path):
    """
    DOCK-001, DOCK-006, AWS-001, AWS-007
    Fails if a key anywhere in the data equals a forbidden value.

    For Dockerfile: checks top-level keys (USER, PRIVILEGED).
    For Terraform:  searches all resource blocks of the target resource_type.
    """
    key            = rule.get("key", "")
    forbidden      = rule.get("forbidden_value") or rule.get("forbidden_values", [])
    resource_type  = rule.get("resource_type")   # None for Dockerfile rules

    if isinstance(forbidden, str):
        forbidden = [forbidden]

    if resource_type:
        # Terraform — search inside resource blocks
        return _check_terraform_key(data, resource_type, key, forbidden, rule, file_path)
    else:
        # Dockerfile — top-level key check
        values = data.get(key, [])
        for val in values:
            if isinstance(val, str) and val.lower() in [f.lower() for f in forbidden]:
                return _make_finding(rule, file_path,
                    f"'{key}' is set to '{val}' (forbidden value)")
    return None


def _eval_key_value_not_match(data, rule, file_path):
    """
    AWS-003, AWS-006, AWS-008
    Fails if a key does NOT equal the required value.
    This catches missing encryption flags, disabled logging, etc.
    """
    key            = rule.get("key", "")
    required       = rule.get("required_value", "")
    resource_type  = rule.get("resource_type")

    if resource_type:
        resources = _get_resources(data, resource_type)
        for res_name, res_body in resources.items():
            actual = str(res_body.get(key, "")).lower()
            req    = str(required).lower()
            if actual != req:
                return _make_finding(rule, file_path,
                    f"'{key}' is '{actual or 'not set'}' but must be '{required}' "
                    f"(resource: {resource_type}.{res_name})")
    return None


def _eval_key_absent(data, rule, file_path):
    """
    DOCK-004, AWS-004
    Fails if an important key is completely missing from the config.
    """
    key           = rule.get("key", "")
    resource_type = rule.get("resource_type")

    if resource_type:
        resources = _get_resources(data, resource_type)
        for res_name, res_body in resources.items():
            if key not in res_body:
                return _make_finding(rule, file_path,
                    f"Required key '{key}' is absent "
                    f"(resource: {resource_type}.{res_name})")
    else:
        # Dockerfile — check top-level instruction presence
        if key not in data:
            return _make_finding(rule, file_path,
                f"Required Dockerfile instruction '{key}' is missing")
    return None


def _eval_cidr_check(data, rule, file_path):
    """
    AWS-002, AWS-005
    Fails if an ingress/egress rule allows a forbidden CIDR (e.g. 0.0.0.0/0)
    on a sensitive port.
    """
    resource_type   = rule.get("resource_type", "aws_security_group")
    sensitive_ports = [int(p) for p in rule.get("sensitive_ports", [])]
    forbidden_cidrs = rule.get("forbidden_cidr", ["0.0.0.0/0"])
    resources       = _get_resources(data, resource_type)

    for res_name, res_body in resources.items():
        # ingress/egress may be a nested dict
        for direction in ("ingress", "egress"):
            rule_block = res_body.get(direction, {})
            if not isinstance(rule_block, dict):
                continue

            cidr_blocks  = rule_block.get("cidr_blocks", [])
            from_port    = int(rule_block.get("from_port", -1))
            to_port      = int(rule_block.get("to_port", from_port))

            if not isinstance(cidr_blocks, list):
                cidr_blocks = [cidr_blocks]

            for cidr in cidr_blocks:
                if cidr in forbidden_cidrs:
                    # Check if any sensitive port falls in the range.
                    # Special case: port 0 in the policy means the rule targets
                    # "all-ports-open" configs (from_port=0, to_port=0, protocol=-1).
                    # It should only fire when the FILE itself has from_port=0 AND to_port=0.
                    for port in sensitive_ports:
                        if port == 0:
                            # Only flag if the file actually opens all ports (0-0)
                            if from_port == 0 and to_port == 0:
                                return _make_finding(rule, file_path,
                                    f"{direction} allows '{cidr}' on port {port} "
                                    f"(resource: {resource_type}.{res_name})")
                        elif from_port <= port <= to_port:
                            return _make_finding(rule, file_path,
                                f"{direction} allows '{cidr}' on port {port} "
                                f"(resource: {resource_type}.{res_name})")
    return None


def _eval_image_tag_check(data, rule, file_path):
    """
    DOCK-003
    Fails if a FROM instruction uses the :latest tag (or no tag at all).
    """
    from_values = data.get("FROM", [])
    for image in from_values:
        # Skip build-stage aliases: "FROM golang:1.21 AS builder"
        image_name = image.split(" ")[0]
        if ":" not in image_name or image_name.endswith(":latest"):
            return _make_finding(rule, file_path,
                f"FROM uses non-deterministic image: '{image_name}'. "
                "Always pin to a specific version tag.")
    return None


def _eval_port_check(data, rule, file_path):
    """
    DOCK-002
    Fails if EXPOSE contains any port listed in forbidden_ports.
    """
    forbidden_ports = [str(p) for p in rule.get("forbidden_ports", [])]
    exposed_ports   = data.get("EXPOSE", [])

    for port in exposed_ports:
        if str(port) in forbidden_ports:
            return _make_finding(rule, file_path,
                f"Dangerous port {port} is exposed. "
                "Remove this EXPOSE instruction.")
    return None


def _eval_env_secret_check(data, rule, file_path):
    """
    DOCK-005
    Scans ENV instruction values for patterns that look like secrets.
    Uses the same regex patterns from the secret_patterns block if available.
    """
    # Quick built-in patterns for ENV lines
    _secret_indicators = re.compile(
        r"(?i)(password|secret|key|token|api_key|passwd|credential)\s*=\s*\S{6,}",
        re.IGNORECASE
    )
    env_lines = data.get("ENV", [])
    for env_line in env_lines:
        if _secret_indicators.search(env_line):
            return _make_finding(rule, file_path,
                f"ENV instruction contains a possible secret: '{env_line[:60]}...' "
                if len(env_line) > 60 else
                f"ENV instruction contains a possible secret: '{env_line}'")
    return None


def _eval_copy_secret_check(data, rule, file_path):
    """
    DOCK-007
    Fails if COPY or ADD instructions reference files that look like secrets
    (e.g. .env, .pem, id_rsa, credentials).
    """
    forbidden_patterns = rule.get("forbidden_patterns", [])
    instructions = data.get("COPY", []) + data.get("ADD", [])

    for instruction_args in instructions:
        for pattern in forbidden_patterns:
            if pattern.lower() in instruction_args.lower():
                return _make_finding(rule, file_path,
                    f"Sensitive file '{pattern}' is being copied into the image: "
                    f"'{instruction_args[:80]}'")
    return None


# ─────────────────────────────────────────────────────────────────────────────
#  TERRAFORM HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _get_resources(data, resource_type):
    """
    Extract all resources of a specific type from a parsed Terraform dict.

    Returns a dict of { resource_name: resource_body } for the given type.
    Returns {} if no resources of that type are found.
    """
    return data.get("resource", {}).get(resource_type, {})


def _check_terraform_key(data, resource_type, key, forbidden_values, rule, file_path):
    """
    Walk all resources of resource_type and check if key == any forbidden value.
    """
    resources = _get_resources(data, resource_type)
    for res_name, res_body in resources.items():
        if not isinstance(res_body, dict):
            continue
        actual = str(res_body.get(key, "")).lower()
        for fv in forbidden_values:
            if actual == fv.lower():
                return _make_finding(rule, file_path,
                    f"'{key}' = '{actual}' (forbidden) "
                    f"in resource: {resource_type}.{res_name}")
    return None
