"""
iac_parser.py — Infrastructure-as-Code Lexical Parser
======================================================
Converts Dockerfile and Terraform (.tf) files into Python
dictionaries that the policy engine can evaluate.

Supports:
  - Dockerfile  → parse_dockerfile()
  - Terraform   → parse_terraform()

Public interface:
  parse_file(filepath: Path) -> dict | None
"""

import re
from pathlib import Path


# ─────────────────────────────────────────────────────────────────────────────
#  INTERNAL HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _is_dockerfile(path):
    """
    Return True if the file is a Dockerfile or a Dockerfile variant.

    Matches:
      - Dockerfile            (production)
      - bad_dockerfile        (test fixture)
      - good_dockerfile       (test fixture)
      - Dockerfile.prod       (multi-stage variant)
      - Dockerfile.dev
    """
    name = path.name.lower()
    return "dockerfile" in name


# ─────────────────────────────────────────────────────────────────────────────
#  PUBLIC INTERFACE
# ─────────────────────────────────────────────────────────────────────────────

def parse_file(filepath):
    """
    Route a file to the correct parser based on its name/extension.

    Args:
        filepath (str | Path): Path to the IaC file.

    Returns:
        dict with keys:
            file_type   (str)  : "dockerfile" or "terraform"
            file_path   (str)  : original path as string
            parsed_data (dict) : structured representation of the file
        or None if the file type is not supported / cannot be parsed.
    """
    path = Path(filepath)

    try:
        if _is_dockerfile(path):
            parsed = parse_dockerfile(path)
            return {
                "file_type":   "dockerfile",
                "file_path":   str(path),
                "parsed_data": parsed,
            }

        elif path.suffix == ".tf":
            parsed = parse_terraform(path)
            return {
                "file_type":   "terraform",
                "file_path":   str(path),
                "parsed_data": parsed,
            }

        else:
            return None   # Not an IaC file — caller should skip

    except (OSError, UnicodeDecodeError) as exc:
        # File read error — log and skip gracefully
        print(f"  [WARN] Could not read file '{path}': {exc}")
        return None

    except Exception as exc:  # noqa: BLE001
        print(f"  [WARN] Unexpected parse error in '{path}': {exc}")
        return None


# ─────────────────────────────────────────────────────────────────────────────
#  DOCKERFILE PARSER
# ─────────────────────────────────────────────────────────────────────────────

def parse_dockerfile(filepath):
    """
    Tokenize a Dockerfile into a dictionary of instruction → [arguments].

    Each Dockerfile instruction (FROM, USER, EXPOSE, ENV, RUN, COPY, ADD,
    HEALTHCHECK, …) becomes a key. The value is a list of all arguments seen
    for that instruction across the whole file.

    Example output:
        {
            "FROM":        ["ubuntu:latest"],
            "USER":        ["root"],
            "EXPOSE":      ["22", "80"],
            "ENV":         ["SECRET_KEY=abc123"],
            "HEALTHCHECK": []          # key present = instruction exists
        }

    Args:
        filepath (Path): Absolute or relative path to the Dockerfile.

    Returns:
        dict: Parsed instruction map.
    """
    result = {}

    with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
        for raw_line in fh:
            line = raw_line.strip()

            # Skip blank lines and comments
            if not line or line.startswith("#"):
                continue

            # Handle line continuations (backslash at end of line)
            # We join them in a pre-pass but keep it simple here:
            # split at first whitespace → (instruction, rest)
            parts = line.split(None, 1)  # maxsplit=1
            if not parts:
                continue

            instruction = parts[0].upper()
            argument    = parts[1].strip() if len(parts) > 1 else ""

            if instruction not in result:
                result[instruction] = []

            if instruction == "EXPOSE":
                # EXPOSE can list multiple ports: "EXPOSE 22 80 443"
                ports = argument.split()
                result[instruction].extend(ports)

            elif instruction == "ENV":
                # ENV can appear multiple times; collect each line as a whole
                result[instruction].append(argument)

            elif instruction == "HEALTHCHECK":
                # We only care that it exists; store argument for completeness
                result[instruction].append(argument)

            elif instruction in ("COPY", "ADD"):
                result[instruction].append(argument)

            else:
                # FROM, USER, RUN, CMD, ENTRYPOINT, WORKDIR, etc.
                result[instruction].append(argument)

    return result


# ─────────────────────────────────────────────────────────────────────────────
#  TERRAFORM (HCL) PARSER
# ─────────────────────────────────────────────────────────────────────────────

# Regex patterns for HCL tokenization
_RE_BLOCK_START  = re.compile(
    r'^(\w+)\s*"([^"]+)"\s*"([^"]+)"\s*\{')         # resource "type" "name" {
_RE_BLOCK_START2 = re.compile(
    r'^(\w+)\s*"([^"]+)"\s*\{')                      # provider "aws" {
_RE_BLOCK_START3 = re.compile(r'^(\w+)\s*\{')        # ingress {
_RE_ASSIGNMENT   = re.compile(
    r'^([\w-]+)\s*=\s*(.+)$')                        # key = value
_RE_LIST_VALUE   = re.compile(r'^\[([^\]]*)\]')      # ["a", "b"]
_RE_STRING_VALUE = re.compile(r'^"([^"]*)"')         # "value"
_RE_BOOL_VALUE   = re.compile(r'^(true|false)$')     # true / false
_RE_NUMBER_VALUE = re.compile(r'^-?\d+(\.\d+)?$')    # 22 / 3.14


def parse_terraform(filepath):
    """
    Perform a line-by-line lexical parse of a Terraform HCL file.

    Converts nested block structures into nested Python dictionaries.
    This is not a full HCL parser — it covers the subset of HCL needed
    for policy evaluation (resource blocks, key=value assignments, lists).

    Example output:
        {
            "resource": {
                "aws_s3_bucket": {
                    "my_bucket": {
                        "acl": "public-read"
                    }
                },
                "aws_security_group": {
                    "my_sg": {
                        "ingress": {
                            "from_port":   "22",
                            "cidr_blocks": ["0.0.0.0/0"]
                        }
                    }
                }
            }
        }

    Args:
        filepath (Path): Absolute or relative path to the .tf file.

    Returns:
        dict: Nested representation of the Terraform config.
    """
    root   = {}           # top-level result dict
    stack  = [root]       # stack of dicts — current nesting context
    labels = []           # stack of (key, sub-key) tuples tracking block names

    with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
        for raw_line in fh:
            line = raw_line.strip()

            # Skip blank lines and comments (# and //)
            if not line or line.startswith("#") or line.startswith("//"):
                continue

            # ── Block closing  } ──────────────────────────────────────────
            if line == "}":
                if len(stack) > 1:
                    stack.pop()
                    if labels:
                        labels.pop()
                continue

            # ── Block opening: resource "aws_s3_bucket" "my_bucket" { ─────
            m = _RE_BLOCK_START.match(line)
            if m:
                block_kw, type_label, name_label = m.groups()
                current = stack[-1]
                current.setdefault(block_kw, {})
                current[block_kw].setdefault(type_label, {})
                current[block_kw][type_label].setdefault(name_label, {})
                new_scope = current[block_kw][type_label][name_label]
                stack.append(new_scope)
                labels.append((block_kw, type_label, name_label))
                continue

            # ── Block opening: provider "aws" { ───────────────────────────
            m = _RE_BLOCK_START2.match(line)
            if m:
                block_kw, type_label = m.groups()
                current = stack[-1]
                current.setdefault(block_kw, {})
                current[block_kw].setdefault(type_label, {})
                new_scope = current[block_kw][type_label]
                stack.append(new_scope)
                labels.append((block_kw, type_label))
                continue

            # ── Block opening: ingress { ──────────────────────────────────
            m = _RE_BLOCK_START3.match(line)
            if m and line.endswith("{"):
                block_kw = m.group(1)
                current = stack[-1]
                current.setdefault(block_kw, {})
                stack.append(current[block_kw])
                labels.append((block_kw,))
                continue

            # ── Key = Value assignment ────────────────────────────────────
            m = _RE_ASSIGNMENT.match(line)
            if m:
                key, raw_value = m.groups()
                raw_value = raw_value.strip().rstrip(",")
                value = _parse_value(raw_value)
                stack[-1][key] = value
                continue

    return root


def _parse_value(raw):
    """
    Convert a raw HCL value string to the appropriate Python type.

    Handles: lists, quoted strings, booleans, numbers, bare words.
    """
    raw = raw.strip()

    # List: ["a", "b"] or [22, 80]
    m = _RE_LIST_VALUE.match(raw)
    if m:
        inner  = m.group(1).strip()
        if not inner:
            return []
        items  = [i.strip().strip('"') for i in inner.split(",")]
        return [i for i in items if i]   # remove empty strings

    # Quoted string: "value"
    m = _RE_STRING_VALUE.match(raw)
    if m:
        return m.group(1)

    # Boolean: true / false
    m = _RE_BOOL_VALUE.match(raw)
    if m:
        return raw == "true"

    # Number: 22 or 3.14
    m = _RE_NUMBER_VALUE.match(raw)
    if m:
        return float(raw) if "." in raw else int(raw)

    # Bare word / heredoc / expression — return as string
    return raw.strip('"')
