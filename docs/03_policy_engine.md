# policy_engine.py — The Rule Evaluator

## What Is This File?

`engine/policy_engine.py` is the **brain** of the IaC scanning system.

It receives the parsed Python dictionary from `iac_parser.py`, loads the rules
from `policy.yaml`, and then methodically checks every applicable rule against
the parsed data.

It answers one question: **"Does this IaC file violate any security rule?"**

---

## Where It Fits In The Pipeline

```
iac_parser.py
    └─► Returns parsed dict
         │
         ▼
policy_engine.py  ◄── also loads policy.yaml
    └─► Checks each rule
         └─► Returns list of violations
              │
              ▼
         reporter.py
```

---

## How It Works (Step by Step)

### Step 1: Load the Rulebook
On startup, the engine loads `config/policy.yaml` once into memory.

```python
with open("config/policy.yaml", "r") as f:
    rules = yaml.safe_load(f)
```

**Why `yaml.safe_load` and not `yaml.load`?**
`yaml.load()` can execute arbitrary Python code embedded in YAML (a security risk!).
`yaml.safe_load()` only loads data — no code execution. Always use safe_load.

---

### Step 2: Route to the Correct Policy Block

Based on the file type from the parser:

```python
if file_type == "dockerfile":
    applicable_rules = rules["docker_policies"]
elif file_type == "terraform":
    applicable_rules = rules["aws_policies"]
```

This is called **Smart Routing**. A Dockerfile is never checked against AWS rules,
and a Terraform file is never checked against Docker rules. This prevents false positives.

---

### Step 3: Evaluate Each Rule

For each rule in the applicable list, the engine dispatches to the correct
evaluator function based on the rule's `check_type`:

```python
evaluators = {
    "key_value_match":     evaluate_key_value_match,
    "key_value_not_match": evaluate_key_value_not_match,
    "key_absent":          evaluate_key_absent,
    "cidr_check":          evaluate_cidr,
    "image_tag_check":     evaluate_image_tag,
    "port_check":          evaluate_port,
    "env_secret_check":    evaluate_env_secret,
}

result = evaluators[rule["check_type"]](parsed_data, rule)
```

This is the **Dispatcher Pattern** — a dictionary maps rule types to functions.
Adding a new check type means adding one function + one line in the dictionary.

---

## The 7 Evaluator Functions

### 1. `key_value_match`
Fails if a specific key equals a forbidden value.

```
Rule: "acl must not be public-read"
Check: parsed["acl"] == "public-read"  → VIOLATION
```

**Real rule example:** S3 bucket ACL set to `"public-read"` or `"public-read-write"`

---

### 2. `key_value_not_match`
Fails if a key does NOT equal the required value.

```
Rule: "encryption must be true"
Check: parsed["encrypted"] != "true"  → VIOLATION
```

**Real rule example:** RDS database encryption not enabled

---

### 3. `key_absent`
Fails if an important key is completely missing from the config.

```
Rule: "Dockerfile must have HEALTHCHECK"
Check: "HEALTHCHECK" not in parsed  → VIOLATION
```

**Real rule example:** Docker containers with no health check defined

---

### 4. `cidr_check`
Parses CIDR network blocks and fails if any rule allows `0.0.0.0/0`
(meaning: open to the entire internet) on a sensitive port.

```
Rule: "SSH (port 22) must not be open to internet"
Check: cidr_blocks contains "0.0.0.0/0" AND port == 22  → VIOLATION
```

**What is a CIDR?**
`0.0.0.0/0` = every IP address on earth = anyone can connect.
`10.0.0.0/8` = only internal corporate network.

---

### 5. `image_tag_check`
Fails if a Docker `FROM` instruction uses the `:latest` tag.

```
Rule: "Never use :latest — use a specific version"
Check: "FROM ubuntu:latest"  → VIOLATION
       "FROM ubuntu:20.04"   → PASS
```

**Why?** `:latest` is non-deterministic. Today it's safe, tomorrow it might
pull a vulnerable version. Specific tags ensure reproducible, auditable builds.

---

### 6. `port_check`
Fails if a Dockerfile `EXPOSE`s a port considered dangerous.

```
Rule: "Do not expose port 22 (SSH)"
Check: "22" in parsed["EXPOSE"]  → VIOLATION
```

Dangerous ports checked: **22** (SSH), **23** (Telnet), **3389** (RDP/Windows Remote Desktop)

---

### 7. `env_secret_check`
Scans `ENV` lines in Dockerfiles for embedded secrets using regex patterns.

```
Rule: "No secrets in ENV instructions"
Check: ENV SECRET_KEY=abc123  →  matches secret pattern  → VIOLATION
```

---

## What Gets Returned

The engine returns a list of **Finding objects** (Python dicts):

```python
[
    {
        "rule_id":   "AWS-002",
        "rule_name": "SSH Port Open to World",
        "severity":  "CRITICAL",
        "standard":  "AWS Well-Architected SEC-5",
        "file":      "infra/main.tf",
        "detail":    "ingress allows 0.0.0.0/0 on port 22",
        "fix":       "Restrict cidr_blocks to a specific IP range"
    },
    ...
]
```

An empty list `[]` means: no violations found — the file is clean.

---

## Key Python Concepts Used

| Concept | Where Used |
|---|---|
| `yaml.safe_load()` | Safely load YAML without code execution risk |
| Dispatcher dict | Map `check_type` strings to evaluator functions |
| `dict.get(key, default)` | Safe key access without KeyError crashes |
| List comprehension | Filter rules, collect violations efficiently |
| `ipaddress` module | Validate and compare CIDR network ranges |
