# iac_parser.py — The Infrastructure-as-Code Parser

## What Is This File?

`engine/iac_parser.py` reads IaC (Infrastructure-as-Code) files and converts them
into a Python dictionary that the policy engine can understand.

It is the **"translator"** of the system. It takes files written in specialized
formats (HCL for Terraform, Dockerfile syntax) and turns them into a common,
standard Python data structure.

---

## Why Do We Need a Parser?

The policy engine speaks Python. But IaC files are written in their own languages:

```hcl
# Terraform HCL — NOT valid Python
resource "aws_s3_bucket" "my_bucket" {
  acl = "public-read"
}
```

```dockerfile
# Dockerfile — also NOT valid Python
FROM ubuntu:latest
USER root
EXPOSE 22
```

The parser's job: **translate both of these into Python dicts** so the policy engine
can evaluate them with a single, unified interface.

---

## The Two Parsers Inside This File

### Parser 1: Dockerfile Tokenizer

**Input:**
```dockerfile
FROM ubuntu:20.04
USER root
EXPOSE 22 80
ENV SECRET_KEY=abc123def456
```

**Output (Python dict):**
```python
{
    "FROM": ["ubuntu:20.04"],
    "USER": ["root"],
    "EXPOSE": ["22", "80"],
    "ENV": ["SECRET_KEY=abc123def456"]
}
```

**How it works (step by step):**
1. Read the file line by line
2. Skip blank lines and lines starting with `#` (comments)
3. Split each line at the first space → instruction + argument
4. Group all arguments by instruction keyword

---

### Parser 2: Terraform HCL Tokenizer

HCL (HashiCorp Configuration Language) is more complex — it has nested blocks.

**Input:**
```hcl
resource "aws_s3_bucket" "my_bucket" {
  acl    = "public-read"
  region = "us-east-1"
}

resource "aws_security_group" "my_sg" {
  ingress {
    from_port   = 22
    cidr_blocks = ["0.0.0.0/0"]
  }
}
```

**Output (Python dict):**
```python
{
    "resource": {
        "aws_s3_bucket": {
            "my_bucket": {
                "acl": "public-read",
                "region": "us-east-1"
            }
        },
        "aws_security_group": {
            "my_sg": {
                "ingress": {
                    "from_port": "22",
                    "cidr_blocks": ["0.0.0.0/0"]
                }
            }
        }
    }
}
```

**How it works (step by step):**
1. Read the file line by line
2. Detect block openings (lines ending with `{`) → push to a stack
3. Detect block closings (`}`) → pop from the stack
4. Detect assignments (`key = value`) → store in current block
5. Detect list values (`["a", "b"]`) → store as Python list

---

## The Concept: Lexical Analysis

What we're doing here is called **Lexical Analysis** (or **Tokenization**).

It's the same first step that all compilers use (like the Python interpreter itself).

```
Raw text  ──►  Tokenizer  ──►  Tokens  ──►  Parser  ──►  Data Structure
```

| Term | Meaning |
|---|---|
| **Token** | A meaningful unit of text (`FROM`, `ubuntu:latest`, `=`, `{`) |
| **Lexer / Tokenizer** | The code that splits raw text into tokens |
| **Parser** | The code that assembles tokens into structured data |
| **AST** | Abstract Syntax Tree — a tree-shaped data structure (we use a dict) |

We build a simplified version (a flat/nested dict instead of a full AST) which is
sufficient for our rule-checking needs.

---

## Smart Routing — How The File Gets To The Right Parser

The parser detects which format to use based on the file name:

```python
def parse_file(filepath):
    if filepath.name == "Dockerfile":
        return parse_dockerfile(filepath)
    elif filepath.suffix == ".tf":
        return parse_terraform(filepath)
    else:
        return None   # Not an IaC file — skip
```

---

## What Gets Returned

The parser always returns a **standardized dict**:

```python
{
    "file_type": "dockerfile",       # or "terraform"
    "file_path": "infra/Dockerfile",
    "parsed_data": { ... }           # the actual parsed content
}
```

This standard format means the policy engine doesn't need to know what type of
file it came from — it just reads the dict.

---

## Error Handling

If a file cannot be parsed (encoding error, malformed syntax, etc.):
- The parser logs a WARNING (does not crash)
- Returns `None`
- The orchestrator skips that file and continues scanning others

---

## Key Python Concepts Used

| Concept | Where Used |
|---|---|
| `pathlib.Path` | File path handling (works on Windows and Linux) |
| `open(file, encoding='utf-8')` | Safe file reading with explicit encoding |
| `str.split(maxsplit=1)` | Split instruction from argument on first space |
| Stack (list as stack) | Track nested `{ }` blocks in HCL using `.append()` / `.pop()` |
| `re.match()` | Detect assignment lines (`key = "value"`) |
