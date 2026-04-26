# secret_scanner.py — The Secret & Credential Detector

## What Is This File?

`engine/secret_scanner.py` hunts for **leaked credentials and secrets** inside
your code files and Git history.

It covers two scenarios:
1. **Right now** — secrets in the files you are about to commit (staged files)
2. **The past** — secrets in old commits that were "deleted" but still exist in history

---

## Why Do We Need This?

Developers accidentally hardcode secrets all the time:

```python
# BAD — This will be detected and blocked
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
STRIPE_KEY = "sk_live_abc123xyz789"
DB_PASSWORD = "SuperSecret@123"
```

Even if you **delete** these lines later and commit again, the original commit still
exists in Git history. Anyone who clones the repo can run `git log -p` and see
the deleted secrets. This is called a **Ghost Secret**.

---

## The Two Scanners

### Scanner 1: Staged File Scanner

Scans the exact content that is **about to be committed** (not the working tree).

**Key distinction:**
```
Working tree  =  files on your disk right now
Staged index  =  files selected for commit with "git add"
```

We scan the **staged index**, not the working tree. This is important because:
- The file on disk might be clean (secret deleted)
- But the staged version still has the secret
- We catch the exact content Git will store

**How it works using GitPython:**
```python
repo = git.Repo(".")
staged_items = repo.index.diff("HEAD")  # files changed vs last commit

for item in staged_items:
    blob_content = item.a_blob.data_stream.read().decode("utf-8")
    # scan blob_content for secrets
```

---

### Scanner 2: Forensic History Scanner

Walks backwards through the last 50 commits and scans every diff (code change)
for secret patterns.

**How it works:**
```python
for commit in repo.iter_commits(max_count=50):
    for diff in commit.diff(commit.parents[0] if commit.parents else None):
        patch_text = diff.diff.decode("utf-8", errors="replace")
        # scan patch_text for secrets
```

This reads the actual `+` (added) lines from each commit's diff, which means
it catches secrets that were added in any commit — even if deleted in a later one.

---

## The Detection Methods

### Method 1: Regex DFA Patterns

**What is a DFA?**

A **Deterministic Finite Automaton** is a mathematical machine with:
- A set of states
- Transitions between states based on input characters
- An accept state (pattern matched) or reject state (no match)

Python's `re` module compiles regex patterns into DFA machines. This means:
- The pattern is compiled **once** at startup
- Matching runs at near-machine-speed for every string checked
- The result is 100% deterministic — same string always gives same result

**Our Pattern Library:**

| Rule ID | What It Catches | Pattern Example |
|---|---|---|
| `SEC-001` | AWS Access Key | `AKIA[0-9A-Z]{16}` |
| `SEC-002` | AWS Secret Key | 40-char alphanumeric near `aws_secret` |
| `SEC-003` | Generic API Key | `api[_-]?key\s*[:=]\s*['"]?[A-Za-z0-9]{20,}` |
| `SEC-004` | Stripe Live Key | `sk_live_[0-9a-zA-Z]{24}` |
| `SEC-005` | GitHub PAT | `ghp_[A-Za-z0-9]{36}` |
| `SEC-006` | Private Key Header | `-----BEGIN .* PRIVATE KEY-----` |
| `SEC-007` | Hardcoded Password | `password\s*[:=]\s*['"]?[^\s'"]{8,}` |
| `SEC-008` | Google API Key | `AIza[0-9A-Za-z\-_]{35}` |
| `SEC-009` | Slack Token | `xox[baprs]-[0-9A-Za-z]{10,}` |

---

### Method 2: Shannon Entropy Check

Some secrets don't match a known pattern (custom tokens, random strings).
For these, we use **information theory**.

**What is Shannon Entropy?**

Claude Shannon (founder of information theory) defined entropy as the measure
of randomness in a string:

```
H = -Σ p(c) × log₂(p(c))
```

Where:
- `p(c)` = probability of character `c` appearing in the string
- `Σ` = sum over all unique characters

**In plain English:**
- A string like `"aaaaaaa"` has very LOW entropy (not random, not a secret)
- A string like `"aB3$kL9mQzR2"` has HIGH entropy (very random, possibly a secret)

**Our threshold:**
```
entropy > 4.5 bits/char  AND  string length > 20 characters
    └─► Flagged as "possible high-entropy secret" (MEDIUM severity)
```

This catches secrets that look like random garbage but have no known format.

**Real example:**
```
String: "wJalrXUtnFEMI/K7MDENG/bPxRfi"
Entropy: 4.89 bits/char  →  FLAGGED
```

---

## False Positive Handling

Not every high-entropy string is a secret. Common false positives:
- Base64-encoded images embedded in HTML
- UUIDs in test files
- Hash values in lock files (`package-lock.json`, `poetry.lock`)

**How we reduce false positives:**
1. Check file extension — skip `.lock` files, binary files, images
2. Check context — is the string assigned to a variable named `hash`, `checksum`, `uuid`?
3. Only flag entropy strings that are adjacent to "suspicious" variable names

---

## What Gets Returned

```python
[
    {
        "rule_id":   "SEC-001",
        "rule_name": "AWS Access Key Detected",
        "severity":  "CRITICAL",
        "standard":  "OWASP A02:2021",
        "file":      "src/config.py",
        "line":      7,
        "detail":    "Matched pattern: AKIA[0-9A-Z]{16}",
        "fix":       "Remove key. Use IAM roles or environment variables instead."
    }
]
```

---

## Key Python Concepts Used

| Concept | Where Used |
|---|---|
| `re.compile()` | Pre-compile patterns once for speed |
| `re.finditer()` | Find ALL matches in a string, with position |
| Shannon entropy formula | `math.log2()` on character frequency |
| `git.Repo(".")` | Open current directory as a Git repo |
| `repo.iter_commits(max_count=50)` | Walk through last 50 commits |
| `commit.diff(parent)` | Get the diff between a commit and its parent |
| `.decode("utf-8", errors="replace")` | Safe binary-to-text decoding |
