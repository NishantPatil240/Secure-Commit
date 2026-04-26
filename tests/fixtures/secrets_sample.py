# secrets_sample.py — Test fixture for secret scanner
# This file intentionally contains hardcoded secrets FOR TESTING ONLY.
# It should NEVER be committed to a real repository.

import os

# SEC-001: AWS Access Key ID
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"

# SEC-002: AWS Secret Access Key
aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# SEC-003: Stripe Live Key
STRIPE_SECRET = "sk_live_abc123xyz789ABCDEF012345678"

# SEC-004: GitHub Personal Access Token
GITHUB_TOKEN = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"

# SEC-006: Private key header (inline)
PRIVATE_KEY_HEADER = "-----BEGIN RSA PRIVATE KEY-----"

# SEC-007: Hardcoded password
DB_PASSWORD = "SuperSecret@Database123"

# SEC-008: Google Cloud API Key
GCP_KEY = "AIzaSyD-9tSrke72I6e5DvCE6GBw1t5GGQh9Xjk"

# This is fine — not a secret (should NOT be flagged)
VERSION_HASH = "a1b2c3d4e5f6"
CHECKSUM_MD5 = "d41d8cd98f00b204e9800998ecf8427e"
