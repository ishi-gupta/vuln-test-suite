"""Weak Cryptography vulnerabilities (CWE-327).

Intentionally vulnerable code for scanner validation.
Each function demonstrates a different weak cryptography pattern.
"""

import hashlib
import random
import string


# VULN: category=weak_crypto, id=crypto_001, severity=high
# Expected scanner: bandit, semgrep
def hash_password_md5(password):
    """MD5 for password hashing."""
    return hashlib.md5(password.encode(), usedforsecurity=False).hexdigest()


# VULN: category=weak_crypto, id=crypto_002, severity=medium
# Expected scanner: bandit, semgrep
def hash_data_sha1(data):
    """SHA1 for security-sensitive hashing."""
    return hashlib.sha1(data.encode()).hexdigest()


# VULN: category=weak_crypto, id=crypto_003, severity=high
# Expected scanner: bandit, semgrep
def generate_token(length=32):
    """Insecure random number generation with random module instead of secrets."""
    chars = string.ascii_letters + string.digits
    return "".join(random.choice(chars) for _ in range(length))


# VULN: category=weak_crypto, id=crypto_004, severity=medium
# Expected scanner: bandit, semgrep
def generate_session_id():
    """Using random.randint for security-sensitive value."""
    return str(random.randint(100000, 999999))
