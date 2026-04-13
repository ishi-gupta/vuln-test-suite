"""
Intentionally vulnerable Python code for testing scanner detection.
Category: Weak Cryptography (CWE-327)
"""

import hashlib
import tempfile


def weak_hash_md5(password: str) -> str:
    """Using MD5 for password hashing (weak)."""
    return hashlib.md5(password.encode()).hexdigest()


def weak_hash_sha1(data: str) -> str:
    """Using SHA1 (known to be weak for security purposes)."""
    return hashlib.sha1(data.encode()).hexdigest()


def weak_random():
    """Using random module for security-sensitive operations (not cryptographically secure)."""
    import random
    token = random.randint(100000, 999999)
    return str(token)


def insecure_temp_file():
    """Using mktemp (insecure, race condition)."""
    return tempfile.mktemp()


def weak_cipher():
    """Using DES (weak cipher)."""
    try:
        from Crypto.Cipher import DES
        key = b"12345678"
        cipher = DES.new(key, DES.MODE_ECB)
        return cipher.encrypt(b"testdata")
    except ImportError:
        pass
