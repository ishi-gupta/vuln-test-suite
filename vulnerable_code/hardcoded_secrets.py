"""Hardcoded Secrets vulnerabilities (CWE-798).

Intentionally vulnerable code for scanner validation.
Each variable demonstrates a different hardcoded credential pattern.
"""

# VULN: category=hardcoded_secrets, id=secret_001, severity=critical
# Expected scanner: gitleaks, semgrep
API_KEY = "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234"

# VULN: category=hardcoded_secrets, id=secret_002, severity=critical
# Expected scanner: gitleaks, semgrep
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# VULN: category=hardcoded_secrets, id=secret_003, severity=critical
# Expected scanner: gitleaks, semgrep
DB_PASSWORD = "SuperSecret123!"
DATABASE_URL = "postgres://admin:SuperSecret123!@prod-db.example.com:5432/myapp"

# VULN: category=hardcoded_secrets, id=secret_004, severity=critical
# Expected scanner: gitleaks, semgrep
GITHUB_TOKEN = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef012345"

# VULN: category=hardcoded_secrets, id=secret_005, severity=high
# Expected scanner: gitleaks, semgrep
PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGcY5unA67hiBRmR+oP6EXAMPLEKEY\n-----END RSA PRIVATE KEY-----"  # noqa: E501


def connect_to_db():
    """Uses hardcoded credentials in connection string."""
    import psycopg2
    return psycopg2.connect(DATABASE_URL)


def call_api():
    """Uses hardcoded API key in request header."""
    import requests
    headers = {"Authorization": f"Bearer {API_KEY}"}
    return requests.get("https://api.example.com/data", headers=headers)
