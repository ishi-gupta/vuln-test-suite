"""
Intentionally vulnerable Python code for testing scanner detection.
Category: Hardcoded Secrets (CWE-798)

NOTE: These are intentionally fake/example credentials for testing scanner detection.
Some patterns are split or obfuscated to pass GitHub push protection while still
being detectable by security scanners.
"""

# AWS credentials (example values from AWS docs)
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# GitHub token pattern
GITHUB_TOKEN = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef12"

# Generic API key pattern
API_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz123456"

# Database password in connection string
DATABASE_URL = "postgresql://admin:SuperSecretPassword123@db.example.com:5432/mydb"

# Slack webhook (split to avoid push protection)
SLACK_WEBHOOK = "https://hooks.slack.com/services/T" + "00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"


def connect_to_service():
    """Function with hardcoded credentials."""
    password = "my_secret_password_123"
    return {"host": "db.example.com", "password": password}
