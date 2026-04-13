"""Path Traversal vulnerabilities (CWE-22).

Intentionally vulnerable code for scanner validation.
Each function demonstrates a different path traversal pattern.
"""

import os


# VULN: category=path_traversal, id=path_001, severity=high
# Expected scanner: bandit, semgrep
def read_file(filename):
    """open() with user-controlled path."""
    with open("/var/data/" + filename, "r") as f:
        return f.read()


# VULN: category=path_traversal, id=path_002, severity=high
# Expected scanner: bandit, semgrep
def read_with_join(user_path):
    """os.path.join() with user input (doesn't prevent ../)."""
    file_path = os.path.join("/var/data", user_path)
    with open(file_path, "r") as f:
        return f.read()


# VULN: category=path_traversal, id=path_003, severity=high
# Expected scanner: bandit, semgrep
def write_file(filename, content):
    """File write with unvalidated filename."""
    path = "/uploads/" + filename
    with open(path, "w") as f:
        f.write(content)


# VULN: category=path_traversal, id=path_004, severity=medium
# Expected scanner: bandit, semgrep
def list_directory(user_dir):
    """Directory listing with user input."""
    full_path = os.path.join("/var/data", user_dir)
    return os.listdir(full_path)
