"""
Intentionally vulnerable Python code for testing scanner detection.
Category: Path Traversal (CWE-22)
"""

import os


def path_traversal_open(user_input: str) -> str:
    """Path traversal via open() with user input."""
    with open("/data/" + user_input) as f:
        return f.read()


def path_traversal_os_path_join(base_dir: str, filename: str) -> str:
    """Path traversal via os.path.join (still vulnerable if filename is absolute)."""
    filepath = os.path.join(base_dir, filename)
    with open(filepath) as f:
        return f.read()


def path_traversal_send_file(user_input: str):
    """Path traversal in file serving."""
    file_path = os.path.join("/uploads", user_input)
    return open(file_path, "rb").read()


def path_traversal_makedirs(user_input: str):
    """Path traversal in directory creation."""
    os.makedirs("/tmp/user_data/" + user_input, exist_ok=True)
