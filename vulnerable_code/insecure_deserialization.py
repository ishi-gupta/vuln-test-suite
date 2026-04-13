"""
Intentionally vulnerable Python code for testing scanner detection.
Category: Insecure Deserialization (CWE-502)
"""

import pickle
import marshal
import yaml


def insecure_pickle_loads(user_data: bytes):
    """Deserializing untrusted data with pickle."""
    return pickle.loads(user_data)


def insecure_pickle_load(file_path: str):
    """Loading pickle from a file (potentially untrusted)."""
    with open(file_path, "rb") as f:
        return pickle.load(f)


def insecure_yaml_load(yaml_string: str):
    """Using yaml.load without SafeLoader (allows arbitrary code execution)."""
    return yaml.load(yaml_string)


def insecure_marshal_loads(data: bytes):
    """Deserializing untrusted data with marshal."""
    return marshal.loads(data)


def insecure_exec(code_string: str):
    """Executing arbitrary code from user input."""
    exec(code_string)
