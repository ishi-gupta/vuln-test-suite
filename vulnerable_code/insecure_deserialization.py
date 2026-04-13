"""Insecure Deserialization vulnerabilities (CWE-502).

Intentionally vulnerable code for scanner validation.
Each function demonstrates a different insecure deserialization pattern.
"""

import marshal
import pickle

import yaml


# VULN: category=insecure_deserialization, id=deser_001, severity=critical
# Expected scanner: bandit, semgrep
def load_pickle_data(user_data):
    """pickle.loads with user-controlled data."""
    return pickle.loads(user_data)


# VULN: category=insecure_deserialization, id=deser_002, severity=critical
# Expected scanner: bandit, semgrep
def load_yaml_unsafe(user_data):
    """yaml.load without safe loader."""
    return yaml.load(user_data)


# VULN: category=insecure_deserialization, id=deser_003, severity=critical
# Expected scanner: bandit, semgrep
def parse_json_insecure(json_string):
    """Using eval() instead of json.loads()."""
    return eval(json_string)


# VULN: category=insecure_deserialization, id=deser_004, severity=critical
# Expected scanner: bandit, semgrep
def load_marshal_data(user_data):
    """marshal.loads with user-controlled data."""
    return marshal.loads(user_data)
