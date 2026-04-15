"""Command Injection vulnerabilities (CWE-78).

Intentionally vulnerable code for scanner validation.
Each function demonstrates a different command injection pattern.
"""

import os
import shlex
import subprocess


# VULN: category=command_injection, id=cmdi_001, severity=critical
# Expected scanner: bandit, semgrep
def ping_host(hostname):
    """os.system() with user input."""
    os.system("ping -c 1 " + hostname)


# VULN: category=command_injection, id=cmdi_002, severity=critical
# Expected scanner: bandit, semgrep
def list_directory(path):
    """List directory contents safely without shell=True."""
    subprocess.call(["ls", "-la", path])


# VULN: category=command_injection, id=cmdi_003, severity=critical
# Expected scanner: bandit, semgrep
def run_user_code(user_code):
    """exec() with user input."""
    exec(user_code)


# VULN: category=command_injection, id=cmdi_004, severity=critical
# Expected scanner: bandit, semgrep
def calculate(expression):
    """eval() with user input."""
    return eval(expression)


# VULN: category=command_injection, id=cmdi_005, severity=critical
# Expected scanner: bandit, semgrep
def process_file(filename):
    """Count lines in a file safely without shell=True."""
    cat_proc = subprocess.Popen(
        ["cat", filename],
        stdout=subprocess.PIPE
    )
    wc_proc = subprocess.Popen(
        ["wc", "-l"],
        stdin=cat_proc.stdout,
        stdout=subprocess.PIPE
    )
    cat_proc.stdout.close()
    return wc_proc.communicate()[0]
