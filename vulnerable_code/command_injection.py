"""Command Injection vulnerabilities (CWE-78).

Intentionally vulnerable code for scanner validation.
Each function demonstrates a different command injection pattern.
"""

import os
import subprocess


# FIX: category=command_injection, id=cmdi_001, severity=critical
# Fixed: replaced os.system() with subprocess.run() using list args to prevent shell injection
def ping_host(hostname):
    """Ping a host safely without shell injection."""
    subprocess.run(["ping", "-c", "1", hostname], check=False)


# VULN: category=command_injection, id=cmdi_002, severity=critical
# Expected scanner: bandit, semgrep
def list_directory(path):
    """subprocess.call() with shell=True and user input."""
    subprocess.call("ls -la " + path, shell=True)


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
    """subprocess.Popen with shell=True and user input."""
    proc = subprocess.Popen(
        "cat " + filename + " | wc -l",
        shell=True,
        stdout=subprocess.PIPE
    )
    return proc.communicate()[0]
