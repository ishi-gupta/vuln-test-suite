"""
Intentionally vulnerable Python code for testing scanner detection.
Category: Command Injection (CWE-78)
"""

import os
import subprocess


def command_injection_os_system(user_input: str):
    """Command injection via os.system."""
    os.system("ping " + user_input)


def command_injection_subprocess_shell(user_input: str):
    """Command injection via subprocess with shell=True."""
    subprocess.call("ls " + user_input, shell=True)


def command_injection_popen(user_input: str):
    """Command injection via subprocess.Popen with shell=True."""
    proc = subprocess.Popen(user_input, shell=True, stdout=subprocess.PIPE)
    return proc.communicate()


def command_injection_os_popen(filename: str):
    """Command injection via os.popen."""
    result = os.popen("cat " + filename)
    return result.read()


def command_injection_eval(user_input: str):
    """Code injection via eval()."""
    result = eval(user_input)
    return result
