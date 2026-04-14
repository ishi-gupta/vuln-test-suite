"""Command Injection vulnerabilities (CWE-78).

Intentionally vulnerable code for scanner validation.
Each function demonstrates a different command injection pattern.
"""

import ast
import operator
import os
import subprocess


# VULN: category=command_injection, id=cmdi_001, severity=critical
# Expected scanner: bandit, semgrep
def ping_host(hostname):
    """os.system() with user input."""
    os.system("ping -c 1 " + hostname)


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


# FIX: category=command_injection, id=cmdi_004, severity=critical
# Fixed: replaced eval() with safe AST-based expression evaluator (CWE-95)
_SAFE_OPERATORS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.Pow: operator.pow,
    ast.Mod: operator.mod,
    ast.FloorDiv: operator.floordiv,
    ast.USub: operator.neg,
    ast.UAdd: operator.pos,
}


def _safe_eval_node(node):
    """Recursively evaluate an AST node using only safe arithmetic operations."""
    if isinstance(node, ast.Expression):
        return _safe_eval_node(node.body)
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return node.value
    if isinstance(node, ast.BinOp):
        op_func = _SAFE_OPERATORS.get(type(node.op))
        if op_func is None:
            raise ValueError(f"Unsupported operator: {type(node.op).__name__}")
        return op_func(_safe_eval_node(node.left), _safe_eval_node(node.right))
    if isinstance(node, ast.UnaryOp):
        op_func = _SAFE_OPERATORS.get(type(node.op))
        if op_func is None:
            raise ValueError(f"Unsupported operator: {type(node.op).__name__}")
        return op_func(_safe_eval_node(node.operand))
    raise ValueError(f"Unsupported expression element: {type(node).__name__}")


def calculate(expression):
    """Safely evaluate a mathematical expression without using eval()."""
    tree = ast.parse(expression, mode="eval")
    return _safe_eval_node(tree)


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
