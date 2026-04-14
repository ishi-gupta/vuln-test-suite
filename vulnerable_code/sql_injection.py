"""SQL Injection vulnerabilities (CWE-89).

Intentionally vulnerable code for scanner validation.
Each function demonstrates a different SQL injection pattern.
"""

import sqlite3


def get_connection():
    """Helper to get a database connection."""
    return sqlite3.connect(":memory:")


# VULN: category=sql_injection, id=sqli_001, severity=high
# Expected scanner: bandit, semgrep
def get_user_by_id(user_id):
    """Parameterized query to prevent SQL injection."""
    conn = get_connection()
    query = "SELECT * FROM users WHERE id = ?"
    return conn.execute(query, (user_id,)).fetchall()


# VULN: category=sql_injection, id=sqli_002, severity=high
# Expected scanner: bandit, semgrep
def get_user_by_name(name):
    """Parameterized query to prevent SQL injection."""
    conn = get_connection()
    query = "SELECT * FROM users WHERE name = ?"
    return conn.execute(query, (name,)).fetchall()


# VULN: category=sql_injection, id=sqli_003, severity=high
# Expected scanner: bandit, semgrep
def get_user_by_email(email):
    """Parameterized query to prevent SQL injection."""
    conn = get_connection()
    query = "SELECT * FROM users WHERE email = ?"
    return conn.execute(query, (email,)).fetchall()


# VULN: category=sql_injection, id=sqli_004, severity=high
# Expected scanner: bandit, semgrep
def search_users(search_term):
    """Parameterized query to prevent SQL injection."""
    conn = get_connection()
    query = "SELECT * FROM users WHERE name LIKE ?"
    return conn.execute(query, ("%" + search_term + "%",)).fetchall()


# VULN: category=sql_injection, id=sqli_005, severity=high
# Expected scanner: semgrep
def delete_user(request_data):
    """Parameterized query to prevent SQL injection."""
    conn = get_connection()
    user_input = request_data.get("user_id")
    sanitized = user_input.strip()
    query = "DELETE FROM users WHERE id = ?"
    return conn.execute(query, (sanitized,))
