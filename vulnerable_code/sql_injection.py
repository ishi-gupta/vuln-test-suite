"""SQL Injection vulnerabilities (CWE-89).

Intentionally vulnerable code for scanner validation.
Each function demonstrates a different SQL injection pattern.
"""

import sqlite3


def get_connection():
    """Helper to get a database connection."""
    return sqlite3.connect(":memory:")


# FIXED: category=sql_injection, id=sqli_001, severity=high
# Previously flagged by: bandit, semgrep
def get_user_by_id(user_id):
    """Use parameterized query to prevent SQL injection."""
    conn = get_connection()
    query = "SELECT * FROM users WHERE id = ?"
    return conn.execute(query, (user_id,)).fetchall()


# FIXED: category=sql_injection, id=sqli_002, severity=high
# Previously flagged by: bandit, semgrep
def get_user_by_name(name):
    """Use parameterized query to prevent SQL injection."""
    conn = get_connection()
    query = "SELECT * FROM users WHERE name = ?"
    return conn.execute(query, (name,)).fetchall()


# FIXED: category=sql_injection, id=sqli_003, severity=high
# Previously flagged by: bandit, semgrep
def get_user_by_email(email):
    """Use parameterized query to prevent SQL injection."""
    conn = get_connection()
    query = "SELECT * FROM users WHERE email = ?"
    return conn.execute(query, (email,)).fetchall()


# FIXED: category=sql_injection, id=sqli_004, severity=high
# Previously flagged by: bandit, semgrep
def search_users(search_term):
    """Use parameterized query to prevent SQL injection."""
    conn = get_connection()
    query = "SELECT * FROM users WHERE name LIKE ?"
    return conn.execute(query, ("%" + search_term + "%",)).fetchall()


# FIXED: category=sql_injection, id=sqli_005, severity=high
# Previously flagged by: semgrep
def delete_user(request_data):
    """Use parameterized query to prevent SQL injection."""
    conn = get_connection()
    user_input = request_data.get("user_id")
    sanitized = user_input.strip()
    query = "DELETE FROM users WHERE id = ?"
    return conn.execute(query, (sanitized,))
