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
    """String concatenation in SQL query."""
    conn = get_connection()
    query = "SELECT * FROM users WHERE id = " + user_id
    return conn.execute(query).fetchall()


# VULN: category=sql_injection, id=sqli_002, severity=high
# Expected scanner: bandit, semgrep
def get_user_by_name(name):
    """f-string in SQL query."""
    conn = get_connection()
    query = f"SELECT * FROM users WHERE name = '{name}'"
    return conn.execute(query).fetchall()


# VULN: category=sql_injection, id=sqli_003, severity=high
# Expected scanner: bandit, semgrep
def get_user_by_email(email):
    """.format() in SQL query."""
    conn = get_connection()
    query = "SELECT * FROM users WHERE email = '{}'".format(email)
    return conn.execute(query).fetchall()


# VULN: category=sql_injection, id=sqli_004, severity=high
# Expected scanner: bandit, semgrep
def search_users(search_term):
    """Variable assignment then execute (harder to detect)."""
    conn = get_connection()
    where_clause = "name LIKE '%" + search_term + "%'"
    query = "SELECT * FROM users WHERE " + where_clause
    return conn.execute(query).fetchall()


# VULN: category=sql_injection, id=sqli_005, severity=high
# Expected scanner: semgrep
def delete_user(request_data):
    """Multi-step taint: user input -> variable -> another variable -> query."""
    conn = get_connection()
    user_input = request_data.get("user_id")
    sanitized = user_input.strip()
    uid = sanitized
    query = "DELETE FROM users WHERE id = " + uid
    return conn.execute(query)
