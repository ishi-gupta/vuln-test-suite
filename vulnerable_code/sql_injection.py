"""
Intentionally vulnerable Python code for testing scanner detection.
Category: SQL Injection (CWE-89)
Each function contains a different SQL injection pattern.
"""


def sql_injection_string_concat(user_input: str) -> str:
    """Basic string concatenation SQL injection."""
    query = "SELECT * FROM users WHERE id=" + user_input
    return query


def sql_injection_format_string(username: str) -> str:
    """Format string SQL injection."""
    query = "SELECT * FROM users WHERE username='%s'" % username
    return query


def sql_injection_fstring(table_name: str, user_id: str) -> str:
    """f-string SQL injection."""
    query = f"SELECT * FROM {table_name} WHERE id={user_id}"
    return query


def sql_injection_join(columns: list, table: str) -> str:
    """SQL injection via join in column names."""
    cols = ", ".join(columns)
    query = f"SELECT {cols} FROM {table}"
    return query


def sql_injection_execute(cursor, user_input: str):
    """Direct execute with string formatting."""
    cursor.execute("SELECT * FROM users WHERE name = '%s'" % user_input)
