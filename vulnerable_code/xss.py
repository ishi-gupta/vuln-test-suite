"""
Intentionally vulnerable Python code for testing scanner detection.
Category: Cross-Site Scripting / XSS (CWE-79)
"""

from markupsafe import Markup


def xss_direct_html(user_input: str) -> str:
    """Direct HTML injection."""
    return "<h1>" + user_input + "</h1>"


def xss_format_string(user_input: str) -> str:
    """XSS via format string in HTML template."""
    template = "<div class='greeting'>Hello, %s!</div>"
    return template % user_input


def xss_fstring_html(user_input: str) -> str:
    """XSS via f-string in HTML."""
    return f"<script>var name = '{user_input}';</script>"


def xss_markup_unsafe(user_input: str) -> str:
    """XSS via markupsafe.Markup on untrusted data."""
    return Markup("<b>%s</b>") % user_input


def xss_response_write(response, user_input: str):
    """XSS via direct response writing."""
    response.write("<p>" + user_input + "</p>")
