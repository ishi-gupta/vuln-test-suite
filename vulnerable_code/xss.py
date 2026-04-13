"""Cross-Site Scripting (XSS) vulnerabilities (CWE-79).

Intentionally vulnerable code for scanner validation.
Each function demonstrates a different XSS pattern.
"""


# VULN: category=xss, id=xss_001, severity=high
# Expected scanner: semgrep
def render_greeting(user_input):
    """Direct user input in HTML response."""
    return "<h1>Hello, " + user_input + "</h1>"


# VULN: category=xss, id=xss_002, severity=high
# Expected scanner: semgrep
def render_profile(username):
    """Template string with unescaped user input."""
    html = f"<div class='profile'><span>{username}</span></div>"
    return html


# VULN: category=xss, id=xss_003, severity=high
# Expected scanner: semgrep
def reflect_search(query):
    """Reflected XSS pattern - search query echoed back."""
    return "<p>Search results for: {}</p><div id='results'></div>".format(query)


# VULN: category=xss, id=xss_004, severity=high
# Expected scanner: semgrep
def render_script(callback_name):
    """User input in script tag construction."""
    return "<script>var callback = " + callback_name + "; callback();</script>"
