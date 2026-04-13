"""
HARD XSS test cases for vulnerability scanner.
Tests edge cases that regex-based detection CANNOT catch.

Categories:
1. Direct injection (baseline)
2. Indirect flow (variable reassignment, function calls)
3. Sanitized inputs (should NOT flag)
4. Framework-specific sinks (Flask, Django)
5. Tricky patterns (multi-line, nested, conditional)
"""

from markupsafe import Markup, escape
import html


# ============================================================
# CATEGORY 1: Direct injection (baseline — regex CAN catch these)
# ============================================================

def xss_direct_concat(user_input: str) -> str:
    """Direct string concatenation."""
    return "<h1>" + user_input + "</h1>"


def xss_fstring(user_input: str) -> str:
    """F-string injection."""
    return f"<script>var name = '{user_input}';</script>"


def xss_format_percent(user_input: str) -> str:
    """Percent formatting."""
    return "<div>Hello, %s!</div>" % user_input


def xss_format_dot(user_input: str) -> str:
    """.format() injection."""
    return "<span class='name'>{}</span>".format(user_input)


# ============================================================
# CATEGORY 2: Indirect flow (regex CANNOT catch these)
# ============================================================

def xss_variable_reassignment(user_input: str) -> str:
    """Input flows through a variable before reaching HTML."""
    name = user_input
    greeting = "Hello, " + name
    return "<p>" + greeting + "</p>"


def xss_through_function_call(user_input: str) -> str:
    """Input flows through a helper function."""
    processed = process_name(user_input)
    return f"<div>{processed}</div>"


def process_name(name: str) -> str:
    """Helper that passes input through unchanged."""
    return name.strip()


def xss_through_list(user_input: str) -> str:
    """Input stored in a list before reaching HTML."""
    items = [user_input]
    return "<ul><li>" + items[0] + "</li></ul>"


def xss_through_dict(user_input: str) -> str:
    """Input stored in a dict before reaching HTML."""
    data = {"name": user_input}
    return f"<span>{data['name']}</span>"


def xss_conditional_flow(user_input: str, flag: bool) -> str:
    """Input takes different paths but always reaches HTML."""
    if flag:
        output = user_input.upper()
    else:
        output = user_input.lower()
    return "<div>" + output + "</div>"


def xss_loop_accumulation(items: list) -> str:
    """Input accumulated in a loop."""
    html_parts = []
    for item in items:
        html_parts.append(f"<li>{item}</li>")
    return "<ul>" + "".join(html_parts) + "</ul>"


# ============================================================
# CATEGORY 3: Sanitized inputs (should NOT be flagged)
# ============================================================

def safe_html_escape(user_input: str) -> str:
    """Properly escaped with html.escape — NOT vulnerable."""
    safe = html.escape(user_input)
    return f"<div>{safe}</div>"


def safe_markupsafe_escape(user_input: str) -> str:
    """Properly escaped with markupsafe.escape — NOT vulnerable."""
    safe = escape(user_input)
    return Markup("<p>%s</p>") % safe


def safe_int_cast(user_input: str) -> str:
    """Cast to int prevents XSS — NOT vulnerable."""
    user_id = int(user_input)
    return f"<span>User #{user_id}</span>"


def safe_whitelist(user_input: str) -> str:
    """Whitelist validation — NOT vulnerable."""
    allowed = {"admin", "user", "guest"}
    role = user_input if user_input in allowed else "guest"
    return f"<div class='{role}'>Content</div>"


# ============================================================
# CATEGORY 4: Framework-specific sinks
# ============================================================

def xss_flask_make_response(user_input: str):
    """Flask make_response with user input in HTML."""
    from flask import make_response
    resp = make_response(f"<h1>{user_input}</h1>")
    return resp


def xss_flask_render_template_string(user_input: str):
    """Flask render_template_string — SSTI + XSS."""
    from flask import render_template_string
    return render_template_string("<div>%s</div>" % user_input)


def xss_response_write(response, user_input: str):
    """Direct response.write with HTML."""
    response.write("<p>" + user_input + "</p>")


def xss_markup_unsafe(user_input: str) -> str:
    """markupsafe.Markup on raw user input — bypasses escaping."""
    return Markup(f"<b>{user_input}</b>")


# ============================================================
# CATEGORY 5: Tricky patterns
# ============================================================

def xss_multiline_build(user_input: str) -> str:
    """HTML built across multiple lines."""
    html_str = "<div>"
    html_str += "<h2>Profile</h2>"
    html_str += "<p>Name: " + user_input + "</p>"
    html_str += "</div>"
    return html_str


def xss_join_injection(user_input: str) -> str:
    """Input injected via join."""
    parts = ["<td>", user_input, "</td>"]
    return "".join(parts)


def xss_nested_fstring(user_input: str, title: str) -> str:
    """Multiple user inputs in nested f-string."""
    return f"<div><h1>{title}</h1><p>{user_input}</p></div>"


def xss_bytes_decode(user_bytes: bytes) -> str:
    """Input comes as bytes, decoded then injected."""
    text = user_bytes.decode("utf-8")
    return f"<pre>{text}</pre>"


def xss_return_tuple(user_input: str):
    """XSS in a tuple return (common in Flask)."""
    return f"<h1>Error: {user_input}</h1>", 400
