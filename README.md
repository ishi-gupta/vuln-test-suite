# Adversarial Vulnerability Test Suite

This repo is part of a 3-repo **event-driven vulnerability remediation system**. It contains intentionally vulnerable code used to measure how well the scanner detects real vulnerabilities.

## How This Repo Fits In

| Repo | Role |
|------|------|
| [ishi-gupta/superset](https://github.com/ishi-gupta/superset) | **Target** — gets scanned, issues + fix PRs land here |
| [ishi-gupta/vuln-remediation-system](https://github.com/ishi-gupta/vuln-remediation-system) | **Brain** — scanner, issue creator, orchestrator, dashboard |
| **ishi-gupta/vuln-test-suite** (this repo) | **Red Team** — plants known vulnerabilities to test the scanner |

## Purpose

The scanner in `vuln-remediation-system` runs Bandit, Semgrep, pip-audit, and Gitleaks against a target repo. But how do we know it actually catches things? This test suite answers that question by:

1. Planting **known vulnerabilities** in test code (SQL injection, XSS, hardcoded secrets, etc.)
2. Running the scanner against this repo
3. Comparing results to a **ground truth** of what should be detected
4. Computing a **detection rate** per vulnerability category (e.g., "88% of SQL injections detected")
5. Feeding those results into the observability dashboard

## Planned Vulnerability Categories

| Category | CWE | CS155 Topic | Example |
|----------|-----|-------------|---------|
| SQL Injection | CWE-89 | Injection attacks | `query = "SELECT * FROM users WHERE id=" + user_input` |
| XSS | CWE-79 | Cross-site scripting | `return "<h1>" + user_input + "</h1>"` |
| Command Injection | CWE-78 | OS command injection | `os.system("ping " + user_input)` |
| Path Traversal | CWE-22 | Directory traversal | `open("/data/" + user_input)` |
| Hardcoded Secrets | CWE-798 | Credential management | `API_KEY = "sk-abc123..."` |
| Weak Cryptography | CWE-327 | Cryptographic failures | `hashlib.md5(password)` |
| Insecure Deserialization | CWE-502 | Object injection | `pickle.loads(user_data)` |

**Status:** Categories planned, awaiting user approval before building test files.

## Repo Structure (Planned)

```
vuln-test-suite/
├── vulnerable_code/            # Intentionally vulnerable Python files
│   ├── sql_injection.py        # 3-5 SQL injection variants
│   ├── xss.py                  # 3-5 XSS variants
│   ├── command_injection.py    # 3-5 command injection variants
│   ├── path_traversal.py       # 3-5 path traversal variants
│   ├── hardcoded_secrets.py    # 3-5 hardcoded credential patterns
│   ├── weak_crypto.py          # 3-5 weak cryptography patterns
│   ├── insecure_deserialization.py  # 3-5 deserialization patterns
│   └── vulnerable_deps/
│       └── requirements.txt    # Dependencies with known CVEs
│
├── test_harness/
│   ├── expected_findings.json  # Ground truth: what SHOULD be detected
│   └── run_tests.py           # Runs scanner, compares to ground truth, outputs results
│
├── reports/                    # Generated test results
│
├── docs/
│   └── spec.md                # Detailed spec for each vulnerability
│
└── README.md                  # This file
```

## How to Run (Once Built)

```bash
# From the vuln-remediation-system repo
python -m automation.evaluate --test-suite ../vuln-test-suite

# Output: adversarial_results.json → feeds into the dashboard
```

## Full System Documentation

For the complete system architecture, tech stack, data flow, and build plan, see:
- [Architecture](https://github.com/ishi-gupta/vuln-remediation-system/blob/main/docs/ARCHITECTURE.md)
- [Build Plan](https://github.com/ishi-gupta/vuln-remediation-system/blob/main/docs/PLAN.md)
