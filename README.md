# Adversarial Vulnerability Test Suite

The **Red Team** repo in a 3-repo vulnerability remediation system. This repo simulates real engineers accidentally introducing security bugs, then measures whether the scanner catches them.

## How This Repo Fits In

| Repo | Role |
|------|------|
| [ishi-gupta/superset](https://github.com/ishi-gupta/superset) | **Target** — gets scanned, issues + fix PRs land here |
| [ishi-gupta/vuln-remediation-system](https://github.com/ishi-gupta/vuln-remediation-system) | **Brain** — scanner, issue creator, orchestrator, dashboard |
| **ishi-gupta/vuln-test-suite** (this repo) | **Red Team** — AI-generated adversarial bugs to stress-test the scanner |

## How It Works

The adversarial suite uses Devin AI sessions to simulate careless engineers introducing realistic security bugs:

1. **God Agent (parent Devin session)** — Plans a batch of realistic bugs across vulnerability categories (SQL injection, XSS, command injection, etc.). Decides which types of mistakes to simulate and how they should look like natural code a real developer might write.

2. **Baby Devins (child sessions)** — Each child session acts as a "careless engineer." It writes a small, realistic piece of buggy code — complete with comments, error handling, and logging — that contains a specific vulnerability. It creates a PR on the target repo explaining what the bug is and why a developer might write it that way.

3. **Scanner picks up the new PRs** → creates issues on the dashboard → the remediation orchestrator sends more Devin agents to fix them → the cycle continues.

This creates a continuous adversarial loop:
```
Devin plants bugs → Scanner detects them → Dashboard shows issues → Devin fixes them → Repeat
```

## Vulnerability Categories

| Category | CWE | Variants | Example |
|----------|-----|----------|---------|
| SQL Injection | CWE-89 | 5 | `query = "SELECT * FROM users WHERE id=" + user_input` |
| XSS | CWE-79 | 4 | `return "<h1>" + user_input + "</h1>"` |
| Command Injection | CWE-78 | 5 | `os.system("ping " + user_input)` |
| Path Traversal | CWE-22 | 4 | `open("/data/" + user_input)` |
| Hardcoded Secrets | CWE-798 | 5 | `API_KEY = "sk-abc123..."` |
| Weak Cryptography | CWE-327 | 4 | `hashlib.md5(password)` |
| Insecure Deserialization | CWE-502 | 4 | `pickle.loads(user_data)` |
| Vulnerable Dependencies | — | 5 | `flask==2.2.0` (known CVEs) |

**Total: 36 planted vulnerabilities**

## Repo Structure

```
vuln-test-suite/
├── vulnerable_code/                 # Intentionally vulnerable Python files
│   ├── sql_injection.py             # 5 SQL injection variants
│   ├── xss.py                       # 4 XSS variants
│   ├── command_injection.py         # 5 command injection variants
│   ├── path_traversal.py            # 4 path traversal variants
│   ├── hardcoded_secrets.py         # 5 hardcoded credential patterns
│   ├── weak_crypto.py               # 4 weak cryptography patterns
│   ├── insecure_deserialization.py  # 4 deserialization patterns
│   └── vulnerable_deps/
│       └── requirements.txt         # Dependencies with known CVEs
│
├── test_harness/
│   ├── expected_findings.json       # Ground truth: what SHOULD be detected
│   ├── run_tests.py                 # Runs scanner + evaluates results end-to-end
│   └── evaluate.py                  # Standalone evaluator (compares scan results to ground truth)
│
├── reports/                         # Generated adversarial results
│
└── README.md                        # This file
```

## How to Run

### Scan this repo and evaluate detection rate
```bash
# 1. Run the scanner against this repo
python -m automation.scanner --target /path/to/vuln-test-suite --output adversarial_scan.json

# 2. Evaluate results against ground truth
python test_harness/evaluate.py \
  --scan-results adversarial_scan.json \
  --expected test_harness/expected_findings.json \
  --output data/adversarial_results.json
```

### Run the full test harness (scan + evaluate in one step)
```bash
python test_harness/run_tests.py \
  --scanner-repo ../vuln-remediation-system \
  --output reports/adversarial_results.json
```

### Detection Rate (Latest Run)

| Category | Detected | Rate | Status |
|----------|----------|------|--------|
| Command Injection | 5/5 | 100% | PASS |
| Hardcoded Secrets | 5/5 | 100% | PASS |
| Insecure Deserialization | 4/4 | 100% | PASS |
| SQL Injection | 5/5 | 100% | PASS |
| Vulnerable Dependencies | 5/5 | 100% | PASS |
| Weak Crypto | 2/4 | 50% | WARN |
| Path Traversal | 0/4 | 0% | FAIL |
| XSS | 0/4 | 0% | FAIL |
| **Overall** | **26/36** | **72%** | |

## Full System Documentation

- [Architecture](https://github.com/ishi-gupta/vuln-remediation-system/blob/main/docs/ARCHITECTURE.md) — full system design, data flow, tech stack
- [Build Plan](https://github.com/ishi-gupta/vuln-remediation-system/blob/main/docs/PLAN.md) — what's built, what's pending
- [Test Report](https://github.com/ishi-gupta/vuln-remediation-system/blob/main/docs/TEST_REPORT.md) — comprehensive test results
