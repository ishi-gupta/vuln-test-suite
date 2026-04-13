"""
Test harness: runs the vulnerability scanner against the adversarial test suite
and compares results to the ground truth in expected_findings.json.

Outputs a detection rate per vulnerability category.
"""

import json
import os
import sys
from pathlib import Path

# Add the vuln-remediation-system to the path
VULN_SYSTEM_DIR = os.environ.get(
    "VULN_SYSTEM_DIR",
    str(Path(__file__).parent.parent.parent / "vuln-remediation-system"),
)
sys.path.insert(0, VULN_SYSTEM_DIR)

from automation.scanner import run_bandit, run_gitleaks, run_semgrep, run_pip_audit, deduplicate


def load_expected_findings() -> dict:
    expected_path = Path(__file__).parent / "expected_findings.json"
    with open(expected_path) as f:
        return json.load(f)


def run_adversarial_tests() -> dict:
    """Run all scanners against the vulnerable_code/ directory and compare to ground truth."""
    vuln_code_dir = str(Path(__file__).parent.parent / "vulnerable_code")
    expected = load_expected_findings()

    print(f"[test_harness] Scanning {vuln_code_dir}")
    print(f"[test_harness] Running bandit...")
    bandit_findings = run_bandit(vuln_code_dir)
    print(f"[test_harness] Bandit: {len(bandit_findings)} findings")

    print(f"[test_harness] Running gitleaks...")
    gitleaks_findings = run_gitleaks(vuln_code_dir)
    print(f"[test_harness] Gitleaks: {len(gitleaks_findings)} findings")

    print(f"[test_harness] Running semgrep...")
    semgrep_findings = run_semgrep(vuln_code_dir)
    print(f"[test_harness] Semgrep: {len(semgrep_findings)} findings")

    print(f"[test_harness] Running pip-audit...")
    pip_audit_findings = run_pip_audit(vuln_code_dir)
    print(f"[test_harness] pip-audit: {len(pip_audit_findings)} findings")

    all_findings = deduplicate(bandit_findings + gitleaks_findings + semgrep_findings + pip_audit_findings)
    print(f"[test_harness] Total deduplicated findings: {len(all_findings)}")

    # Compare results per category
    results = {}
    total_expected = 0
    total_detected = 0

    for category_name, category_data in expected["categories"].items():
        expected_file = category_data["file"]
        expected_count = len(category_data["expected_findings"])
        min_expected = category_data["min_expected_detections"]

        # Find findings matching this file
        matched_findings = [
            f for f in all_findings
            if expected_file.replace("vulnerable_code/", "") in f.file_path
            or f.file_path.endswith(expected_file.split("/")[-1])
        ]

        detected_count = len(matched_findings)
        detection_rate = (detected_count / expected_count * 100) if expected_count > 0 else 0
        meets_minimum = detected_count >= min_expected

        results[category_name] = {
            "expected_total": expected_count,
            "detected": detected_count,
            "detection_rate_pct": round(detection_rate, 1),
            "min_expected": min_expected,
            "meets_minimum": meets_minimum,
            "findings": [
                {
                    "scanner": f.scanner,
                    "severity": f.severity.value,
                    "title": f.title[:100],
                    "line": f.line_number,
                }
                for f in matched_findings
            ],
        }

        total_expected += expected_count
        total_detected += detected_count

        status = "PASS" if meets_minimum else "FAIL"
        print(f"  [{status}] {category_name}: {detected_count}/{expected_count} detected "
              f"({detection_rate:.0f}%) — min required: {min_expected}")

    overall_rate = (total_detected / total_expected * 100) if total_expected > 0 else 0
    print(f"\n[test_harness] Overall: {total_detected}/{total_expected} ({overall_rate:.0f}%)")

    report = {
        "summary": {
            "total_expected": total_expected,
            "total_detected": total_detected,
            "overall_detection_rate_pct": round(overall_rate, 1),
            "categories_passing": sum(1 for r in results.values() if r["meets_minimum"]),
            "categories_total": len(results),
        },
        "categories": results,
    }

    # Write report
    reports_dir = Path(__file__).parent.parent / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    report_path = reports_dir / "adversarial_results.json"
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n[test_harness] Report written to {report_path}")
    return report


if __name__ == "__main__":
    report = run_adversarial_tests()

    # Exit with non-zero if any category fails
    if report["summary"]["categories_passing"] < report["summary"]["categories_total"]:
        failing = [
            name for name, data in report["categories"].items()
            if not data["meets_minimum"]
        ]
        print(f"\nFailing categories: {', '.join(failing)}")
        sys.exit(1)
