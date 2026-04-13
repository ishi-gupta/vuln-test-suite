#!/usr/bin/env python3
"""Adversarial test runner for vulnerability scanner validation.

Runs the scanner from vuln-remediation-system against the vulnerable code
in this repo, then compares results to the ground truth in expected_findings.json.

Usage:
    python test_harness/run_tests.py --scanner-repo ../vuln-remediation-system --output reports/adversarial_results.json
    python test_harness/run_tests.py --help
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone


def parse_args():
    parser = argparse.ArgumentParser(
        description="Run vulnerability scanner against adversarial test suite and evaluate results."
    )
    parser.add_argument(
        "--scanner-repo",
        required=True,
        help="Path to the vuln-remediation-system repo (must be installed or installable).",
    )
    parser.add_argument(
        "--output",
        default="reports/adversarial_results.json",
        help="Path to write the adversarial results JSON (default: reports/adversarial_results.json).",
    )
    parser.add_argument(
        "--target",
        default=None,
        help="Path to the vuln-test-suite repo root (default: auto-detect from script location).",
    )
    parser.add_argument(
        "--scanners",
        nargs="+",
        default=["bandit", "semgrep", "pip-audit", "gitleaks"],
        help="Which scanners to run (default: bandit semgrep pip-audit gitleaks).",
    )
    return parser.parse_args()


def run_scanner(scanner_repo, target_dir, scanners):
    """Run the vulnerability scanner and return the scan results."""
    scan_output = tempfile.mktemp(suffix=".json")

    cmd = [
        sys.executable,
        "-m",
        "automation.scanner",
        "--target",
        target_dir,
        "--output",
        scan_output,
        "--scanners",
    ] + scanners

    print(f"Running scanner: {' '.join(cmd)}")
    print(f"Scanner repo: {scanner_repo}")
    print(f"Target: {target_dir}")

    try:
        result = subprocess.run(
            cmd,
            cwd=scanner_repo,
            capture_output=True,
            text=True,
            timeout=300,
        )
        print(f"Scanner stdout:\n{result.stdout}")
        if result.stderr:
            print(f"Scanner stderr:\n{result.stderr}")

        if result.returncode != 0:
            print(f"Scanner exited with code {result.returncode}")
            # Try to read partial results anyway
            if not os.path.exists(scan_output):
                return None

        with open(scan_output) as f:
            return json.load(f)

    except subprocess.TimeoutExpired:
        print("ERROR: Scanner timed out after 300 seconds")
        return None
    except FileNotFoundError:
        print("ERROR: Could not find scanner module. Is vuln-remediation-system installed?")
        return None
    finally:
        if os.path.exists(scan_output):
            os.unlink(scan_output)


def evaluate_results(scan_results, expected_path):
    """Compare scan results to expected findings and compute metrics."""
    # Import the evaluate module
    test_harness_dir = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, test_harness_dir)
    from evaluate import load_expected, match_findings, compute_metrics

    expected = load_expected(expected_path)
    findings = scan_results.get("findings", [])
    matched, unmatched_expected, unmatched_findings = match_findings(findings, expected)
    return compute_metrics(expected, matched, unmatched_expected, unmatched_findings)


def main():
    args = parse_args()

    # Determine target directory
    if args.target:
        target_dir = os.path.abspath(args.target)
    else:
        # Auto-detect: script is in test_harness/, so go up one level
        target_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    scanner_repo = os.path.abspath(args.scanner_repo)
    expected_path = os.path.join(target_dir, "test_harness", "expected_findings.json")

    # Validate paths
    if not os.path.isdir(scanner_repo):
        print(f"ERROR: Scanner repo not found: {scanner_repo}")
        sys.exit(1)

    if not os.path.isfile(expected_path):
        print(f"ERROR: Expected findings not found: {expected_path}")
        sys.exit(1)

    print("=" * 60)
    print("Adversarial Vulnerability Scanner Test Runner")
    print("=" * 60)
    print(f"Target repo:    {target_dir}")
    print(f"Scanner repo:   {scanner_repo}")
    print(f"Expected file:  {expected_path}")
    print(f"Scanners:       {', '.join(args.scanners)}")
    print("=" * 60)

    # Step 1: Run the scanner
    print("\n[Step 1] Running vulnerability scanner...")
    scan_results = run_scanner(scanner_repo, target_dir, args.scanners)

    if scan_results is None:
        print("ERROR: Scanner failed to produce results.")
        sys.exit(1)

    print(f"\nScanner found {scan_results.get('scan_run', {}).get('total_findings', 0)} findings.")

    # Step 2: Evaluate results
    print("\n[Step 2] Evaluating results against ground truth...")
    results = evaluate_results(scan_results, expected_path)

    # Step 3: Write output
    output_path = args.output
    os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".", exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\n[Step 3] Results written to: {output_path}")

    # Print summary
    print("\n" + "=" * 60)
    print("RESULTS SUMMARY")
    print("=" * 60)
    print(f"Overall detection rate: {results['overall_detection_rate']:.1%}")
    print(f"Total planted:  {results['total_planted']}")
    print(f"Total detected: {results['total_detected']}")
    print(f"Total missed:   {results['total_missed']}")

    print("\nBy category:")
    for cat in results["categories"]:
        print(f"  {cat['name']:30s} {cat['detected']}/{cat['total']} ({cat['rate']:.0%})")

    print("\nBy scanner:")
    for sc in results["by_scanner"]:
        print(f"  {sc['scanner']:15s} {sc['detected']}/{sc['total_applicable']} ({sc['rate']:.0%})")

    if results["total_missed"] > 0:
        print("\nMissed vulnerabilities:")
        for cat in results["categories"]:
            for m in cat.get("missed_details", []):
                print(f"  - [{cat['name']}] {m['id']}: {m['description']} ({m['file']}:{m['line']})")


if __name__ == "__main__":
    main()
