#!/usr/bin/env python3
"""Evaluator for vulnerability scanner results.

Compares pre-computed scan results to the expected findings ground truth
and produces an adversarial_results.json report.

This script does NOT run the scanner itself — it takes scanner output as input.

Usage:
    python test_harness/evaluate.py \\
        --scan-results scan_results.json \\
        --expected test_harness/expected_findings.json \\
        --output data/adversarial_results.json

    python test_harness/evaluate.py --help
"""

import argparse
import json
import os
import sys
from collections import defaultdict
from datetime import datetime, timezone


def parse_args():
    parser = argparse.ArgumentParser(
        description="Evaluate vulnerability scanner results against expected findings ground truth."
    )
    parser.add_argument(
        "--scan-results",
        required=True,
        help="Path to the scanner output JSON file (scan_results.json).",
    )
    parser.add_argument(
        "--expected",
        required=True,
        help="Path to expected_findings.json ground truth.",
    )
    parser.add_argument(
        "--output",
        default="adversarial_results.json",
        help="Path to write the adversarial results JSON (default: adversarial_results.json).",
    )
    parser.add_argument(
        "--line-tolerance",
        type=int,
        default=5,
        help="Line number tolerance for matching findings (default: ±5 lines).",
    )
    return parser.parse_args()


def load_expected(expected_path):
    """Load expected findings from ground truth JSON."""
    with open(expected_path) as f:
        data = json.load(f)
    return data["vulnerabilities"]


def load_scan_results(scan_results_path):
    """Load scanner output JSON."""
    with open(scan_results_path) as f:
        return json.load(f)


def normalize_path(file_path):
    """Normalize a file path for comparison (strip leading ./ and resolve)."""
    path = file_path.strip()
    if path.startswith("./"):
        path = path[2:]
    # Remove any leading slash
    if path.startswith("/"):
        # Try to extract relative path from absolute path
        parts = path.split("/")
        # Look for vulnerable_code or test_harness in the path
        for i, part in enumerate(parts):
            if part in ("vulnerable_code", "test_harness"):
                return "/".join(parts[i:])
    return path


def _extract_package_names(description):
    """Extract likely package names from a vulnerability description.

    E.g. "Flask 2.2.0 with known CVEs" -> ["flask"]
    """
    # Common pattern: first word is the package name
    words = description.split()
    if words:
        return [words[0].lower().rstrip(",.:;")]
    return []


def match_findings(scan_findings, expected_vulns, line_tolerance=5):
    """Match scanner findings to expected vulnerabilities.

    Returns:
        matched: dict mapping expected vuln id -> list of matching scanner findings
        unmatched_expected: list of expected vulns not matched by any finding
        unmatched_findings: list of scanner findings not matching any expected vuln
    """
    matched = defaultdict(list)
    matched_finding_indices = set()

    for vuln in expected_vulns:
        vuln_file = normalize_path(vuln["file"])
        vuln_line = vuln["line"]
        vuln_id = vuln["id"]
        vuln_category = vuln.get("category", "")

        for i, finding in enumerate(scan_findings):
            finding_file = normalize_path(finding.get("file_path", ""))
            finding_line = finding.get("line_number", 0)

            # Match by file path (check if one contains the other)
            file_match = (
                vuln_file == finding_file
                or vuln_file.endswith(finding_file)
                or finding_file.endswith(vuln_file)
            )

            if not file_match:
                continue

            # Special handling for SCA/dependency findings (pip-audit)
            # These often have line_number=0 — match by package name in title instead
            if vuln_category == "vulnerable_dependencies" and finding.get("scanner") == "pip-audit":
                # Extract package name from vuln description (e.g. "Flask 2.2.0 with known CVEs")
                vuln_desc_lower = vuln.get("description", "").lower()
                finding_title_lower = finding.get("title", "").lower()
                finding_pkg = finding.get("package_name", "").lower()
                # Match if the package name appears in the vuln description or vice versa
                pkg_match = (
                    (finding_pkg and finding_pkg in vuln_desc_lower)
                    or any(
                        pkg in finding_title_lower
                        for pkg in _extract_package_names(vuln.get("description", ""))
                    )
                )
                if pkg_match:
                    matched[vuln_id].append(finding)
                    matched_finding_indices.add(i)
                continue

            # Match by line number with tolerance
            line_match = abs(vuln_line - finding_line) <= line_tolerance

            if line_match:
                matched[vuln_id].append(finding)
                matched_finding_indices.add(i)

    unmatched_expected = [v for v in expected_vulns if v["id"] not in matched]
    unmatched_findings = [f for i, f in enumerate(scan_findings) if i not in matched_finding_indices]

    return matched, unmatched_expected, unmatched_findings


def compute_metrics(expected_vulns, matched, unmatched_expected, unmatched_findings):
    """Compute detection metrics from matching results."""
    total_planted = len(expected_vulns)
    total_detected = len(matched)
    total_missed = len(unmatched_expected)

    overall_rate = total_detected / total_planted if total_planted > 0 else 0.0

    # Group by category
    categories_map = defaultdict(lambda: {
        "total": 0,
        "detected": 0,
        "missed_details": [],
        "cwe_id": "",
    })

    for vuln in expected_vulns:
        cat = vuln["category"]
        categories_map[cat]["total"] += 1
        categories_map[cat]["cwe_id"] = vuln["cwe_id"]
        if vuln["id"] in matched:
            categories_map[cat]["detected"] += 1
        else:
            categories_map[cat]["missed_details"].append({
                "id": vuln["id"],
                "description": vuln["description"],
                "file": vuln["file"],
                "line": vuln["line"],
            })

    categories = []
    for name, data in sorted(categories_map.items()):
        cat_total = data["total"]
        cat_detected = data["detected"]
        categories.append({
            "name": _format_category_name(name),
            "cwe_id": data["cwe_id"],
            "total": cat_total,
            "detected": cat_detected,
            "missed": cat_total - cat_detected,
            "rate": round(cat_detected / cat_total, 2) if cat_total > 0 else 0.0,
            "missed_details": data["missed_details"],
        })

    # Group by scanner
    scanner_stats = defaultdict(lambda: {"detected": 0, "total_applicable": 0})

    for vuln in expected_vulns:
        for scanner in vuln.get("expected_scanners", []):
            scanner_stats[scanner]["total_applicable"] += 1
            # Check if this vuln was detected by this specific scanner
            if vuln["id"] in matched:
                for finding in matched[vuln["id"]]:
                    if finding.get("scanner", "").lower() == scanner.lower():
                        scanner_stats[scanner]["detected"] += 1
                        break

    by_scanner = []
    for scanner_name in sorted(scanner_stats.keys()):
        stats = scanner_stats[scanner_name]
        by_scanner.append({
            "scanner": scanner_name,
            "detected": stats["detected"],
            "total_applicable": stats["total_applicable"],
            "rate": round(
                stats["detected"] / stats["total_applicable"], 2
            ) if stats["total_applicable"] > 0 else 0.0,
        })

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "overall_detection_rate": round(overall_rate, 2),
        "total_planted": total_planted,
        "total_detected": total_detected,
        "total_missed": total_missed,
        "false_positives": len(unmatched_findings),
        "categories": categories,
        "by_scanner": by_scanner,
    }


def _format_category_name(name):
    """Convert snake_case category to Title Case."""
    return name.replace("_", " ").title()


def main():
    args = parse_args()

    # Validate inputs
    if not os.path.isfile(args.scan_results):
        print(f"ERROR: Scan results file not found: {args.scan_results}")
        sys.exit(1)

    if not os.path.isfile(args.expected):
        print(f"ERROR: Expected findings file not found: {args.expected}")
        sys.exit(1)

    # Load data
    scan_data = load_scan_results(args.scan_results)
    expected = load_expected(args.expected)
    findings = scan_data.get("findings", [])

    print(f"Loaded {len(expected)} expected vulnerabilities")
    print(f"Loaded {len(findings)} scanner findings")

    # Match findings
    matched, unmatched_expected, unmatched_findings = match_findings(
        findings, expected, line_tolerance=args.line_tolerance
    )

    # Compute metrics
    results = compute_metrics(expected, matched, unmatched_expected, unmatched_findings)

    # Write output
    output_dir = os.path.dirname(args.output)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\nResults written to: {args.output}")

    # Print summary
    print("\n" + "=" * 60)
    print("ADVERSARIAL TEST RESULTS")
    print("=" * 60)
    print(f"Overall detection rate: {results['overall_detection_rate']:.0%}")
    print(f"Total planted:    {results['total_planted']}")
    print(f"Total detected:   {results['total_detected']}")
    print(f"Total missed:     {results['total_missed']}")
    print(f"False positives:  {results['false_positives']}")

    print("\nBy category:")
    for cat in results["categories"]:
        status = "PASS" if cat["rate"] >= 0.8 else "WARN" if cat["rate"] >= 0.5 else "FAIL"
        print(f"  [{status}] {cat['name']:30s} {cat['detected']}/{cat['total']} ({cat['rate']:.0%})")

    print("\nBy scanner:")
    for sc in results["by_scanner"]:
        print(f"  {sc['scanner']:15s} {sc['detected']}/{sc['total_applicable']} ({sc['rate']:.0%})")

    if results["total_missed"] > 0:
        print("\nMissed vulnerabilities:")
        for cat in results["categories"]:
            for m in cat.get("missed_details", []):
                print(f"  - [{cat['name']}] {m['id']}: {m['description']}")
                print(f"    File: {m['file']}:{m['line']}")

    return 0 if results["overall_detection_rate"] > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
