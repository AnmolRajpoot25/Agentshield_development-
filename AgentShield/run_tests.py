#!/usr/bin/env python3
"""
AgentShield — Automated Test Suite Runner & Regression Harness
Lexsi AI Safety Hackathon (Track 2a, Problem Statement 2a.3)

Executes unit, integration, resilience, and adversarial regression suites
with real-time formatting, timing analysis, and coverage reporting.
"""

import sys
import os
import time
import argparse
import subprocess

# Ensure AgentShield root is in Python module search path
REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)
PARENT_DIR = os.path.dirname(REPO_ROOT)
if PARENT_DIR not in sys.path:
    sys.path.insert(0, PARENT_DIR)


def print_banner():
    banner = """
================================================================================
                    AgentShield — Automated Test Harness
    Multi-Turn AI Agent Security Auditing & Enforcement Verification
================================================================================
"""
    print(banner)


def run_tests(args):
    print_banner()

    cmd = [sys.executable, "-m", "pytest"]

    # Target specific test suites or all tests
    if args.suite == "all":
        cmd.append(os.path.join(REPO_ROOT, "tests"))
    elif args.suite == "adversarial":
        cmd.append(os.path.join(REPO_ROOT, "tests", "test_adversarial_regression.py"))
    elif args.suite == "resilience":
        cmd.append(os.path.join(REPO_ROOT, "tests", "test_resilience.py"))
    elif args.suite == "isolation":
        cmd.append(os.path.join(REPO_ROOT, "tests", "test_isolation.py"))
    elif args.suite == "properties":
        cmd.append(os.path.join(REPO_ROOT, "tests", "test_properties.py"))
    elif args.suite == "guard":
        cmd.append(os.path.join(REPO_ROOT, "tests", "test_guard.py"))
    elif args.suite == "policies":
        cmd.append(os.path.join(REPO_ROOT, "tests", "test_policies.py"))
    elif args.suite == "security":
        cmd.append(os.path.join(REPO_ROOT, "tests", "test_security_hardening.py"))

    # Verbosity
    if args.verbose:
        cmd.append("-v")

    # Coverage
    if args.coverage:
        cov_target = os.path.join(REPO_ROOT, "src")
        cov_json = os.path.join(REPO_ROOT, "results", "coverage.json")
        cmd.extend([
            f"--cov={cov_target}",
            "--cov-report=term",
            f"--cov-report=json:{cov_json}"
        ])

    print(f"[*] Running command: {' '.join(cmd)}")
    start_time = time.time()
    result = subprocess.run(cmd)
    elapsed = time.time() - start_time

    print("\n" + "=" * 80)
    print(f"[*] Execution completed in {elapsed:.2f} seconds.")
    if result.returncode == 0:
        print("[+] SUITE VERDICT: PASSED (100% of test invariants satisfied)")
    else:
        print(f"[-] SUITE VERDICT: FAILED (Exit code: {result.returncode})")
    print("=" * 80 + "\n")

    return result.returncode


def main():
    parser = argparse.ArgumentParser(description="AgentShield Automated Test Runner")
    parser.add_argument(
        "--suite",
        choices=["all", "adversarial", "resilience", "isolation", "properties", "guard", "policies", "security"],
        default="all",
        help="Test suite subset to run (default: all)"
    )
    parser.add_argument("-v", "--verbose", action="store_true", default=True, help="Run pytest with verbose output")
    parser.add_argument("--coverage", action="store_true", default=False, help="Generate statement coverage reports")
    args = parser.parse_args()

    sys.exit(run_tests(args))


if __name__ == "__main__":
    main()

