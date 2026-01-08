#!/usr/bin/env python3
"""Test runner for functional tests."""

import sys
import os
import subprocess
import argparse
import time
from pathlib import Path


def run_test(test_script, timeout):
    """Run a single test script and return (success, duration)."""
    print(f"\n{'=' * 60}")
    print(f"Running: {test_script.name}")
    print('=' * 60)

    start = time.time()
    try:
        result = subprocess.run(
            [sys.executable, str(test_script)],
            cwd=test_script.parent.parent.parent,
            timeout=timeout
        )
        duration = time.time() - start
        return (result.returncode == 0, duration)
    except subprocess.TimeoutExpired:
        print(f"✗ TIMEOUT after {timeout}s: {test_script.name}")
        duration = time.time() - start
        return (False, duration)


def main():
    """Run all functional tests."""
    parser = argparse.ArgumentParser(description="Functional test runner")
    parser.add_argument("-k", dest="pattern", default="", help="Filter tests by substring match")
    parser.add_argument("--junit", dest="junit", default="", help="Write JUnit XML report to path")
    parser.add_argument("--timeout", dest="timeout", type=int, default=900, help="Per-test timeout (seconds)")
    parser.add_argument("--failfast", action="store_true",
                        help="Stop running further tests after the first failure")
    args = parser.parse_args()

    test_dir = Path(__file__).parent

    # Files to exclude (setup scripts, debug scripts, and infrastructure)
    exclude_files = {
        "test_runner.py",
        "regenerate_test_chains.py", # Setup script, not a test
        "debug_sync_issue.py",       # Debug script, not a test
        "p2p_batching.py",           # Slow test (opt-in via -k)
        "feature_multinode_sync.py",  # Slow/complex (opt-in via -k)
        "feature_chaos_convergence.py",  # Slow/complex (opt-in via -k)
        "feature_ibd_restart_resume.py",  # Unstable/advanced (opt-in via -k)
        "feature_suspicious_reorg.py",  # Advanced behavior (opt-in via -k)
        "adversarial_headers_wire.py",   # Wire-level adversarial (opt-in; uses node_simulator)
        "adversarial_oversized_wire.py", # Wire-level: oversized headers (opt-in)
        "adversarial_spam_non_continuous_wire.py", # Wire-level: spam non-continuous (opt-in)
        "adversarial_slow_loris_wire.py",  # Wire-level: slow-loris (opt-in)
        "adversarial_framing_wire.py",     # Wire-level: framing errors (opt-in)
        "test_sync_100k.py",               # 100k-block sync perf test (requires local chain_100000_blocks)
        "feature_large_concurrent_reorg_cascade.py",  # Slow test (opt-in via -k)
        "feature_massive_reorg.py",  # Slow test (opt-in via -k)
    }

    # Find all test scripts (only feature_* and test_* files)
    test_scripts = []
    for file in sorted(test_dir.glob("*.py")):
        if file.name not in exclude_files and not file.name.startswith("_"):
            if file.name.startswith(("feature_", "test_", "p2p_", "rpc_", "basic_", "consensus_", "orphan_")):
                if not args.pattern or args.pattern in file.name:
                    test_scripts.append(file)

    if not test_scripts:
        print("No test scripts found!")
        return 1

    print(f"Found {len(test_scripts)} test(s)")

    # Run all tests
    results = {}
    durations = {}
    for test_script in test_scripts:
        success, duration = run_test(test_script, timeout=args.timeout)
        results[test_script.name] = success
        durations[test_script.name] = duration

        # Optional fail-fast behavior
        if not success and args.failfast:
            print("\nStopping test run early due to failure (--failfast enabled).")
            break

    # Print summary
    print(f"\n{'=' * 60}")
    print("Test Summary")
    print('=' * 60)

    passed = sum(1 for success in results.values() if success)
    failed = len(results) - passed

    for test_name, success in results.items():
        status = "✓ PASSED" if success else "✗ FAILED"
        print(f"{status}: {test_name} ({durations[test_name]:.1f}s)")

    print(f"\n{passed} passed, {failed} failed out of {len(results)} tests")

    # Optional JUnit output
    if args.junit:
        try:
            from xml.etree.ElementTree import Element, SubElement, ElementTree
            ts = Element("testsuite", name="functional", tests=str(len(results)), failures=str(failed))
            for name, success in results.items():
                tc = SubElement(ts, "testcase", name=name, time=f"{durations[name]:.3f}")
                if not success:
                    failure = SubElement(tc, "failure", message="Test failed")
                    failure.text = "See console output for details"
            tree = ElementTree(ts)
            with open(args.junit, "wb") as f:
                tree.write(f, encoding="utf-8", xml_declaration=True)
            print(f"JUnit report written to {args.junit}")
        except Exception as e:
            print(f"Failed to write JUnit report: {e}")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
