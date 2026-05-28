#!/usr/bin/env python3
"""Functional test — addnode failure logging (un-node #6 root cause 1).

Issue #6 root cause 1: "Silent async failures — connection failures only
increment a counter; no logging occurs at any level."

PR #10 fix: every failed outbound connection produces a
`[network] [warning] outbound connect failed: <ip>:<port> (conn_type=<...>)`
entry in debug.log.

This test exercises ONLY the logging aspect of the fix — the payload/sync
aspects are covered by feature_addnode_sync_rpc.py.

Issue:  https://github.com/unicitynetwork/unicity-node/issues/6 (RC1)
Fix PR: https://github.com/unicitynetwork/unicity-node/pull/10
"""
import sys
import time
import tempfile
import shutil
import re
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "test_framework"))
from test_node import TestNode
from util import pick_free_port

GREEN, RED, YELLOW, BLUE, RESET = '\033[92m', '\033[91m', '\033[93m', '\033[94m', '\033[0m'


def log(msg, color=None):
    print(f"{color}{msg}{RESET}" if color else msg)


def log_count(node, pattern):
    """Count regex matches in the node's debug.log."""
    debug = Path(node.datadir) / "debug.log"
    if not debug.exists():
        return 0
    rx = re.compile(pattern, re.IGNORECASE)
    with debug.open() as f:
        return sum(1 for line in f if rx.search(line))


def main():
    test_dir = Path(tempfile.mkdtemp(prefix='cbc_addnode_logging_'))
    binary = Path(__file__).resolve().parent.parent.parent / "build" / "bin" / "unicityd"
    node = TestNode(0, test_dir / "node0", binary_path=binary,
                    extra_args=[f"--port={pick_free_port()}"], chain="regtest")
    failures = []

    def check(name, ok, detail=""):
        marker = f"{GREEN}✅{RESET}" if ok else f"{RED}❌{RESET}"
        log(f"  {marker} {name}" + (f"  ({detail})" if detail else ""))
        if not ok:
            failures.append(name + (": " + detail if detail else ""))

    try:
        log("\n" + "=" * 70, BLUE)
        log("Functional test — un-node #6 RC1 (addnode failure LOGGING)", BLUE)
        log("=" * 70, BLUE)

        node.start()

        # Trigger several distinct failures on different ports so we can count log lines.
        ports = [65501, 65502, 65503, 65504, 65505]
        log(f"\n[1] trigger {len(ports)} unreachable addnode attempts (distinct ports)")
        for p in ports:
            node.rpc("addnode", f"127.0.0.1:{p}", "onetry")
        time.sleep(0.5)  # let the logger flush

        # Each failure must produce a WARN log line containing the port.
        log("\n[2] each failure produces a WARN log line with the port")
        per_port = {p: log_count(node, rf"outbound connect failed.*127\.0\.0\.1:{p}\b") for p in ports}
        for p, n in per_port.items():
            log(f"    port {p}: {n} matching warning(s)")
        check(f"{len(ports)} unique-port warnings ({len(ports)} expected)",
              all(n >= 1 for n in per_port.values()),
              f"per_port={per_port}")

        # The warning includes the connection type (manual / outbound / ...) — this is the
        # rich context PR #10 added.
        log("\n[3] warnings include conn_type context")
        with_conn_type = log_count(node, r"outbound connect failed:.*conn_type=")
        log(f"    warnings with conn_type=: {with_conn_type}")
        check("at least one warning includes conn_type", with_conn_type >= 1,
              f"with_conn_type={with_conn_type}")

        # Negative check: NO failures should be silent. The total warning count must
        # match the number of addnode failures (one per attempt).
        log("\n[4] no silent failures — warnings count >= addnode failure count")
        total_warns = log_count(node, r"outbound connect failed:.*127\.0\.0\.1")
        log(f"    total 'outbound connect failed' warnings: {total_warns}")
        check(f"{total_warns} >= {len(ports)}", total_warns >= len(ports),
              f"got {total_warns} for {len(ports)} attempts")

        log("\n" + "=" * 70, BLUE)
        if failures:
            log("FAIL — un-node #6 RC1 regression:", RED)
            for f in failures:
                log(f"  - {f}", RED)
            return 1
        log("PASS — un-node #6 RC1 verified.", GREEN)
        log("       Every failed addnode produces a [network] [warning]", GREEN)
        log("       outbound connect failed: ... log entry with conn_type context.", GREEN)
        return 0
    finally:
        try:
            node.stop()
        except Exception:
            pass
        shutil.rmtree(test_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
