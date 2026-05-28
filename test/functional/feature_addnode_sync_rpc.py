#!/usr/bin/env python3
"""Functional test — addnode synchronous RPC behaviour (un-node #6 root cause 2).

Issue #6 root cause 2: "addnode returned {'success': true} BEFORE the TCP
connect completed (premature success)."

PR #10 fix: introduced `connect_to_sync` API; the addnode RPC now blocks until
the connect outcome is known, returns `{"error": "Transport connect failed"}`
for failures, structured errors for malformed inputs, etc.

This test covers ONLY the synchronous-RPC aspect (root cause 2). The companion
file `feature_addnode_logging.py` covers root cause 1 (the WARN log on every
failure). The two ROOT CAUSES were fixed by the same PR but exercise different
properties of the fix, so they get separate files for 1:1 sub-point mapping.

Sub-conditions covered HERE (RC2 — sync semantics + payload):
  - payload         — unreachable port returns a clean error, not success:true
  - synchronicity   — response carries the post-connect outcome
  - malformed input — structured error payload
  - command forms   — add / onetry / remove all synchronous
  - idempotency     — addnode same addr twice with add doesn't silent-dupe
  - concurrency     — 3 parallel addnodes don't deadlock
  - state           — getpeerinfo has no phantom entries
  - regression sweep — zero {"success": true} across all unreachable invocations

Out of scope here (covered elsewhere):
  - logging (RC1)            → feature_addnode_logging.py
  - retry mechanism (RC3)    → bug_addnode_no_retry.py
  - post-IBD stall (RC4)     → bug_post_ibd_stall_disabled.py
  - getaddednodeinfo (Adj.)  → bug_getaddednodeinfo_missing.py

Issue:  https://github.com/unicitynetwork/unicity-node/issues/6 (RC2)
Fix PR: https://github.com/unicitynetwork/unicity-node/pull/10
"""
import sys
import time
import tempfile
import shutil
import threading
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "test_framework"))
from test_node import TestNode
from util import pick_free_port

GREEN, RED, YELLOW, BLUE, RESET = '\033[92m', '\033[91m', '\033[93m', '\033[94m', '\033[0m'


def log(msg, color=None):
    print(f"{color}{msg}{RESET}" if color else msg)


def is_clean_error(rv):
    """rpc() returns either a dict on JSON output or a string. Treat any dict
    that has 'error' (and no 'success': true) as a clean structured error.
    Treat 'Transport connect failed' / 'Invalid address format' etc. as ok."""
    if isinstance(rv, dict):
        if rv.get("success") is True:
            return False
        return "error" in rv
    if isinstance(rv, str):
        return ("error" in rv.lower()) and ('"success": true' not in rv.lower())
    return False


def is_success(rv):
    if isinstance(rv, dict):
        return rv.get("success") is True
    return isinstance(rv, str) and '"success": true' in rv.lower()


def log_count(node, pattern):
    """Count occurrences of <pattern> in the node's debug.log (regex)."""
    debug = Path(node.datadir) / "debug.log"
    if not debug.exists():
        return 0
    import re
    rx = re.compile(pattern, re.IGNORECASE)
    n = 0
    with debug.open() as f:
        for line in f:
            if rx.search(line):
                n += 1
    return n


def main():
    test_dir = Path(tempfile.mkdtemp(prefix='cbc_addnode_sync_'))
    binary_path = Path(__file__).resolve().parent.parent.parent / "build" / "bin" / "unicityd"
    failures = []

    node = TestNode(0, test_dir / "node0", binary_path=binary_path,
                    extra_args=[f"--port={pick_free_port()}"], chain="regtest")

    def check(name, ok, detail=""):
        marker = f"{GREEN}✅{RESET}" if ok else f"{RED}❌{RESET}"
        log(f"  {marker} {name}" + (f"  ({detail})" if detail else ""))
        if not ok:
            failures.append(name + (": " + detail if detail else ""))
        return ok

    try:
        log("\n" + "=" * 70, BLUE)
        log("Functional test — un-node #6 / PR #10 (addnode synchronous + logging)", BLUE)
        log("=" * 70, BLUE)

        log("\n[setup] start regtest node")
        node.start()

        # -------- [2b] payload: unreachable → clean error, NOT success:true
        log("\n[2b] payload — unreachable port returns clean error, not success:true")
        rv = node.rpc("addnode", "127.0.0.1:99", "add")
        check("2b unreachable returns structured error", is_clean_error(rv), f"rv={rv!r}")
        check("2b unreachable does NOT return success:true", not is_success(rv))

        # -------- [2c] sync proof: payload contains specific-to-attempt error
        # NOTE: absolute-time threshold isn't portable — on bare-metal Linux
        # connect()→127.0.0.1:<closed-port> gets an instant kernel RST (<1ms);
        # Docker namespaces add ~150ms. The TRUE sync proof is that the RPC
        # response payload contains an error message that could only be produced
        # AFTER the connect attempt was made (matches the C++ outcome enum).
        # We still measure + print the timings as informational.
        log("\n[2c] synchronicity — RPC response carries the post-connect outcome")
        timings = []
        rvs = []
        for port in (99, 65535, 88):
            t0 = time.monotonic()
            rv = node.rpc("addnode", f"127.0.0.1:{port}", "onetry")
            timings.append((time.monotonic() - t0) * 1000)
            rvs.append(rv)
        for t, p in zip(timings, (99, 65535, 88)):
            log(f"    addnode 127.0.0.1:{p} onetry → {t:.0f} ms  (informational)")
        # Async (old): would have returned {"success": true} BEFORE the connect outcome was known.
        # Sync (new):  every response carries a concrete failure message from the connect attempt.
        check_msg = lambda rv: (
            isinstance(rv, dict)
            and "error" in rv
            and any(k in rv.get("error", "").lower()
                    for k in ("transport", "timeout", "fail", "unreachable", "refused"))
        )
        check("2c every response carries a post-connect failure message",
              all(check_msg(rv) for rv in rvs),
              f"rvs={rvs}")

        # -------- [2d] logging — moved to feature_addnode_logging.py (RC1)
        # The logging sub-check (failure → debug.log warning) is verified by
        # the companion file feature_addnode_logging.py. This file focuses on
        # RC2 (synchronous RPC payload/semantics) for clean 1:1 sub-point
        # mapping.

        # -------- [2e] malformed addresses → structured errors
        log("\n[2e] malformed addresses → structured error payload (not crash, not success)")
        for addr in ["256.256.256.256:1234", "not_an_ip:1234", "0.0.0.0:0", "127.0.0.1:0"]:
            rv = node.rpc("addnode", addr, "onetry")
            check(f"2e malformed {addr}", is_clean_error(rv), f"rv={rv!r}")

        # -------- [2f] command forms: add / onetry / remove all synchronous and structured
        log("\n[2f] command forms — add / onetry / remove all synchronous")
        rv_add    = node.rpc("addnode", "127.0.0.1:65501", "add")
        rv_onetry = node.rpc("addnode", "127.0.0.1:65502", "onetry")
        rv_rm     = node.rpc("addnode", "127.0.0.1:65501", "remove")
        rv_rm2    = node.rpc("addnode", "127.0.0.1:65501", "remove")
        check("2f add    returns error (unreachable)", is_clean_error(rv_add))
        check("2f onetry returns error (unreachable)", is_clean_error(rv_onetry))
        check("2f remove returns error (peer not found)", is_clean_error(rv_rm))
        check("2f remove twice → error both times", is_clean_error(rv_rm2))

        # -------- [2g] idempotency
        log("\n[2g] idempotency — addnode same addr twice with 'add' doesn't silent-dupe")
        rv1 = node.rpc("addnode", "127.0.0.1:65503", "add")
        rv2 = node.rpc("addnode", "127.0.0.1:65503", "add")
        check("2g first  add → structured error", is_clean_error(rv1))
        check("2g second add → structured error (no silent-dupe success)",
              is_clean_error(rv2) and not is_success(rv2))
        node.rpc("addnode", "127.0.0.1:65503", "remove")

        # -------- [2i] state: getpeerinfo has no phantom entries
        log("\n[2i] state — getpeerinfo shows 0 phantom peers after all the failed addnodes")
        peers = node.rpc("getpeerinfo")
        n_peers = len(peers) if isinstance(peers, list) else 0
        check("2i 0 connected peers (no phantoms)", n_peers == 0, f"n_peers={n_peers}")

        # -------- [2j] concurrency: 3 parallel addnodes — all return, all logged
        log("\n[2j] concurrency — 3 parallel addnodes don't deadlock; all logged")
        results = {}
        def go(p):
            results[p] = node.rpc("addnode", f"127.0.0.1:{p}", "onetry")
        threads = [threading.Thread(target=go, args=(p,)) for p in (65510, 65511, 65512)]
        t0 = time.monotonic()
        for t in threads: t.start()
        for t in threads: t.join(timeout=10)
        wall = (time.monotonic() - t0) * 1000
        log(f"    3 parallel total wall: {wall:.0f} ms")
        check("2j all 3 returned", all(p in results for p in (65510, 65511, 65512)))
        check("2j all 3 returned errors (no successes)",
              all(is_clean_error(results[p]) for p in (65510, 65511, 65512)),
              f"results={results}")
        time.sleep(0.5)
        n_par = log_count(node, r"outbound connect failed.*127\.0\.0\.1:(65510|65511|65512)")
        check("2j ≥ 3 corresponding log warnings", n_par >= 3, f"found {n_par}")

        # -------- [2k] regression sweep — zero {success:true} across all the unreachable cases
        log("\n[2k] sweep — zero {success:true} across all unreachable invocations")
        sweep_ports = [99, 88, 65535, 65501, 65502, 65510, 65511, 65512]
        bad_success = 0
        for p in sweep_ports:
            rv = node.rpc("addnode", f"127.0.0.1:{p}", "onetry")
            if is_success(rv):
                bad_success += 1
        check("2k zero silent-success regressions", bad_success == 0,
              f"bad_success={bad_success}")

        # -------- Verdict
        log("\n" + "=" * 70, BLUE)
        if failures:
            log("FAIL — un-node #6 / PR #10 regression detected:", RED)
            for f in failures:
                log(f"  - {f}", RED)
            return 1
        log("PASS — un-node #6 / PR #10 verified.", GREEN)
        log("       addnode is synchronous, returns clean errors, logs every failure,", GREEN)
        log("       no phantom peers, no silent-success regression, no deadlock under", GREEN)
        log("       concurrent use.", GREEN)
        return 0
    finally:
        try:
            node.stop()
        except Exception:
            pass
        shutil.rmtree(test_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
