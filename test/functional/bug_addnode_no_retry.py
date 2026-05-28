#!/usr/bin/env python3
"""Bug reproducer — `addnode add` has no retry on transient failure.

Original issue body of #6 listed FOUR root causes:
  1. silent async failures (LOG-less)            — FIXED by PR #10
  2. premature RPC success                        — FIXED by PR #10
  3. NO RETRY MECHANISM                           — STILL OPEN (this file)
  4. post-IBD stall detection disabled            — STILL OPEN (see bug_post_ibd_stall_disabled.py)

`manual_addresses_` in connection_manager just remembers the address; if the
initial TCP connect fails, the node never re-attempts the manual peer. So if
you `addnode <peer> add` while <peer> is briefly down, then bring <peer> up
later, the node never connects.

This reproducer demonstrates the gap. It exits 0 if the gap is still present
(bug still open) and exits 1 if the node has learned to retry (= someone has
implemented the fix; this reproducer is now obsolete and should be inverted).

Issue:  https://github.com/unicitynetwork/unicity-node/issues/6 (item 3)
Tracking: aggregator-subscription/INVESTIGATIONS.md F6a
"""
import sys
import socket
import time
import tempfile
import shutil
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "test_framework"))
from test_node import TestNode
from util import pick_free_port

GREEN, RED, YELLOW, BLUE, RESET = '\033[92m', '\033[91m', '\033[93m', '\033[94m', '\033[0m'


def log(msg, color=None):
    print(f"{color}{msg}{RESET}" if color else msg)


def main():
    test_dir = Path(tempfile.mkdtemp(prefix='cbc_bug_addnode_no_retry_'))
    binary = Path(__file__).resolve().parent.parent.parent / "build" / "bin" / "unicityd"

    node_port = pick_free_port()
    peer_port = pick_free_port()  # the "peer" we'll bring up belatedly

    node = TestNode(0, test_dir / "node0", binary_path=binary,
                    extra_args=[f"--port={node_port}"], chain="regtest")

    listener_stop = threading.Event()
    listener_thread = None
    accepted = []

    def listener():
        """Belated TCP listener. After we addnode to peer_port (closed),
        we wait a few seconds, then start accepting on peer_port. If the
        node had a retry mechanism, it would connect to us."""
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            srv.bind(("127.0.0.1", peer_port))
            srv.listen(8)
            srv.settimeout(0.5)
        except OSError as e:
            log(f"  listener bind failed: {e}", RED)
            return
        deadline = time.time() + 20
        while not listener_stop.is_set() and time.time() < deadline:
            try:
                c, addr = srv.accept()
                accepted.append(addr)
                # We're not a real unicity peer; just close.
                c.close()
            except socket.timeout:
                pass
        srv.close()

    try:
        log("\n" + "=" * 70, BLUE)
        log("BUG REPRODUCER — un-node #6, out-of-scope item: 'no retry on addnode'", BLUE)
        log("=" * 70, BLUE)

        log("\n[setup] start regtest node")
        node.start()

        log(f"\n[step 1] addnode 127.0.0.1:{peer_port} add — peer is CLOSED right now (no listener)")
        rv = node.rpc("addnode", f"127.0.0.1:{peer_port}", "add")
        log(f"  result: {rv}")
        # Expected post-PR-10: clean error, not success.

        log(f"\n[step 2] start a TCP listener on 127.0.0.1:{peer_port} (5s after addnode)")
        time.sleep(5)
        listener_thread = threading.Thread(target=listener, daemon=True)
        listener_thread.start()
        log("  listener up; if the node has retry logic, it would now connect within ~10s")

        log("\n[step 3] wait 15s; observe whether the node attempts the manual peer again")
        time.sleep(15)
        log(f"  listener accepted {len(accepted)} connection attempt(s) from the node")

        # Capture additional evidence from debug.log: did unicityd log any retry attempt?
        debug = node.datadir / "debug.log"
        retry_log_hits = 0
        if debug.exists():
            with debug.open() as f:
                for line in f:
                    if str(peer_port) in line and (
                        "outbound connect attempt" in line.lower()
                        or "outbound connect failed" in line.lower()
                    ):
                        retry_log_hits += 1
        log(f"  debug.log mentions of port {peer_port}: {retry_log_hits}")

        # Verdict
        log("\n" + "=" * 70, BLUE)
        if len(accepted) == 0 and retry_log_hits <= 1:
            log("BUG REPRODUCED — the node did not retry the manual peer.", YELLOW)
            log(f"  • 0 inbound connection attempts from the node within 15s of the listener opening", YELLOW)
            log(f"  • only the original (failed) outbound attempt is in debug.log", YELLOW)
            log("  → un-node #6 item 3 (no retry mechanism) is still open. ✅ reproducer working.", YELLOW)
            return 0
        else:
            log("BUG FIXED?  Unexpected connection attempts observed:", GREEN)
            log(f"  • accepted {len(accepted)} connection(s) from the node", GREEN)
            log(f"  • {retry_log_hits} debug.log entries for port {peer_port}", GREEN)
            log("  → looks like retry logic is in. This reproducer is OBSOLETE.", GREEN)
            log("    Invert the assertion or delete this file, and file a CHANGELOG entry.", GREEN)
            return 1
    finally:
        listener_stop.set()
        if listener_thread:
            listener_thread.join(timeout=2)
        try:
            node.stop()
        except Exception:
            pass
        shutil.rmtree(test_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
