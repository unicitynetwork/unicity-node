#!/usr/bin/env python3
"""Bug reproducer — RPC server still uses thread-per-request `std::thread().detach()` (un-node #5 Priority 2).

The original #5 body listed THREE recommended fixes:
  1. increase listen backlog                                — DONE by PR #11
  2. replace detached threads with thread pool              — STILL OPEN (this file, F2)
  3. support HTTP keep-alive to reduce connection count     — STILL OPEN (F2b)

PR #11 addressed only #1. Each accepted connection still spawns a fresh
`std::thread([](){ ... }).detach()`, so the accept loop bears thread-creation
overhead under bursty load.

This reproducer is a SOURCE-LEVEL check on `src/network/rpc_server.cpp`'s
accept loop (a runtime test of thread-creation overhead would be a benchmark,
not a pass/fail). It asserts:
  - the accept loop still contains `std::thread(...)` and `.detach()`
  - there is no `ThreadPool` / worker queue construct

When the fix lands (worker pool replaces the per-request thread), the
assertion flips and this file should be inverted or deleted.

Tracking: aggregator-subscription/INVESTIGATIONS.md F2
"""
import re
import sys
from pathlib import Path

GREEN, RED, YELLOW, BLUE, RESET = '\033[92m', '\033[91m', '\033[93m', '\033[94m', '\033[0m'


def log(msg, color=None):
    print(f"{color}{msg}{RESET}" if color else msg)


def main():
    src = Path(__file__).resolve().parent.parent.parent / "src" / "network" / "rpc_server.cpp"
    if not src.exists():
        log(f"source not found: {src}", RED)
        return 2
    text = src.read_text()

    log("\n" + "=" * 70, BLUE)
    log("BUG REPRODUCER — un-node #5 Priority 2: thread-per-request still in place", BLUE)
    log("=" * 70, BLUE)

    # Find ServerThread() / accept-loop. The accept-loop function spawns a
    # detached std::thread per accepted client_fd.
    m = re.search(r"void\s+RPCServer::ServerThread\s*\(\s*\)\s*\{(.+?)\n\}\n", text, re.DOTALL)
    if not m:
        log("ServerThread() function not found — has it been renamed/restructured?", YELLOW)
        log("That alone could indicate the fix landed (e.g. a thread-pool refactor).", YELLOW)
        return 1
    body = m.group(1)

    log("\n[1] accept loop spawns std::thread per request")
    has_thread = bool(re.search(r"std::thread\s*\(", body))
    has_detach = ".detach()" in body
    log(f"  std::thread(...) call present: {has_thread}",
        YELLOW if has_thread else GREEN)
    log(f"  .detach() call present:        {has_detach}",
        YELLOW if has_detach else GREEN)

    log("\n[2] no worker-pool replacement")
    # Look for any sign of a thread-pool / worker-queue construct anywhere in the file.
    has_pool = bool(re.search(
        r"thread_pool|ThreadPool|worker_pool|WorkerPool|task_queue|TaskQueue", text))
    log(f"  thread/worker pool present:    {has_pool}",
        GREEN if has_pool else YELLOW)

    log("\n[3] MAX_CONCURRENT_REQUESTS guard (informational — Priority 2 context)")
    has_max_concurrent = bool(re.search(r"MAX_CONCURRENT_REQUESTS", text))
    log(f"  MAX_CONCURRENT_REQUESTS guard present: {has_max_concurrent}")

    log("\n" + "=" * 70, BLUE)
    if has_thread and has_detach and not has_pool:
        log("BUG REPRODUCED — accept loop still spawns detached threads per request.", YELLOW)
        log("  • std::thread(...) call present:  True", YELLOW)
        log("  • .detach() call present:         True", YELLOW)
        log("  • thread/worker pool replacement: False", YELLOW)
        log("  → un-node #5 Priority 2 still open. ✅ reproducer working.", YELLOW)
        return 0
    else:
        log("BUG FIXED?  The thread-per-request pattern no longer matches:", GREEN)
        log(f"  • std::thread present: {has_thread}", GREEN)
        log(f"  • .detach() present:   {has_detach}", GREEN)
        log(f"  • pool present:        {has_pool}", GREEN)
        log("  → looks like a worker pool was introduced.", GREEN)
        log("    Reproducer is OBSOLETE; invert or delete it.", GREEN)
        return 1


if __name__ == "__main__":
    sys.exit(main())
