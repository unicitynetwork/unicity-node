#!/usr/bin/env python3
"""Bug reproducer — no FAST post-IBD chain-sync stall detection.

The original #6 body claimed "post-IBD stall detection disabled". After
verification, the picture is more nuanced:

POST-IBD LOGIC THAT IS PRESENT (commit 83a0fae9 added it):
  - ConsiderEviction(peer): post-IBD stale-chain eviction by chain-work
    comparison.  src/network/header_sync_manager.cpp:132-137 + :755+
  - PING/PONG timeout (~1200 s) at the protocol layer.
  - Inactivity timeout (~1200 s) at the protocol layer.
  - Multi-peer post-IBD sync (CheckInitialSync() pulls from all new outbound
    peers, not just one).

THE SPECIFIC GAP THAT REMAINS:
  The IBD-only deadline-based stall check inside `ProcessTimers()` —

      if (in_ibd) {
        // sync_deadline check on sync peer; disconnect on miss
      } else {
        // ONLY ConsiderEviction, NO deadline check
      }

  — has no post-IBD analog. A peer that:
    (a) responds to PINGs (passes the 1200 s timeouts), and
    (b) has chain-work not visibly behind ours (passes ConsiderEviction), and
    (c) silently drags its feet on actually delivering headers
  is only caught by the 1200 s inactivity timeout — a 20-minute window
  during which the node is effectively wedged on a slow peer. The IBD
  path catches the same case in seconds.

This reproducer is a SOURCE-LEVEL check on that specific shape. It asserts:
  - ProcessTimers() has the gate `in_ibd`
  - The IBD branch has a deadline-based check (look for `sync_deadline`)
  - The else (post-IBD) branch has NO deadline check (only ConsiderEviction)

When the gap is fixed (post-IBD branch gets a deadline analog), the third
assertion flips → exit code becomes 1 → time to invert/delete this file.

A runtime test of the actual stall would need a 2-node controlled-silence
scenario (peer that keeps PINGing but ignores GETHEADERS); doable but
fragile. Source-level is canonical here.

Issue:    https://github.com/unicitynetwork/unicity-node/issues/6 (item 4, scoped down)
Tracking: aggregator-subscription/INVESTIGATIONS.md F6b
"""
import re
import sys
from pathlib import Path

GREEN, RED, YELLOW, BLUE, RESET = '\033[92m', '\033[91m', '\033[93m', '\033[94m', '\033[0m'


def log(msg, color=None):
    print(f"{color}{msg}{RESET}" if color else msg)


def main():
    src_hsm = Path(__file__).resolve().parent.parent.parent / "src" / "network" / "header_sync_manager.cpp"
    if not src_hsm.exists():
        log(f"source not found: {src_hsm}", RED)
        return 2

    body = src_hsm.read_text()
    m = re.search(r"void\s+HeaderSyncManager::ProcessTimers\s*\(\s*\)\s*\{(.+?)\n\}\n",
                  body, re.DOTALL)
    if not m:
        log("ProcessTimers() not found — has the function been renamed?", RED)
        return 2
    pt_body = m.group(1)

    log("\n" + "=" * 70, BLUE)
    log("BUG REPRODUCER — no FAST post-IBD chain-sync stall detection", BLUE)
    log("=" * 70, BLUE)

    # Split into `if (in_ibd) { ... }` IBD branch and `else { ... }` post-IBD branch.
    ibd_match = re.search(
        r"if\s*\(\s*in_ibd\s*\)\s*\{(.*?)\}\s*else\s*\{(.*?)\}\s*$",
        pt_body.strip(), re.DOTALL,
    )
    if not ibd_match:
        log("Couldn't split ProcessTimers into if(in_ibd)/else branches.", YELLOW)
        log("Either the gate was removed (good!) or restructured (re-check the assertion).", YELLOW)
        log(f"ProcessTimers body:\n{pt_body}", YELLOW)
        return 1
    ibd_branch = ibd_match.group(1)
    post_ibd_branch = ibd_match.group(2)

    # [1] IBD branch HAS a deadline-based check (the gold standard)
    log("\n[1] IBD branch contains a deadline-based stall check")
    ibd_has_deadline = bool(re.search(
        r"sync_deadline|deadline\s*[!<>=]|timeout.*exceeded", ibd_branch, re.IGNORECASE))
    log(f"  IBD branch references sync_deadline / deadline / timeout: {ibd_has_deadline}",
        GREEN if ibd_has_deadline else RED)

    # [2] Post-IBD branch has ConsiderEviction (the existing partial mitigation)
    log("\n[2] post-IBD branch calls ConsiderEviction (existing partial mitigation)")
    post_has_eviction = "ConsiderEviction" in post_ibd_branch
    log(f"  post-IBD calls ConsiderEviction: {post_has_eviction}",
        GREEN if post_has_eviction else RED)

    # [3] Post-IBD branch has NO deadline check — this is the SPECIFIC gap
    log("\n[3] post-IBD branch does NOT have a deadline-based stall check (the gap)")
    post_has_deadline = bool(re.search(
        r"sync_deadline|deadline\s*[!<>=]|\btimeout\b.*exceeded", post_ibd_branch, re.IGNORECASE))
    log(f"  post-IBD references sync_deadline / deadline / timeout: {post_has_deadline}",
        YELLOW if not post_has_deadline else GREEN)

    log("\n" + "=" * 70, BLUE)
    if ibd_has_deadline and post_has_eviction and not post_has_deadline:
        log("BUG REPRODUCED — the specific gap is still present:", YELLOW)
        log("  • IBD branch has the deadline-based stall check", YELLOW)
        log("  • post-IBD branch has ConsiderEviction (chain-work eviction only)", YELLOW)
        log("  • post-IBD branch has NO deadline-based stall check", YELLOW)
        log("  → fast post-IBD stall detection is still missing. ✅ reproducer working.", YELLOW)
        return 0
    elif post_has_deadline:
        log("BUG FIXED?  post-IBD branch now references a deadline / timeout check:", GREEN)
        log("  → looks like the fast post-IBD stall check was implemented.", GREEN)
        log("    This reproducer is OBSOLETE; invert / delete it.", GREEN)
        return 1
    else:
        log("UNEXPECTED — IBD-branch mechanism changed, can't characterise:", RED)
        log(f"  ibd_has_deadline={ibd_has_deadline}", RED)
        log(f"  post_has_eviction={post_has_eviction}", RED)
        log(f"  post_has_deadline={post_has_deadline}", RED)
        log("  → re-inspect the source manually.", RED)
        return 2


if __name__ == "__main__":
    sys.exit(main())
