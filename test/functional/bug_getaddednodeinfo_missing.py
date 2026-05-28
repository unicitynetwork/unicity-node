#!/usr/bin/env python3
"""Bug reproducer — `getaddednodeinfo` RPC is not implemented.

Surfaced during the manual verification of un-node #6 / PR #10 (state-query
sub-check 2i). Bitcoin-Core-style nodes typically expose `getaddednodeinfo`
so operators can inspect what `addnode add` actually queued. Without it,
the only way to verify the manually-added-nodes list is by grepping
`debug.log`.

Not a regression of #10 (which didn't claim to add this RPC). Logged here
as an adjacent gap. This file exits 0 while the gap is still there (calling
the RPC returns `Unknown command`), and exits 1 when someone implements it.

Tracking: aggregator-subscription/INVESTIGATIONS.md F6c
"""
import sys
import tempfile
import shutil
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "test_framework"))
from test_node import TestNode
from util import pick_free_port

GREEN, RED, YELLOW, BLUE, RESET = '\033[92m', '\033[91m', '\033[93m', '\033[94m', '\033[0m'


def log(msg, color=None):
    print(f"{color}{msg}{RESET}" if color else msg)


def main():
    test_dir = Path(tempfile.mkdtemp(prefix='cbc_bug_getaddednodeinfo_'))
    binary = Path(__file__).resolve().parent.parent.parent / "build" / "bin" / "unicityd"
    node = TestNode(0, test_dir / "node0", binary_path=binary,
                    extra_args=[f"--port={pick_free_port()}"], chain="regtest")
    try:
        log("\n" + "=" * 70, BLUE)
        log("BUG REPRODUCER — getaddednodeinfo RPC not implemented", BLUE)
        log("=" * 70, BLUE)

        node.start()
        log("\n[step] call getaddednodeinfo")
        rv = node.rpc("getaddednodeinfo")
        log(f"  result: {rv}")

        unknown = isinstance(rv, dict) and "unknown command" in str(rv.get("error", "")).lower()

        log("\n" + "=" * 70, BLUE)
        if unknown:
            log("BUG REPRODUCED — getaddednodeinfo returns 'Unknown command'.", YELLOW)
            log("  → RPC is still unimplemented. ✅ reproducer working.", YELLOW)
            return 0
        else:
            log("BUG FIXED?  getaddednodeinfo returned a non-Unknown-command response:", GREEN)
            log(f"  {rv}", GREEN)
            log("  → looks like the RPC was implemented. This reproducer is OBSOLETE;", GREEN)
            log("    invert/delete it and add a positive feature test.", GREEN)
            return 1
    finally:
        try:
            node.stop()
        except Exception:
            pass
        shutil.rmtree(test_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
