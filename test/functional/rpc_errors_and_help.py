#!/usr/bin/env python3
"""RPC error surfaces (strict).

Validates that unknown commands, bad params, and a non-existent 'help' RPC
produce deterministic JSON errors; also verifies a known RPC returns
structured JSON.
"""

import sys
import tempfile
import shutil
from pathlib import Path

# Add test framework to path
sys.path.insert(0, str(Path(__file__).parent / "test_framework"))
from test_node import TestNode


def main():
    print("Starting rpc_errors_and_help (strict) test...")

    test_dir = Path(tempfile.mkdtemp(prefix="unicity_rpc_errors_"))
    binary_path = Path(__file__).parent.parent.parent / "build" / "bin" / "unicityd"

    node = None
    try:
        node = TestNode(0, test_dir / "node0", binary_path, extra_args=["--regtest"])  # default regtest
        node.start()

        # 1) Unknown command must return JSON with exact error
        res = node.rpc("idontexist")
        assert isinstance(res, dict), f"Expected JSON dict for error, got {type(res)}"
        assert res.get("error") == "Unknown command", f"Unexpected error: {res}"

        # 2) Bad params count must return exact error message
        res = node.rpc("setban")  # missing args
        assert isinstance(res, dict), f"Expected JSON dict for error, got {type(res)}"
        assert res.get("error") == "Missing subnet/IP parameter", f"Unexpected error: {res}"

        # 3) 'help' is not an RPC command; must return Unknown command deterministically
        res = node.rpc("help")
        assert isinstance(res, dict) and res.get("error") == "Unknown command", f"Unexpected help response: {res}"

        # 4) Known command returns structured JSON
        info = node.get_info()
        assert isinstance(info, dict), f"getinfo must return JSON dict, got {type(info)}"
        for k in ("blocks", "bestblockhash"):
            assert k in info, f"getinfo missing key: {k} in {info}"

        print("✓ rpc_errors_and_help (strict) passed")
        return 0

    except Exception as e:
        print(f"✗ rpc_errors_and_help failed: {e}")
        return 1

    finally:
        if node and node.is_running():
            print("Stopping node...")
            node.stop()
        print(f"Cleaning up {test_dir}")
        shutil.rmtree(test_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
