#!/usr/bin/env python3
"""RPC banlist persistence test (strict).

Verifies setban persists across restart and clearbanned removes entries.
"""

import sys
import tempfile
import shutil
import time
from pathlib import Path

# Add test framework to path
sys.path.insert(0, str(Path(__file__).parent / "test_framework"))
from test_node import TestNode
from util import pick_free_port


def listbanned_map(node):
    arr = node.rpc("listbanned")
    assert isinstance(arr, list), f"listbanned must return a list, got {type(arr)}"
    return {e.get("address"): e for e in arr if isinstance(e, dict)}


def main():
    print("Starting rpc_ban_persistence (strict) test...")

    test_dir = Path(tempfile.mkdtemp(prefix="unicity_ban_persist_"))
    binary_path = Path(__file__).parent.parent.parent / "build" / "bin" / "unicityd"

    node = None
    port = pick_free_port()
    try:
        node = TestNode(0, test_dir / "node0", binary_path, extra_args=["--regtest", f"--port={port}"])
        node.start()

        # Add a couple bans
        r1 = node.rpc("setban", "127.0.0.2", "add")
        r2 = node.rpc("setban", "127.0.0.3", "add")
        assert isinstance(r1, dict) and r1.get("success") is True, f"setban failed: {r1}"
        assert isinstance(r2, dict) and r2.get("success") is True, f"setban failed: {r2}"
        banned = listbanned_map(node)
        assert "127.0.0.2" in banned and "127.0.0.3" in banned

        # Restart
        node.stop()
        time.sleep(1)
        node = TestNode(0, test_dir / "node0", binary_path, extra_args=["--regtest", f"--port={port}"])  # same datadir
        node.start()

        # Verify bans persisted
        banned2 = listbanned_map(node)
        assert "127.0.0.2" in banned2 and "127.0.0.3" in banned2, "Banlist did not persist across restart"

        # Clear banned must be supported on regtest
        res = node.rpc("clearbanned")
        assert isinstance(res, dict) and res.get("success") is True, f"clearbanned failed: {res}"
        banned3 = listbanned_map(node)
        assert not banned3, "Expected banlist to be empty after clearbanned"

        print("✓ rpc_ban_persistence (strict) passed")
        return 0

    except Exception as e:
        print(f"✗ rpc_ban_persistence failed: {e}")
        return 1

    finally:
        if node and node.is_running():
            print("Stopping node...")
            node.stop()
        print(f"Cleaning up {test_dir}")
        shutil.rmtree(test_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
