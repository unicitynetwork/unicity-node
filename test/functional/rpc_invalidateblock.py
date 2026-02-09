#!/usr/bin/env python3
"""Functional tests for invalidateblock RPC.

Tests:
1. Basic invalidation - invalidate a block and verify chain rewinds
2. Invalidate genesis - should fail with error
3. Invalidate unknown block - should fail with error
4. Fork switch after invalidation - invalidate main chain, switch to fork
5. Multi-node: node invalidates block, builds new chain, other node syncs
"""

import sys
import time
import tempfile
import shutil
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "test_framework"))
from test_node import TestNode
from util import pick_free_port, wait_until

GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'


def log(msg, color=None):
    if color:
        print(f"{color}{msg}{RESET}")
    else:
        print(msg)


def test_basic_invalidation(test_dir, binary_path):
    """Test basic block invalidation and chain rewind."""
    log("\n[TEST] Basic invalidation", BLUE)
    log("-" * 50)

    port = pick_free_port()
    node = TestNode(1, test_dir / "n1", binary_path,
                    extra_args=["--listen", f"--port={port}"])

    try:
        node.start()

        # Generate initial chain: genesis -> A -> B -> C -> D (height 4)
        node.generate(4)
        info = node.get_info()
        assert info["blocks"] == 4, f"Expected height 4, got {info['blocks']}"
        tip_hash = info["bestblockhash"]
        log(f"  Initial chain: height={info['blocks']}, tip={tip_hash[:16]}...")

        # Get block B hash (height 2) via getblockhash
        block_b_hash = node.rpc("getblockhash", 2)
        log(f"  Block at height 2: {block_b_hash[:16]}...")

        # Invalidate block B
        log(f"  Invalidating block at height 2...")
        result = node.rpc("invalidateblock", block_b_hash)
        assert result.get("success") is True, f"invalidateblock failed: {result}"

        # Verify chain rewound to height 1
        info = node.get_info()
        assert info["blocks"] == 1, f"Expected height 1 after invalidation, got {info['blocks']}"
        log(f"  After invalidation: height={info['blocks']}, tip={info['bestblockhash'][:16]}...")

        # Advance mock time to ensure new blocks have different timestamps than invalidated blocks
        # This prevents hash collisions (same prev_hash + same time + same nonce = same hash)
        future_time = int(time.time()) + 100  # 100 seconds in future
        node.setmocktime(future_time)

        # Generate new blocks on the alternate chain
        log("  Generating new blocks after invalidation...")
        node.generate(3)
        info = node.get_info()
        assert info["blocks"] == 4, f"Expected height 4 after generating, got {info['blocks']}"
        new_tip = info["bestblockhash"]
        assert new_tip != tip_hash, "New tip should differ from original (different chain)"
        log(f"  New chain: height={info['blocks']}, tip={new_tip[:16]}...")

        log("  [PASS] Basic invalidation", GREEN)
        return True

    finally:
        if node.is_running():
            node.stop()


def test_invalidate_genesis(test_dir, binary_path):
    """Test that invalidating genesis block fails."""
    log("\n[TEST] Invalidate genesis (should fail)", BLUE)
    log("-" * 50)

    port = pick_free_port()
    node = TestNode(2, test_dir / "n2", binary_path,
                    extra_args=["--listen", f"--port={port}"])

    try:
        node.start()

        # Get genesis hash
        genesis_hash = node.rpc("getblockhash", 0)
        log(f"  Genesis hash: {genesis_hash[:16]}...")

        # Try to invalidate genesis - should fail
        result = node.rpc("invalidateblock", genesis_hash)

        # Check for error
        if "error" in result:
            log(f"  Got expected error: {result['error']}")
            log("  [PASS] Invalidate genesis correctly rejected", GREEN)
            return True
        elif result.get("success") is False:
            log(f"  Got expected failure: {result.get('message', 'no message')}")
            log("  [PASS] Invalidate genesis correctly rejected", GREEN)
            return True
        else:
            log(f"  [FAIL] Expected error, got: {result}", RED)
            return False

    finally:
        if node.is_running():
            node.stop()


def test_invalidate_unknown_block(test_dir, binary_path):
    """Test that invalidating unknown block fails."""
    log("\n[TEST] Invalidate unknown block (should fail)", BLUE)
    log("-" * 50)

    port = pick_free_port()
    node = TestNode(3, test_dir / "n3", binary_path,
                    extra_args=["--listen", f"--port={port}"])

    try:
        node.start()

        # Use a fake hash
        fake_hash = "0000000000000000000000000000000000000000000000000000000000001234"
        log(f"  Fake hash: {fake_hash[:16]}...")

        # Try to invalidate unknown block - should fail
        result = node.rpc("invalidateblock", fake_hash)

        # Check for error
        if "error" in result:
            log(f"  Got expected error: {result['error']}")
            log("  [PASS] Invalidate unknown block correctly rejected", GREEN)
            return True
        else:
            log(f"  [FAIL] Expected error, got: {result}", RED)
            return False

    finally:
        if node.is_running():
            node.stop()


def test_fork_switch_after_invalidation(test_dir, binary_path):
    """Test that invalidating a mid-chain block properly rewinds."""
    log("\n[TEST] Fork switch after invalidation", BLUE)
    log("-" * 50)

    port = pick_free_port()
    node = TestNode(10, test_dir / "n10", binary_path,
                    extra_args=["--listen", f"--port={port}"])

    try:
        node.start()

        # Build main chain: genesis -> A1 -> A2 -> A3 -> A4 (height 4)
        node.generate(4)
        info = node.get_info()
        assert info["blocks"] == 4
        main_tip = info["bestblockhash"]
        block_a1_hash = node.rpc("getblockhash", 1)
        log(f"  Main chain: height=4, tip={main_tip[:16]}...")

        # Get block at height 2
        block_a2_hash = node.rpc("getblockhash", 2)
        log(f"  Block A2 (height 2): {block_a2_hash[:16]}...")

        # Invalidate A2
        log(f"  Invalidating block A2...")
        result = node.rpc("invalidateblock", block_a2_hash)
        assert result.get("success") is True, f"invalidateblock failed: {result}"

        # Chain should rewind to A1 (height 1)
        info = node.get_info()
        assert info["blocks"] == 1, f"Expected height 1, got {info['blocks']}"
        assert info["bestblockhash"] == block_a1_hash
        log(f"  After invalidation: height={info['blocks']}, tip={info['bestblockhash'][:16]}...")

        # Advance mock time to ensure new blocks have different timestamps than invalidated blocks
        future_time = int(time.time()) + 100
        node.setmocktime(future_time)

        # Build new longer chain on alternate fork
        log("  Building new chain from height 1...")
        node.generate(5)
        info = node.get_info()
        assert info["blocks"] == 6, f"Expected height 6, got {info['blocks']}"
        new_tip = info["bestblockhash"]
        assert new_tip != main_tip, "New tip should differ from original"
        log(f"  New chain: height={info['blocks']}, tip={new_tip[:16]}...")

        log("  [PASS] Fork switch after invalidation", GREEN)
        return True

    finally:
        if node.is_running():
            node.stop()


def test_multinode_sync_after_invalidation(test_dir, binary_path):
    """Test that peers sync correctly after one node invalidates a block."""
    log("\n[TEST] Multi-node sync after invalidation", BLUE)
    log("-" * 50)

    port1 = pick_free_port()
    port2 = pick_free_port()

    node1 = TestNode(20, test_dir / "n20", binary_path,
                     extra_args=["--listen", f"--port={port1}"])
    node2 = TestNode(21, test_dir / "n21", binary_path,
                     extra_args=["--listen", f"--port={port2}"])

    try:
        # Start both nodes
        node1.start()
        node2.start()

        # Node1 generates initial chain (height 5)
        node1.generate(5)
        info1 = node1.get_info()
        assert info1["blocks"] == 5
        original_tip = info1["bestblockhash"]
        log(f"  Node1 initial: height={info1['blocks']}, tip={original_tip[:16]}...")

        # Connect node2 -> node1 (outbound from node2)
        log("  Connecting Node2 -> Node1...")
        result = node2.add_node(f"127.0.0.1:{port1}", "add")
        assert result.get("success") is True, f"addnode failed: {result}"

        # Wait for node2 to sync
        def node2_synced():
            try:
                info = node2.get_info()
                return info["blocks"] == 5 and info["bestblockhash"] == original_tip
            except:
                return False

        synced = wait_until(node2_synced, timeout=30)
        assert synced, "Node2 failed to sync initial chain"
        log(f"  Node2 synced to height 5")

        # Disconnect nodes from both sides and wait for cleanup
        log("  Disconnecting nodes...")
        peers2 = node2.get_peer_info()
        if peers2:
            for peer in peers2:
                node2.rpc("disconnectnode", str(peer.get("id", peer.get("peer_id", 0))))
        peers1 = node1.get_peer_info()
        if peers1:
            for peer in peers1:
                node1.rpc("disconnectnode", str(peer.get("id", peer.get("peer_id", 0))))

        # Wait for both nodes to fully disconnect
        def both_disconnected():
            try:
                p1 = node1.get_peer_info()
                p2 = node2.get_peer_info()
                return len(p1) == 0 and len(p2) == 0
            except:
                return False
        wait_until(both_disconnected, timeout=10)

        # Node2 invalidates block at height 3
        block_h3 = node2.rpc("getblockhash", 3)
        log(f"  Node2 invalidating block at height 3: {block_h3[:16]}...")
        result = node2.rpc("invalidateblock", block_h3)
        assert result.get("success") is True

        info2 = node2.get_info()
        assert info2["blocks"] == 2, f"Expected height 2, got {info2['blocks']}"
        log(f"  Node2 after invalidation: height={info2['blocks']}")

        # Advance mock time to ensure new blocks have different timestamps than invalidated blocks
        future_time = int(time.time()) + 100
        node2.setmocktime(future_time)

        # Node2 builds new longer chain (height 6)
        log("  Node2 building new chain...")
        node2.generate(4)
        info2 = node2.get_info()
        assert info2["blocks"] == 6
        new_tip = info2["bestblockhash"]
        log(f"  Node2 new chain: height={info2['blocks']}, tip={new_tip[:16]}...")

        # Set same mock time on Node1 so it accepts Node2's future-dated blocks
        node1.setmocktime(future_time)

        # Reconnect nodes - node1 should switch to node2's longer chain
        log("  Reconnecting Node1 -> Node2...")
        result = node1.add_node(f"127.0.0.1:{port2}", "add")
        assert result.get("success") is True

        # Wait for node1 to sync to node2's chain
        def node1_reorged():
            try:
                info = node1.get_info()
                return info["blocks"] == 6 and info["bestblockhash"] == new_tip
            except:
                return False

        synced = wait_until(node1_reorged, timeout=60)

        info1 = node1.get_info()
        log(f"  Node1 final: height={info1['blocks']}, tip={info1['bestblockhash'][:16]}...")

        if synced:
            log("  [PASS] Multi-node sync after invalidation", GREEN)
            return True
        else:
            log(f"  [FAIL] Node1 did not sync to new chain (height={info1['blocks']})", RED)
            return False

    finally:
        if node1.is_running():
            node1.stop()
        if node2.is_running():
            node2.stop()


def main():
    """Run all invalidateblock tests."""
    log("=" * 70, BLUE)
    log("INVALIDATEBLOCK FUNCTIONAL TESTS", BLUE)
    log("=" * 70, BLUE)

    test_dir = Path(tempfile.mkdtemp(prefix="uc_inv_"))
    binary_path = Path(__file__).parent.parent.parent / "build" / "bin" / "unicityd"

    log(f"Test directory: {test_dir}")
    log(f"Binary: {binary_path}")

    results = {}

    try:
        # Each test manages its own node(s)
        results["basic_invalidation"] = test_basic_invalidation(test_dir, binary_path)
        results["invalidate_genesis"] = test_invalidate_genesis(test_dir, binary_path)
        results["invalidate_unknown"] = test_invalidate_unknown_block(test_dir, binary_path)
        results["fork_switch"] = test_fork_switch_after_invalidation(test_dir, binary_path)
        results["multinode_sync"] = test_multinode_sync_after_invalidation(test_dir, binary_path)

    except Exception as e:
        log(f"\n[ERROR] Test failed with exception: {e}", RED)
        import traceback
        traceback.print_exc()
        return 1

    finally:
        log(f"\nTest directory: {test_dir}", YELLOW)
        # Uncomment to auto-cleanup:
        # shutil.rmtree(test_dir, ignore_errors=True)

    # Summary
    log("\n" + "=" * 70, BLUE)
    log("TEST SUMMARY", BLUE)
    log("=" * 70, BLUE)

    passed = sum(1 for r in results.values() if r)
    failed = sum(1 for r in results.values() if not r)

    for name, result in results.items():
        status = "[PASS]" if result else "[FAIL]"
        color = GREEN if result else RED
        log(f"  {status} {name}", color)

    log("")
    if failed == 0:
        log(f"All {passed} tests passed!", GREEN)
        return 0
    else:
        log(f"{failed} of {passed + failed} tests failed", RED)
        return 1


if __name__ == "__main__":
    sys.exit(main())
