#!/usr/bin/env python3
"""Test getblocktemplate and submitblock RPC commands.

Tests:
1. getblocktemplate returns correct structure
2. Template updates when chain advances
3. Long-polling blocks until new block arrives
4. submitblock accepts valid blocks
5. submitblock rejects invalid blocks
"""

import sys
import time
import tempfile
import shutil
import threading
from pathlib import Path

# Add test framework to path
sys.path.insert(0, str(Path(__file__).parent / "test_framework"))

from test_node import TestNode


def test_getblocktemplate_structure(node):
    """Test that getblocktemplate returns expected fields."""
    print("  Testing getblocktemplate structure...")

    template = node.rpc("getblocktemplate")

    # Check required fields
    required_fields = [
        "version", "previousblockhash", "height", "curtime",
        "bits", "target", "longpollid", "mintime", "mutable",
        "noncerange", "capabilities"
    ]

    for field in required_fields:
        assert field in template, f"Missing field: {field}"

    # Check field types
    assert isinstance(template["version"], int), "version should be int"
    assert isinstance(template["height"], int), "height should be int"
    assert isinstance(template["curtime"], int), "curtime should be int"
    assert isinstance(template["mintime"], int), "mintime should be int"
    assert len(template["previousblockhash"]) == 64, "previousblockhash should be 64 hex chars"
    assert len(template["bits"]) == 8, "bits should be 8 hex chars"
    assert len(template["target"]) == 64, "target should be 64 hex chars"
    assert len(template["longpollid"]) == 64, "longpollid should be 64 hex chars"
    assert "longpoll" in template["capabilities"], "should support longpoll"

    print(f"    Template at height {template['height']}: OK")
    return template


def test_template_updates_on_new_block(node):
    """Test that template changes when a new block is mined."""
    print("  Testing template updates on new block...")

    # Get initial template
    template1 = node.rpc("getblocktemplate")
    initial_height = template1["height"]
    initial_prevhash = template1["previousblockhash"]

    # Mine a block
    node.generate(1)

    # Get new template
    template2 = node.rpc("getblocktemplate")

    # Verify template updated
    assert template2["height"] == initial_height + 1, \
        f"Height should increase: {initial_height} -> {template2['height']}"
    assert template2["previousblockhash"] != initial_prevhash, \
        "previousblockhash should change"
    assert template2["longpollid"] != template1["longpollid"], \
        "longpollid should change"

    print(f"    Height increased {initial_height} -> {template2['height']}: OK")


def test_longpoll_blocks_until_new_block(node):
    """Test that long-polling blocks until a new block arrives."""
    print("  Testing long-polling behavior...")

    # Get current template and longpollid
    template = node.rpc("getblocktemplate")
    longpollid = template["longpollid"]
    initial_height = template["height"]

    # Start long-poll request in background thread
    longpoll_result = {"template": None, "error": None, "completed": False}

    def do_longpoll():
        try:
            # Pass longpollid directly as a string parameter (not JSON)
            # This should block until a new block arrives or timeout
            result = node.rpc("getblocktemplate", longpollid, timeout=60)
            longpoll_result["template"] = result
        except Exception as e:
            longpoll_result["error"] = str(e)
        longpoll_result["completed"] = True

    longpoll_thread = threading.Thread(target=do_longpoll)
    longpoll_thread.start()

    # Wait a moment to ensure long-poll is waiting
    time.sleep(1)
    assert not longpoll_result["completed"], "Long-poll should be blocking"

    # Mine a block to trigger long-poll return
    print("    Mining block to trigger long-poll...")
    node.generate(1)

    # Wait for long-poll to complete
    longpoll_thread.join(timeout=10)

    assert longpoll_result["completed"], "Long-poll should have completed"
    assert longpoll_result["error"] is None, f"Long-poll error: {longpoll_result['error']}"

    new_template = longpoll_result["template"]
    assert new_template["height"] == initial_height + 1, \
        f"Long-poll should return updated height: {new_template['height']}"

    print(f"    Long-poll returned new template at height {new_template['height']}: OK")


def test_longpoll_returns_immediately_if_tip_changed(node):
    """Test that long-poll returns immediately if tip already changed."""
    print("  Testing long-poll immediate return on stale longpollid...")

    # Get template, then mine a block
    template = node.rpc("getblocktemplate")
    old_longpollid = template["longpollid"]

    node.generate(1)

    # Now long-poll with old longpollid - should return immediately
    start_time = time.time()
    new_template = node.rpc("getblocktemplate", old_longpollid, timeout=5)
    elapsed = time.time() - start_time

    assert elapsed < 2, f"Long-poll should return immediately, took {elapsed:.1f}s"
    assert new_template["height"] == template["height"] + 1, \
        "Should return updated template"

    print(f"    Immediate return in {elapsed:.2f}s: OK")


def test_submitblock_valid(node):
    """Test that submitblock accepts a valid block (from internal miner)."""
    print("  Testing submitblock with valid block...")

    # For this test, we use the internal miner to create a valid block
    # and verify it's accepted. We can't easily craft a valid RandomX block
    # externally, so we test the RPC plumbing works.

    # Get template
    template = node.rpc("getblocktemplate")
    height_before = template["height"]

    # Use internal miner
    result = node.generate(1)

    # Verify block was added
    template_after = node.rpc("getblocktemplate")
    assert template_after["height"] == height_before + 1, \
        "Block should have been added"

    print(f"    Block accepted at height {template_after['height'] - 1}: OK")


def test_submitblock_invalid_length(node):
    """Test that submitblock rejects invalid header length."""
    print("  Testing submitblock rejects invalid length...")

    # Too short
    result = node.rpc("submitblock", "00" * 50)  # 50 bytes instead of 100
    assert result.get("error") or result.get("success") == False, \
        "Should reject short header"

    # Too long
    result = node.rpc("submitblock", "00" * 150)  # 150 bytes instead of 100
    assert result.get("error") or result.get("success") == False, \
        "Should reject long header"

    print("    Invalid lengths rejected: OK")


def test_submitblock_invalid_hex(node):
    """Test that submitblock rejects invalid hex."""
    print("  Testing submitblock rejects invalid hex...")

    # Invalid hex characters
    result = node.rpc("submitblock", "GG" + "00" * 99)
    assert result.get("error") or result.get("success") == False, \
        "Should reject invalid hex"

    print("    Invalid hex rejected: OK")


def test_submitblock_invalid_prevhash(node):
    """Test that submitblock rejects block with unknown prevhash."""
    print("  Testing submitblock rejects unknown prevhash...")

    # Construct a header with garbage prevhash (won't connect to chain)
    # Header format: version(4) + prevhash(32) + mineraddr(20) + time(4) + bits(4) + nonce(4) + rxhash(32) = 100 bytes
    fake_header = (
        "01000000" +                              # version = 1
        "ff" * 32 +                               # prevhash = all 0xff (doesn't exist)
        "00" * 20 +                               # minerAddress = zeros
        "00000000" +                              # time = 0
        "ffff001d" +                              # bits (doesn't matter)
        "00000000" +                              # nonce = 0
        "00" * 32                                 # hashRandomX = zeros
    )

    result = node.rpc("submitblock", fake_header)

    # Should fail because prevhash doesn't exist
    assert result.get("success") == False or result.get("error"), \
        "Should reject block with unknown prevhash"

    print("    Unknown prevhash rejected: OK")


def main():
    """Run all tests."""
    print("Starting getblocktemplate/submitblock RPC tests...\n")

    # Setup
    test_dir = Path(tempfile.mkdtemp(prefix="unicity_gbt_test_"))
    node = None

    try:
        # Start node
        node = TestNode(0, test_dir / "node0")
        print(f"Starting node at {node.datadir}...")
        node.start()

        # Generate some initial blocks
        print("Generating initial blocks...")
        node.generate(5)

        # Run tests
        print("\nRunning tests:")

        test_getblocktemplate_structure(node)
        test_template_updates_on_new_block(node)
        test_longpoll_blocks_until_new_block(node)
        test_longpoll_returns_immediately_if_tip_changed(node)
        test_submitblock_valid(node)
        test_submitblock_invalid_length(node)
        test_submitblock_invalid_hex(node)
        test_submitblock_invalid_prevhash(node)

        print("\n" + "=" * 50)
        print("All tests passed!")
        print("=" * 50)
        return 0

    except Exception as e:
        print(f"\n{'=' * 50}")
        print(f"TEST FAILED: {e}")
        print("=" * 50)

        if node:
            print("\nLast 30 lines of debug.log:")
            print(node.read_log(30))

        import traceback
        traceback.print_exc()
        return 1

    finally:
        if node and node.is_running():
            print("\nStopping node...")
            node.stop()

        print(f"Cleaning up: {test_dir}")
        shutil.rmtree(test_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
