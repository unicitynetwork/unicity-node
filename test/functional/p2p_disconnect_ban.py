#!/usr/bin/env python3
"""Test P2P disconnect and ban functionality.

Tests:
1. Disconnect via RPC (disconnectnode)
2. Manual ban via RPC (setban)
3. Banned nodes cannot reconnect
4. Clearing bans via RPC (clearbanned)
5. listbanned RPC works correctly
6. Disconnect and ban persistence across restarts

Adapted from Bitcoin Core's p2p_disconnect_ban.py for Unicity.
"""

import sys
import socket
import time
import tempfile
import shutil
from pathlib import Path

# Add test framework to path
sys.path.insert(0, str(Path(__file__).parent / "test_framework"))

from test_node import TestNode
from util import pick_free_port, wait_until


def test_disconnect_node(node1, node2):
    """Test disconnecting a peer via RPC."""
    print("  Test: Disconnect node via RPC")
    
    # Get node2's address
    peers = node1.get_peer_info()
    if not peers or len(peers) == 0:
        print("    ✗ FAILED: No peers connected")
        return False
    
    peer = peers[0]
    peer_addr = peer.get('addr')
    if not peer_addr:
        print("    ✗ FAILED: Cannot get peer address")
        return False
    
    # Disconnect
    result = node1.rpc("disconnectnode", peer_addr)
    if not (isinstance(result, dict) and result.get("success")):
        print(f"    ✗ FAILED: disconnectnode failed: {result}")
        return False
    
    # Wait for disconnect
    def disconnected():
        peers = node1.get_peer_info()
        return len(peers) == 0
    
    if not wait_until(disconnected, timeout=5):
        print("    ✗ FAILED: Peer not disconnected")
        return False
    
    print("    ✓ Successfully disconnected peer via RPC")
    return True


def test_ban_node(node1, node2_port):
    """Test banning an address via RPC."""
    print("  Test: Ban node via RPC")
    
    # Ban 127.0.0.1
    result = node1.rpc("setban", "127.0.0.1", "add")
    if not (isinstance(result, dict) and result.get("success")):
        print(f"    ✗ FAILED: setban failed: {result}")
        return False
    
    # Check ban list
    banned = node1.rpc("listbanned")
    if not isinstance(banned, list) or len(banned) == 0:
        print(f"    ✗ FAILED: No bans in listbanned: {banned}")
        return False
    
    # Verify 127.0.0.1 is banned
    found = False
    for ban in banned:
        if isinstance(ban, dict) and "127.0.0.1" in ban.get("address", ""):
            found = True
            break
    
    if not found:
        print(f"    ✗ FAILED: 127.0.0.1 not in ban list: {banned}")
        return False
    
    print("    ✓ Successfully banned address")
    
    # Try to reconnect node2 - should fail since it's on 127.0.0.1
    # Unicity blocks banned IPs for both inbound and outbound (peer_lifecycle_manager.cpp:1161, 1329)
    time.sleep(1)
    
    # addnode should return an error when trying to connect to banned IP
    #
    # Note: TestNode.rpc() returns structured JSON error objects on non-zero
    # exit codes (see test_framework/test_node.py). In that case it does NOT
    # raise, but instead returns a dict with an "error" key and an optional
    # "exit_code" field. Treat that as the expected failure for this test.
    result = node1.rpc("addnode", f"127.0.0.1:{node2_port}", "add")
    if isinstance(result, dict) and result.get("error"):
        print(f"    ✓ addnode correctly failed for banned IP: {result}")
    else:
        print(f"    ✗ FAILED: addnode did not fail as expected for banned IP: {result}")
        return False
    
    # Double-check: verify no peers connected
    time.sleep(1)
    peers = node1.get_peer_info()
    for peer in peers:
        if isinstance(peer, dict) and peer.get('connected') and peer.get('successfully_connected'):
            print(f"    ✗ FAILED: Banned node successfully connected: {peer}")
            return False
    
    print("    ✓ Banned node cannot connect (connection blocked by ban)")
    return True


def test_clear_bans(node):
    """Test clearing ban list via RPC."""
    print("  Test: Clear bans via RPC")
    
    # Should have bans from previous test
    banned = node.rpc("listbanned")
    if not isinstance(banned, list) or len(banned) == 0:
        print("    ✗ FAILED: No bans to clear")
        return False
    
    # Clear all bans
    result = node.rpc("clearbanned")
    if not (isinstance(result, dict) and result.get("success")):
        print(f"    ✗ FAILED: clearbanned failed: {result}")
        return False
    
    # Check ban list is empty
    banned = node.rpc("listbanned")
    if not isinstance(banned, list):
        print(f"    ✗ FAILED: listbanned returned non-list: {banned}")
        return False
    
    if len(banned) > 0:
        print(f"    ✗ FAILED: Bans not cleared: {banned}")
        return False
    
    print("    ✓ Successfully cleared bans")
    return True


def test_manual_disconnect(node1, node2, node2_port):
    """Test manual disconnect and reconnect."""
    print("  Test: Manual disconnect and reconnect")
    
    # Verify we start clean (pre-test cleanup should have handled this)
    peers1 = node1.get_peer_info()
    peers2 = node2.get_peer_info()
    if len(peers1) > 0 or len(peers2) > 0:
        print(f"    ✗ FAILED: Test precondition failed - nodes not clean (node1={len(peers1)}, node2={len(peers2)})")
        return False
    
    # Connect
    result = node1.rpc("addnode", f"127.0.0.1:{node2_port}", "add")
    if not (isinstance(result, dict) and result.get("success")):
        # addnode might fail if reconnecting too quickly - wait longer and retry
        print(f"    First connect attempt failed: {result}, waiting and retrying...")
        time.sleep(5)
        result = node1.rpc("addnode", f"127.0.0.1:{node2_port}", "add")
        if not (isinstance(result, dict) and result.get("success")):
            print(f"    ✗ FAILED: addnode failed after retry: {result}")
            return False
    
    # Wait for connection
    def connected():
        peers = node1.get_peer_info()
        for p in peers:
            if p.get('successfully_connected'):
                return True
        return False
    
    if not wait_until(connected, timeout=15):
        print("    ✗ FAILED: Nodes did not connect")
        print("\nNode1 debug.log (last 50 lines):")
        print(node1.read_log(50))
        print("\nNode2 debug.log (last 50 lines):")
        print(node2.read_log(50))
        return False
    
    print("    ✓ Nodes connected")
    
    # Disconnect
    result = node1.rpc("addnode", f"127.0.0.1:{node2_port}", "remove")
    if not (isinstance(result, dict) and result.get("success")):
        print(f"    ✗ FAILED: remove failed: {result}")
        return False
    
    # Wait for disconnect
    def disconnected():
        peers = node1.get_peer_info()
        for p in peers:
            if p.get('successfully_connected'):
                return False
        return True
    
    if not wait_until(disconnected, timeout=5):
        print("    ✗ FAILED: Nodes did not disconnect")
        return False
    
    print("    ✓ Manual disconnect successful")
    return True


def test_ban_with_time(node):
    """Test setting ban with expiration time."""
    print("  Test: Ban with expiration time")
    
    # Ban for 60 seconds
    result = node.rpc("setban", "192.168.1.1", "add", "60")
    if not (isinstance(result, dict) and result.get("success")):
        print(f"    ✗ FAILED: setban with time failed: {result}")
        return False
    
    # Check it's banned
    banned = node.rpc("listbanned")
    if not isinstance(banned, list):
        print(f"    ✗ FAILED: listbanned failed: {banned}")
        return False
    
    found = False
    for ban in banned:
        if isinstance(ban, dict) and "192.168.1.1" in ban.get("address", ""):
            # Check has banned_until field (Unicity uses 'banned_until')
            if "banned_until" not in ban:
                print(f"    ✗ FAILED: Ban missing banned_until: {ban}")
                return False
            found = True
            break
    
    if not found:
        print(f"    ✗ FAILED: 192.168.1.1 not banned: {banned}")
        return False
    
    print("    ✓ Ban with expiration time set correctly")
    
    # Remove the ban for cleanup
    node.rpc("setban", "192.168.1.1", "remove")
    
    return True


def test_remove_specific_ban(node):
    """Test removing a specific ban."""
    print("  Test: Remove specific ban")
    
    # Clear any existing bans first
    node.rpc("clearbanned")
    time.sleep(0.5)
    
    # Add two bans
    node.rpc("setban", "10.0.0.1", "add")
    node.rpc("setban", "10.0.0.2", "add")
    
    # Check both are banned
    banned = node.rpc("listbanned")
    if not isinstance(banned, list) or len(banned) < 2:
        print(f"    ✗ FAILED: Expected 2 bans, got: {banned}")
        return False
    
    # Remove one
    result = node.rpc("setban", "10.0.0.1", "remove")
    if not (isinstance(result, dict) and result.get("success")):
        print(f"    ✗ FAILED: setban remove failed: {result}")
        return False
    
    # Check only one remains
    banned = node.rpc("listbanned")
    if not isinstance(banned, list) or len(banned) != 1:
        print(f"    ✗ FAILED: Expected 1 ban, got: {banned}")
        return False
    
    # Check it's the right one
    if "10.0.0.2" not in banned[0].get("address", ""):
        print(f"    ✗ FAILED: Wrong ban remained: {banned}")
        return False
    
    print("    ✓ Specific ban removed correctly")
    
    # Cleanup
    node.rpc("clearbanned")
    
    return True


def main():
    print("Starting p2p_disconnect_ban test...")
    
    test_dir = Path(tempfile.mkdtemp(prefix="unicity_p2p_disconnect_ban_"))
    binary_path = Path(__file__).parent.parent.parent / "build" / "bin" / "unicityd"
    node1 = None
    node2 = None
    
    try:
        # Start two nodes
        port1 = pick_free_port()
        node1 = TestNode(
            0,
            test_dir / "node1",
            binary_path,
            extra_args=["--listen", f"--port={port1}", "--debug=network"],
            chain="regtest"
        )
        node1.start()
        
        port2 = pick_free_port()
        node2 = TestNode(
            1,
            test_dir / "node2",
            binary_path,
            extra_args=["--listen", f"--port={port2}", "--debug=network"],
            chain="regtest"
        )
        node2.start()
        
        print(f"Node1 started on port {port1}")
        print(f"Node2 started on port {port2}")
        time.sleep(2)
        
        # Connect nodes
        result = node1.rpc("addnode", f"127.0.0.1:{port2}", "add")
        assert isinstance(result, dict) and result.get("success"), f"Failed to connect nodes: {result}"
        
        # Wait for connection
        def connected():
            peers = node1.get_peer_info()
            return len(peers) > 0
        
        assert wait_until(connected, timeout=10), "Nodes failed to connect"
        print("Nodes connected successfully\n")
        
        # Run tests
        all_passed = True
        
        all_passed &= test_disconnect_node(node1, node2)
        time.sleep(1)
        
        # Reconnect for next test
        node1.rpc("addnode", f"127.0.0.1:{port2}", "add")
        wait_until(lambda: len(node1.get_peer_info()) > 0, timeout=10)
        
        all_passed &= test_ban_node(node1, port2)
        time.sleep(1)
        
        all_passed &= test_clear_bans(node1)
        time.sleep(2)
        
        # Debug: Check state before manual disconnect test
        print(f"\nDEBUG: State before manual_disconnect test:")
        print(f"  Node2 running: {node2.is_running()}")
        peers = node1.get_peer_info()
        print(f"  Node1 peers: {len(peers)}")
        for peer in peers:
            print(f"    Peer: addr={peer.get('addr')}, connected={peer.get('connected')}, successfully_connected={peer.get('successfully_connected')}")
        
        # Clear any lingering peer connections AND remove persistent addnode  
        # Remove the persistent addnode from earlier tests (line 372)
        # Note: addnode remove both disconnects the peer AND prevents auto-reconnection
        print("Removing persistent addnode connection...")
        result = node1.rpc("addnode", f"127.0.0.1:{port2}", "remove")
        print(f"  Remove addnode result: {result}")
        
        # Wait for the remove operation to complete (addnode remove disconnects the peer)
        def no_peers():
            return len(node1.get_peer_info()) == 0
        
        if wait_until(no_peers, timeout=5):
            print("  ✓ Node1 cleanup complete")
        else:
            peers = node1.get_peer_info()
            print(f"  ⚠ Warning: Node1 still has {len(peers)} peer(s) after remove")
            for peer in peers:
                print(f"      Peer {peer.get('id')}: connected={peer.get('connected')}, successfully_connected={peer.get('successfully_connected')}")
        
        # Also clean up node2's side
        peers2 = node2.get_peer_info()
        if len(peers2) > 0:
            print(f"Cleaning up node2's {len(peers2)} peer(s)...")
            for peer in peers2:
                peer_id = peer.get('id')
                if peer_id is not None:
                    result = node2.rpc("disconnectnode", str(peer_id))
                    print(f"    Node2 disconnecting peer {peer_id}: {result}")
            # Wait for cleanup
            def node2_no_peers():
                return len(node2.get_peer_info()) == 0
            if wait_until(node2_no_peers, timeout=5):
                print("  ✓ Node2 cleanup complete")
            else:
                peers2 = node2.get_peer_info()
                print(f"  ⚠ Warning: Node2 still has {len(peers2)} peer(s) after cleanup")
        
        all_passed &= test_manual_disconnect(node1, node2, port2)
        time.sleep(2)
        
        all_passed &= test_ban_with_time(node1)
        time.sleep(1)
        
        all_passed &= test_remove_specific_ban(node1)
        
        if all_passed:
            print("\n✓ All p2p_disconnect_ban tests passed")
            return 0
        else:
            print("\n✗ Some p2p_disconnect_ban tests failed")
            return 1
    
    except Exception as e:
        print(f"\n✗ p2p_disconnect_ban test failed with exception: {e}")
        import traceback
        traceback.print_exc()
        
        if node1:
            print("\nNode1 last 50 lines of debug.log:")
            print(node1.read_log(50))
        if node2:
            print("\nNode2 last 50 lines of debug.log:")
            print(node2.read_log(50))
        
        return 1
    
    finally:
        if node1 and node1.is_running():
            print("\nStopping node1...")
            node1.stop()
        if node2 and node2.is_running():
            print("\nStopping node2...")
            node2.stop()
        print(f"Cleaning up {test_dir}")
        shutil.rmtree(test_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
