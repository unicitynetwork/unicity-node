#!/usr/bin/env python3
"""Utility functions for functional tests."""

import time
import socket


def assert_equal(actual, expected, message=""):
    """Assert that two values are equal."""
    if actual != expected:
        if message:
            raise AssertionError(f"{message}: expected {expected}, got {actual}")
        else:
            raise AssertionError(f"Expected {expected}, got {actual}")


def wait_until(predicate, timeout=10, check_interval=0.5):
    """
    Wait until a predicate returns True.

    Args:
        predicate: Callable that returns True when condition is met
        timeout: Maximum time to wait in seconds
        check_interval: Time between checks in seconds

    Returns:
        True if condition met, False if timeout
    """
    start_time = time.time()
    while time.time() - start_time < timeout:
        if predicate():
            return True
        time.sleep(check_interval)
    return False


def connect_nodes(node_from, node_to):
    """
    Connect two test nodes.

    Args:
        node_from: TestNode that initiates connection
        node_to: TestNode to connect to

    Returns:
        True if connection successful
    """
    # Get node_to's listening address
    # For now, nodes only support outbound connections in regtest
    # This will be enhanced when we add P2P listening support
    try:
        node_from.add_node(f"127.0.0.1:{9000 + node_to.index}")
        return True
    except Exception as e:
        print(f"Failed to connect nodes: {e}")
        return False


def sync_blocks(nodes, timeout=60):
    """
    Wait for all nodes to have the same best block.

    Args:
        nodes: List of TestNode instances
        timeout: Maximum time to wait in seconds

    Returns:
        True if synced, False if timeout
    """
    def all_synced():
        heights = []
        hashes = []
        for node in nodes:
            try:
                info = node.get_info()
                heights.append(info.get("height", -1))
                hashes.append(info.get("bestblockhash", ""))
            except Exception:
                return False

        # All heights must be equal and all hashes must be equal
        return len(set(heights)) == 1 and len(set(hashes)) == 1

    return wait_until(all_synced, timeout=timeout)


def wait_for_peers(node, peer_count, timeout=10):
    """
    Wait for node to have a specific number of peers.

    Args:
        node: TestNode instance
        peer_count: Expected number of peers
        timeout: Maximum time to wait in seconds

    Returns:
        True if peer count reached, False if timeout
    """
    def has_peers():
        try:
            peers = node.get_peer_info()
            return len(peers) >= peer_count
        except Exception:
            return False

    return wait_until(has_peers, timeout=timeout)


def pick_free_port():
    """Return an available localhost TCP port.

    Note: best-effort; there is a small race between returning the value and
    a test using it. Keep allocation and use close together to reduce risk.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# Default Unicity regtest P2P base port (see include/network/protocol.hpp)
REGTEST_BASE_PORT = 29590

def regtest_base_port():
    return REGTEST_BASE_PORT
