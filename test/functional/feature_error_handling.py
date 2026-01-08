#!/usr/bin/env python3
# Copyright (c) 2025 The Unicity Foundation
# Distributed under the MIT software license

"""Test error handling and unhappy path scenarios (strict)."""

from test_framework.test_node import TestNode
from test_framework.util import pick_free_port
import os
import time
import signal
import tempfile
import shutil


def test_port_conflict():
    """Second instance on same port must fail deterministically."""
    datadir1 = tempfile.mkdtemp(prefix="unicity_port1_")
    datadir2 = tempfile.mkdtemp(prefix="unicity_port2_")

    try:
        port = pick_free_port()
        node1 = TestNode(1, datadir=datadir1, extra_args=["--regtest", f"--port={port}"])
        node1.start()
        time.sleep(1)  # Let it bind

        node2 = TestNode(2, datadir=datadir2, extra_args=["--regtest", f"--port={port}"])
        failed = False
        try:
            node2.start()
        except Exception:
            failed = True
        assert failed, "node2 should fail to start due to port conflict"
        assert node1.is_running(), "node1 should still be running after node2 failure"
        node1.stop()
    finally:
        shutil.rmtree(datadir1, ignore_errors=True)
        shutil.rmtree(datadir2, ignore_errors=True)


def test_readonly_datadir():
    """Node should not crash with readonly datadir (starts successfully)."""
    datadir = tempfile.mkdtemp(prefix="unicity_readonly_")

    try:
        # Make datadir readonly (rx only for traversal)
        os.chmod(datadir, 0o555)
        node = TestNode(1, datadir=datadir, extra_args=["--regtest", f"--port={pick_free_port()}"])

        # With the updated error handling, a readonly datadir is tolerated:
        # the node should either log a clear error or fall back internally,
        # but must not crash during startup.
        node.start()
        assert node.is_running(), "Node failed to stay running with readonly datadir"

        # Basic sanity check that RPC works in this configuration.
        info = node.get_info()
        assert isinstance(info, dict), "get_info() did not return expected JSON object"
    finally:
        # Ensure we can clean up even if start() raised unexpectedly on some platforms.
        try:
            os.chmod(datadir, 0o755)  # Restore for cleanup
        except Exception:
            pass
        shutil.rmtree(datadir, ignore_errors=True)


def test_rapid_start_stop():
    """Rapid start/stop cycles complete without crash (strict asserts)."""
    datadir = tempfile.mkdtemp(prefix="unicity_rapid_")

    try:
        base_port = pick_free_port()
        for i in range(5):
            node = TestNode(1, datadir=datadir, extra_args=["--regtest", f"--port={base_port+i}"])
            node.start()
            assert node.is_running(), f"Node not running on cycle {i+1}"
            time.sleep(0.3)
            node.stop()
            assert not node.is_running(), f"Node did not stop on cycle {i+1}"
            time.sleep(0.2)
    finally:
        shutil.rmtree(datadir, ignore_errors=True)


def test_signal_handling():
    """SIGINT must yield clean shutdown (exit 0 or 130)."""
    datadir = tempfile.mkdtemp(prefix="unicity_signal_")

    try:
        node = TestNode(1, datadir=datadir, extra_args=["--regtest", f"--port={pick_free_port()}"])
        node.start()
        time.sleep(1)
        node.send_signal(signal.SIGINT)
        exit_code = node.wait_for_exit(timeout=10)
        assert exit_code in (0, 130), f"Unexpected exit code: {exit_code}"
    finally:
        shutil.rmtree(datadir, ignore_errors=True)


def test_corrupted_anchor_file():
    """Corrupted anchors.json must not crash node (starts and runs)."""
    datadir = tempfile.mkdtemp(prefix="unicity_corrupt_")

    try:
        os.makedirs(datadir, exist_ok=True)
        with open(os.path.join(datadir, "anchors.json"), "w") as f:
            f.write("not valid json{{{")
        node = TestNode(1, datadir=datadir, extra_args=["--regtest", f"--port={pick_free_port()}"])
        node.start()
        time.sleep(1)
        assert node.is_running(), "Node failed to start with corrupted anchors.json"
        node.stop()
    finally:
        shutil.rmtree(datadir, ignore_errors=True)


if __name__ == "__main__":
    print("=== Unicity Error Handling Test Suite (strict) ===")
    test_port_conflict()
    test_readonly_datadir()
    test_rapid_start_stop()
    test_signal_handling()
    test_corrupted_anchor_file()
    print("\n=== All tests completed ===")
