#!/usr/bin/env python3
"""Test P2P invalid message handling.

Tests node behavior when receiving invalid/malformed P2P messages:
1. Wrong magic bytes -> disconnect
2. Bad checksum -> disconnect
3. Oversized message -> disconnect
4. Unknown command -> ignored (not disconnect)
5. Empty payload for messages that require data -> disconnect
6. Non-empty payload for messages that must be empty -> disconnect
7. Sending non-VERSION as first message -> ignored (matches Bitcoin Core net_processing.cpp:3657-3660)
8. Sending HEADERS before VERACK -> ignored (peer stays connected, message not processed)

Adapted from Bitcoin Core's p2p_invalid_messages.py for Unicity.
"""

import sys
import socket
import struct
import time
import tempfile
import shutil
from pathlib import Path

# Add test framework to path
sys.path.insert(0, str(Path(__file__).parent / "test_framework"))

from test_node import TestNode
from util import pick_free_port

# Protocol constants
REGTEST_MAGIC = 0x4B7C2E91
MAINNET_MAGIC = 0x554E4943  # "UNIC"
MESSAGE_HEADER_SIZE = 24
MAX_PROTOCOL_MESSAGE_LENGTH = 8010000  # 8.01MB - fits MAX_HEADERS_SIZE (must match protocol.hpp)


def calc_checksum(payload):
    """Calculate 4-byte checksum for message payload."""
    import hashlib
    h1 = hashlib.sha256(payload).digest()
    h2 = hashlib.sha256(h1).digest()
    return h2[:4]


def serialize_command(cmd):
    """Serialize command string to 12-byte null-padded array."""
    cmd_bytes = cmd.encode('ascii')
    return cmd_bytes + b'\x00' * (12 - len(cmd_bytes))


def build_message(magic, command, payload=b'', bad_checksum=False):
    """Build a complete P2P message."""
    magic_bytes = struct.pack('<I', magic)
    cmd_bytes = serialize_command(command)
    length_bytes = struct.pack('<I', len(payload))
    
    if bad_checksum:
        checksum = b'\xff\xff\xff\xff'  # Invalid checksum
    else:
        checksum = calc_checksum(payload)
    
    return magic_bytes + cmd_bytes + length_bytes + checksum + payload


def build_version_message(nonce=0, port=29590, user_agent=b'/UnicityTest:0.1/'):
    """Build a VERSION message payload."""
    payload = b''
    payload += struct.pack('<i', 1)  # version
    payload += struct.pack('<Q', 1)  # services  
    payload += struct.pack('<q', int(time.time()))  # timestamp
    # addr_recv
    payload += struct.pack('<Q', 1)
    payload += b'\x00' * 10 + b'\xff\xff' + bytes([127,0,0,1])
    payload += struct.pack('>H', port)
    # addr_from
    payload += struct.pack('<Q', 0)
    payload += b'\x00' * 16
    payload += struct.pack('>H', 0)
    payload += struct.pack('<Q', nonce)
    # user_agent
    payload += bytes([len(user_agent)]) + user_agent
    payload += struct.pack('<i', 0)  # start_height
    return payload


def build_ping_message(nonce=0):
    """Build a PING message payload."""
    return struct.pack('<Q', nonce)


class P2PConnection:
    """Simple P2P connection for testing."""
    
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = None
        
    def connect(self):
        """Connect to node."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(5)
        self.sock.connect((self.host, self.port))
        
    def send_raw(self, data):
        """Send raw bytes."""
        self.sock.sendall(data)
        
    def send_message(self, magic, command, payload=b'', bad_checksum=False):
        """Send a P2P message."""
        msg = build_message(magic, command, payload, bad_checksum)
        self.send_raw(msg)
        
    def is_connected(self):
        """Check if still connected."""
        try:
            self.sock.settimeout(0.1)
            data = self.sock.recv(1, socket.MSG_PEEK | socket.MSG_DONTWAIT)
            if len(data) == 0:
                return False  # EOF = disconnected
            return True
        except BlockingIOError:
            return True  # No data but still connected
        except socket.timeout:
            return True  # No data but still connected
        except (ConnectionResetError, BrokenPipeError, OSError):
            return False
            
    def wait_for_disconnect(self, timeout=5):
        """Wait for peer to be disconnected."""
        start = time.time()
        while time.time() - start < timeout:
            if not self.is_connected():
                return True
            time.sleep(0.2)
        return False
        
    def close(self):
        """Close connection."""
        if self.sock:
            try:
                self.sock.close()
            except:
                pass


def test_wrong_magic(host, port):
    """Test that wrong magic bytes cause disconnect."""
    print("  Test: Wrong magic bytes")
    
    conn = P2PConnection(host, port)
    conn.connect()
    
    # Send VERSION with mainnet magic instead of regtest
    version_payload = build_version_message(nonce=12345)
    conn.send_message(MAINNET_MAGIC, "version", version_payload)
    
    # Should be disconnected
    if conn.wait_for_disconnect(timeout=5):
        print("    ✓ Disconnected after wrong magic")
        conn.close()
        return True
    else:
        print("    ✗ FAILED: Not disconnected after wrong magic")
        conn.close()
        return False


def test_bad_checksum(host, port):
    """Test that bad checksum causes disconnect."""
    print("  Test: Bad checksum")
    
    conn = P2PConnection(host, port)
    conn.connect()
    
    # Send VERSION with bad checksum
    version_payload = build_version_message(nonce=23456)
    conn.send_message(REGTEST_MAGIC, "version", version_payload, bad_checksum=True)
    
    # Should be disconnected
    if conn.wait_for_disconnect(timeout=5):
        print("    ✓ Disconnected after bad checksum")
        conn.close()
        return True
    else:
        print("    ✗ FAILED: Not disconnected after bad checksum")
        conn.close()
        return False


def test_oversized_message(host, port):
    """Test that oversized message causes disconnect."""
    print("  Test: Oversized message")
    
    conn = P2PConnection(host, port)
    conn.connect()
    
    # Send message with length > MAX_PROTOCOL_MESSAGE_LENGTH
    magic_bytes = struct.pack('<I', REGTEST_MAGIC)
    cmd_bytes = serialize_command("version")
    bad_length = MAX_PROTOCOL_MESSAGE_LENGTH + 1
    length_bytes = struct.pack('<I', bad_length)
    checksum = b'\x00\x00\x00\x00'
    
    # Just send header (don't send actual payload - would take too long)
    header = magic_bytes + cmd_bytes + length_bytes + checksum
    conn.send_raw(header)
    
    # Should be disconnected
    if conn.wait_for_disconnect(timeout=5):
        print("    ✓ Disconnected after oversized message")
        conn.close()
        return True
    else:
        print("    ✗ FAILED: Not disconnected after oversized message")
        conn.close()
        return False


def test_unknown_command(host, port):
    """Test that unknown command is handled gracefully."""
    print("  Test: Unknown command")
    
    conn = P2PConnection(host, port)
    conn.connect()
    
    # First complete handshake
    version_payload = build_version_message(nonce=34567)
    conn.send_message(REGTEST_MAGIC, "version", version_payload)
    time.sleep(0.5)
    
    # Receive VERSION and VERACK from node
    try:
        conn.sock.settimeout(2.0)
        data = conn.sock.recv(4096)
        if not data:
            print("    ✗ FAILED: No response from node")
            conn.close()
            return False
    except (socket.timeout, ConnectionResetError, BrokenPipeError):
        if not conn.is_connected():
            print("    ✗ FAILED: Disconnected during handshake")
            conn.close()
            return False
        print("    ✗ FAILED: Connection issue during handshake")
        conn.close()
        return False
    
    # Send VERACK to complete handshake
    conn.send_message(REGTEST_MAGIC, "verack", b'')
    time.sleep(0.5)
    
    # Now send unknown command
    conn.send_message(REGTEST_MAGIC, "notacommand", b'')
    time.sleep(1)
    
    # Should NOT be disconnected (unknown commands are ignored per Bitcoin Core)
    if conn.is_connected():
        print("    ✓ Still connected after unknown command (matches Bitcoin Core)")
        conn.close()
        return True
    else:
        print("    ✗ FAILED: Disconnected after unknown command")
        conn.close()
        return False


def test_verack_with_payload(host, port):
    """Test that VERACK with non-empty payload causes disconnect."""
    print("  Test: VERACK with payload")
    
    conn = P2PConnection(host, port)
    conn.connect()
    
    # Send VERSION
    version_payload = build_version_message(nonce=45678)
    conn.send_message(REGTEST_MAGIC, "version", version_payload)
    time.sleep(0.5)
    
    # Receive node's response (may disconnect immediately after seeing VERSION)
    try:
        conn.sock.settimeout(2.0)
        data = conn.sock.recv(4096)
    except (socket.timeout, ConnectionResetError, BrokenPipeError):
        # Node might have disconnected already
        if not conn.is_connected():
            print("    ✓ Disconnected before VERACK (early detection)")
            conn.close()
            return True
        print("    ✗ FAILED: Connection issue before VERACK")
        conn.close()
        return False
    
    # Send VERACK with invalid payload
    try:
        conn.send_message(REGTEST_MAGIC, "verack", b'\x00\x01\x02\x03')
    except (BrokenPipeError, ConnectionResetError):
        print("    ✓ Disconnected when sending VERACK with payload")
        conn.close()
        return True
    
    # Should be disconnected
    if conn.wait_for_disconnect(timeout=5):
        print("    ✓ Disconnected after VERACK with payload")
        conn.close()
        return True
    else:
        print("    ✗ FAILED: Not disconnected after VERACK with payload")
        conn.close()
        return False


def test_ping_without_payload(host, port):
    """Test that PING without payload (invalid) causes disconnect."""
    print("  Test: PING without payload")
    
    conn = P2PConnection(host, port)
    conn.connect()
    
    # Complete handshake first
    version_payload = build_version_message(nonce=56789)
    conn.send_message(REGTEST_MAGIC, "version", version_payload)
    time.sleep(0.5)
    
    try:
        conn.sock.settimeout(2.0)
        data = conn.sock.recv(4096)
    except (socket.timeout, ConnectionResetError, BrokenPipeError):
        if not conn.is_connected():
            print("    ✓ Disconnected before completing handshake (early detection)")
            conn.close()
            return True
        print("    ✗ FAILED: Connection issue during handshake")
        conn.close()
        return False
    
    try:
        conn.send_message(REGTEST_MAGIC, "verack", b'')
    except (BrokenPipeError, ConnectionResetError):
        print("    ✓ Disconnected when sending VERACK")
        conn.close()
        return True
    time.sleep(0.5)
    
    # Send PING with empty payload (should have 8-byte nonce)
    try:
        conn.send_message(REGTEST_MAGIC, "ping", b'')
    except (BrokenPipeError, ConnectionResetError):
        print("    ✓ Disconnected when sending empty PING")
        conn.close()
        return True
    
    # Should be disconnected
    if conn.wait_for_disconnect(timeout=5):
        print("    ✓ Disconnected after PING without payload")
        conn.close()
        return True
    else:
        print("    ✗ FAILED: Not disconnected after PING without payload")
        conn.close()
        return False


def test_non_version_first_message(host, port):
    """Test that sending non-VERSION as first message is ignored (not disconnect).

    Bitcoin Core behavior: net_processing.cpp:3657-3660 - logs and returns without disconnecting.
    The message is silently ignored and peer stays connected waiting for VERSION.
    """
    print("  Test: Non-VERSION as first message (should be ignored)")

    conn = P2PConnection(host, port)
    conn.connect()

    # Send PING as first message (should be VERSION)
    ping_payload = build_ping_message(nonce=67890)
    conn.send_message(REGTEST_MAGIC, "ping", ping_payload)

    # Node should NOT disconnect - message is silently ignored
    # Wait briefly to verify no PONG comes back and connection stays open
    time.sleep(1.0)

    if conn.is_connected():
        # Verify no PONG response (message was ignored)
        try:
            conn.sock.settimeout(0.5)
            data = conn.sock.recv(1024)
            if data:
                print("    ✗ FAILED: Received unexpected response (should be ignored)")
                conn.close()
                return False
        except socket.timeout:
            pass  # Expected - no response
        except (ConnectionResetError, BrokenPipeError):
            print("    ✗ FAILED: Connection was reset")
            conn.close()
            return False

        print("    ✓ Message ignored, connection stayed open (matches Bitcoin Core)")
        conn.close()
        return True
    else:
        print("    ✗ FAILED: Disconnected (should stay connected and ignore message)")
        conn.close()
        return False


def test_headers_before_verack(host, port):
    """Test that sending HEADERS before VERACK is ignored (not disconnect).

    After VERSION exchange but before VERACK, protocol messages are silently
    ignored. The peer stays connected and can complete handshake normally.
    """
    print("  Test: HEADERS before VERACK (should be ignored)")

    conn = P2PConnection(host, port)
    conn.connect()

    # Send VERSION to start handshake
    version_payload = build_version_message(nonce=78901)
    conn.send_message(REGTEST_MAGIC, "version", version_payload)
    time.sleep(0.5)

    # Receive node's VERSION/VERACK response
    try:
        conn.sock.settimeout(2.0)
        data = conn.sock.recv(4096)
        if not data:
            print("    ✗ FAILED: No response from node")
            conn.close()
            return False
    except (socket.timeout, ConnectionResetError, BrokenPipeError):
        if not conn.is_connected():
            print("    ✗ FAILED: Disconnected during handshake")
            conn.close()
            return False
        print("    ✗ FAILED: Connection issue during handshake")
        conn.close()
        return False

    # DO NOT send VERACK - instead send HEADERS (should be ignored)
    # Empty headers message (just the count = 0)
    headers_payload = b'\x00'  # CompactSize = 0 headers
    try:
        conn.send_message(REGTEST_MAGIC, "headers", headers_payload)
    except (BrokenPipeError, ConnectionResetError):
        print("    ✗ FAILED: Disconnected when sending HEADERS")
        conn.close()
        return False

    # Node should NOT disconnect - message is silently ignored
    time.sleep(1.0)

    if conn.is_connected():
        print("    ✓ HEADERS ignored, connection stayed open (can complete handshake)")
        conn.close()
        return True
    else:
        print("    ✗ FAILED: Disconnected (should stay connected and ignore message)")
        conn.close()
        return False


def main():
    print("Starting p2p_invalid_messages test...")
    
    test_dir = Path(tempfile.mkdtemp(prefix="unicity_p2p_invalid_"))
    binary_path = Path(__file__).parent.parent.parent / "build" / "bin" / "unicityd"
    node = None
    
    try:
        node_port = pick_free_port()
        
        # Start node
        node = TestNode(
            0,
            test_dir / "node0",
            binary_path,
            extra_args=["--listen", f"--port={node_port}"],
            chain="regtest"
        )
        node.start()
        
        print(f"Node started on port {node_port}")
        time.sleep(2)
        
        # Run tests
        all_passed = True

        all_passed &= test_unknown_command("127.0.0.1", node_port)
        time.sleep(2)

        all_passed &= test_wrong_magic("127.0.0.1", node_port)
        time.sleep(2)

        all_passed &= test_bad_checksum("127.0.0.1", node_port)
        time.sleep(2)

        all_passed &= test_oversized_message("127.0.0.1", node_port)
        time.sleep(2)

        all_passed &= test_non_version_first_message("127.0.0.1", node_port)
        time.sleep(2)

        all_passed &= test_headers_before_verack("127.0.0.1", node_port)
        time.sleep(2)

        all_passed &= test_verack_with_payload("127.0.0.1", node_port)
        time.sleep(2)

        all_passed &= test_ping_without_payload("127.0.0.1", node_port)
        
        if all_passed:
            print("\n✓ All p2p_invalid_messages tests passed")
            return 0
        else:
            print("\n✗ Some p2p_invalid_messages tests failed")
            return 1
    
    except Exception as e:
        print(f"\n✗ p2p_invalid_messages test failed with exception: {e}")
        import traceback
        traceback.print_exc()
        
        if node:
            print("\nNode last 50 lines of debug.log:")
            print(node.read_log(50))
        
        return 1
    
    finally:
        if node and node.is_running():
            print("\nStopping node...")
            node.stop()
        print(f"Cleaning up {test_dir}")
        shutil.rmtree(test_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
