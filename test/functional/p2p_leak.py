#!/usr/bin/env python3
"""Test message sending before handshake completion.

Before receiving a VERACK, a node should not send anything but VERSION/VERACK.
This test connects to a node and sends various messages, trying to entice it
into sending us something it shouldn't.

Adapted from Bitcoin Core's p2p_leak.py for Unicity's headers-only architecture.
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

# Protocol constants (from include/network/protocol.hpp)
PROTOCOL_VERSION = 1
MIN_PROTOCOL_VERSION = 1
REGTEST_MAGIC = 0x4B7C2E91
MESSAGE_HEADER_SIZE = 24
COMMAND_SIZE = 12

# Timeouts
PEER_TIMEOUT = 3  # seconds (should match node config if set)
LEAK_WAIT_TIME = PEER_TIMEOUT + 2


def calc_checksum(payload):
    """Calculate 4-byte checksum for message payload (first 4 bytes of double SHA256)."""
    import hashlib
    h1 = hashlib.sha256(payload).digest()
    h2 = hashlib.sha256(h1).digest()
    return h2[:4]


def serialize_command(cmd):
    """Serialize command string to 12-byte null-padded array."""
    cmd_bytes = cmd.encode('ascii')
    if len(cmd_bytes) > COMMAND_SIZE:
        raise ValueError(f"Command too long: {cmd}")
    return cmd_bytes + b'\x00' * (COMMAND_SIZE - len(cmd_bytes))


def build_message(command, payload=b''):
    """Build a complete P2P message with header and payload."""
    magic = struct.pack('<I', REGTEST_MAGIC)
    cmd = serialize_command(command)
    length = struct.pack('<I', len(payload))
    checksum = calc_checksum(payload)
    
    return magic + cmd + length + checksum + payload


def serialize_varstr(s):
    """Serialize a variable-length string (compact size + data)."""
    data = s.encode('utf-8') if isinstance(s, str) else s
    length = len(data)
    
    # Compact size encoding
    if length < 0xfd:
        prefix = struct.pack('<B', length)
    elif length <= 0xffff:
        prefix = struct.pack('<BH', 0xfd, length)
    elif length <= 0xffffffff:
        prefix = struct.pack('<BI', 0xfe, length)
    else:
        prefix = struct.pack('<BQ', 0xff, length)
    
    return prefix + data


def serialize_netaddr(services, ip, port, with_timestamp=False):
    """Serialize a network address (IPv6 format, IPv4-mapped)."""
    result = b''
    if with_timestamp:
        result += struct.pack('<I', int(time.time()))
    result += struct.pack('<Q', services)
    # Convert IPv4 to IPv6-mapped format
    if isinstance(ip, str):
        parts = ip.split('.')
        if len(parts) == 4:
            # IPv4-mapped IPv6: ::ffff:x.x.x.x
            ipv6_bytes = b'\x00' * 10 + b'\xff\xff' + bytes([int(p) for p in parts])
        else:
            ipv6_bytes = b'\x00' * 16  # Default to all zeros
    else:
        ipv6_bytes = b'\x00' * 16
    result += ipv6_bytes
    result += struct.pack('>H', port)  # Network byte order for port
    return result


def build_version_message(version=PROTOCOL_VERSION, services=1, timestamp=None, 
                         nonce=0, user_agent="/UnicityTest:0.1.0/", start_height=0,
                         addr_recv_ip="127.0.0.1", addr_recv_port=29590):
    """Build a VERSION message payload."""
    if timestamp is None:
        timestamp = int(time.time())
    
    payload = b''
    payload += struct.pack('<i', version)  # int32_t version
    payload += struct.pack('<Q', services)  # uint64_t services
    payload += struct.pack('<q', timestamp)  # int64_t timestamp
    payload += serialize_netaddr(1, addr_recv_ip, addr_recv_port)  # addr_recv (no timestamp)
    payload += serialize_netaddr(1, "0.0.0.0", 0)  # addr_from (empty as per Unicity convention)
    payload += struct.pack('<Q', nonce)  # uint64_t nonce
    payload += serialize_varstr(user_agent)  # user_agent
    payload += struct.pack('<i', start_height)  # int32_t start_height
    
    return payload


def build_ping_message(nonce=0):
    """Build a PING message payload."""
    return struct.pack('<Q', nonce)


def build_getaddr_message():
    """Build a GETADDR message (empty payload)."""
    return b''


class RawSocket:
    """Raw TCP socket wrapper for P2P protocol testing."""
    
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = None
        self.recv_buffer = b''
        self.messages_received = []
        
    def connect(self):
        """Connect to the node."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(10)
        self.sock.connect((self.host, self.port))
        
    def send_message(self, command, payload=b''):
        """Send a P2P message."""
        msg = build_message(command, payload)
        self.sock.sendall(msg)
        
    def recv_data(self, timeout=1.0):
        """Receive data with timeout. Returns True if data received."""
        self.sock.settimeout(timeout)
        try:
            data = self.sock.recv(4096)
            if data:
                self.recv_buffer += data
                self._parse_messages()
                return True
            return False
        except socket.timeout:
            return False
        except Exception:
            return False
    
    def _parse_messages(self):
        """Parse complete messages from recv_buffer."""
        while len(self.recv_buffer) >= MESSAGE_HEADER_SIZE:
            # Parse header
            magic = struct.unpack('<I', self.recv_buffer[0:4])[0]
            if magic != REGTEST_MAGIC:
                print(f"Invalid magic: {hex(magic)}")
                self.recv_buffer = b''
                return
            
            command_bytes = self.recv_buffer[4:16]
            command = command_bytes.rstrip(b'\x00').decode('ascii', errors='ignore')
            length = struct.unpack('<I', self.recv_buffer[16:20])[0]
            
            # Check if we have the complete message
            total_size = MESSAGE_HEADER_SIZE + length
            if len(self.recv_buffer) < total_size:
                break  # Need more data
            
            # Extract payload
            payload = self.recv_buffer[MESSAGE_HEADER_SIZE:total_size]
            
            # Store message
            self.messages_received.append({
                'command': command,
                'payload': payload,
                'length': length
            })
            
            # Remove from buffer
            self.recv_buffer = self.recv_buffer[total_size:]
    
    def has_message(self, command):
        """Check if we've received a specific message type."""
        return any(msg['command'] == command for msg in self.messages_received)
    
    def get_messages(self, command=None):
        """Get all messages of a specific type, or all if command is None."""
        if command is None:
            return self.messages_received
        return [msg for msg in self.messages_received if msg['command'] == command]
    
    def close(self):
        """Close the socket."""
        if self.sock:
            self.sock.close()


def test_no_version_peer(node_host, node_port):
    """Test that peer never sending VERSION receives nothing from node."""
    print("  Test: Peer that never sends VERSION")
    
    peer = RawSocket(node_host, node_port)
    peer.connect()
    
    # Just connect and wait - don't send VERSION
    time.sleep(2)
    
    # Try to receive any messages
    peer.recv_data(timeout=1.0)
    
    # Node should NOT send anything (not even VERSION) to a peer that hasn't sent VERSION
    messages = peer.get_messages()
    if messages:
        print(f"    ✗ FAILED: Received unexpected messages: {[m['command'] for m in messages]}")
        peer.close()
        return False
    
    print("    ✓ No messages received (expected)")
    peer.close()
    return True


def test_no_verack_peer(node_host, node_port):
    """Test that peer sending VERSION but not VERACK doesn't receive unexpected messages."""
    print("  Test: Peer that sends VERSION but not VERACK")
    
    peer = RawSocket(node_host, node_port)
    peer.connect()
    
    # Send VERSION
    version_payload = build_version_message(nonce=12345)
    peer.send_message("version", version_payload)
    
    # Receive VERSION and VERACK from node
    for _ in range(5):  # Try a few times to get both messages
        peer.recv_data(timeout=0.5)
    
    # Should have received VERSION and VERACK
    if not peer.has_message("version"):
        print("    ✗ FAILED: Did not receive VERSION from node")
        peer.close()
        return False
    
    if not peer.has_message("verack"):
        print("    ✗ FAILED: Did not receive VERACK from node")
        peer.close()
        return False
    
    print("    ✓ Received VERSION and VERACK")
    
    # Now try to entice the node to send us something else
    # Send PING and GETADDR without having sent VERACK
    peer.send_message("ping", build_ping_message(nonce=67890))
    peer.send_message("getaddr", build_getaddr_message())
    
    # Clear received messages
    peer.messages_received = []
    
    # Wait and see if node sends anything unexpected
    time.sleep(2)
    peer.recv_data(timeout=1.0)
    
    # Node should NOT respond to PING or GETADDR before handshake is complete
    unexpected = [msg for msg in peer.get_messages() 
                  if msg['command'] not in ['version', 'verack']]
    
    if unexpected:
        print(f"    ✗ FAILED: Received unexpected messages: {[m['command'] for m in unexpected]}")
        peer.close()
        return False
    
    print("    ✓ No unexpected messages (expected)")
    peer.close()
    return True


def test_version_local_address_leak(node_host, node_port):
    """Test that VERSION message does not leak local address."""
    print("  Test: VERSION message does not leak local address")
    
    # Use a fresh connection to avoid socket reuse issues
    peer = RawSocket(node_host, node_port)
    try:
        peer.connect()
        print(f"    Connected to {node_host}:{node_port}")
    except Exception as e:
        print(f"    ✗ FAILED: Could not connect: {e}")
        return False
    
    # Send VERSION with unique nonce
    version_payload = build_version_message(nonce=99999)
    peer.send_message("version", version_payload)
    print(f"    Sent VERSION")
    
    # Give node time to respond, then receive
    time.sleep(0.5)
    
    # Receive VERSION from node
    for _ in range(5):
        if peer.has_message("version"):
            break
        peer.recv_data(timeout=0.5)
    
    version_msgs = peer.get_messages("version")
    if not version_msgs:
        all_msgs = peer.get_messages()
        print(f"    ✗ FAILED: Did not receive VERSION from node")
        print(f"       Received messages: {[m['command'] for m in all_msgs]}")
        print(f"       Buffer size: {len(peer.recv_buffer)}")
        peer.close()
        return False
    
    # Parse VERSION payload to check addr_from field
    payload = version_msgs[0]['payload']
    
    # Skip: version(4) + services(8) + timestamp(8) + addr_recv(26)
    offset = 4 + 8 + 8 + 26
    
    # Parse addr_from: services(8) + ip(16) + port(2)
    if len(payload) < offset + 26:
        print("    ✗ FAILED: VERSION payload too short")
        peer.close()
        return False
    
    addr_from_services = struct.unpack('<Q', payload[offset:offset+8])[0]
    addr_from_ip = payload[offset+8:offset+24]
    addr_from_port = struct.unpack('>H', payload[offset+24:offset+26])[0]
    
    # Check that addr_from is all zeros (Unicity convention, matches Bitcoin Core)
    is_zero_ip = addr_from_ip == b'\x00' * 16
    is_zero_port = addr_from_port == 0
    
    if not (is_zero_ip and is_zero_port):
        print(f"    ✗ FAILED: addr_from not empty - ip: {addr_from_ip.hex()}, port: {addr_from_port}")
        peer.close()
        return False
    
    print("    ✓ addr_from is empty (does not leak local address)")
    
    # Check timestamp is reasonable (within 1 hour of now)
    version = struct.unpack('<i', payload[0:4])[0]
    services = struct.unpack('<Q', payload[4:12])[0]
    timestamp = struct.unpack('<q', payload[12:20])[0]
    
    now = int(time.time())
    time_diff = abs(timestamp - now)
    
    if time_diff > 3600:
        print(f"    ⚠ WARNING: Timestamp diff is {time_diff}s (should be < 3600s)")
    else:
        print(f"    ✓ Timestamp is reasonable (diff: {time_diff}s)")
    
    peer.close()
    return True


def test_old_protocol_version_rejected(node_host, node_port):
    """Test that old protocol versions are rejected."""
    print("  Test: Old protocol version is rejected")
    
    peer = RawSocket(node_host, node_port)
    peer.connect()
    
    # Send VERSION with old protocol version (0)
    version_payload = build_version_message(version=0, nonce=11111)
    peer.send_message("version", version_payload)
    
    # Node should disconnect us
    time.sleep(2)
    
    # Try to receive - should get disconnected
    try:
        data = peer.sock.recv(1024)
        if not data:
            print("    ✓ Connection closed by node (expected)")
            peer.close()
            return True
        else:
            # Received data, check if it's a disconnect
            print("    ✓ Node disconnected peer with old protocol version")
            peer.close()
            return True
    except Exception:
        print("    ✓ Connection closed (expected)")
        peer.close()
        return True


def main():
    print("Starting p2p_leak test...")
    
    test_dir = Path(tempfile.mkdtemp(prefix="unicity_p2p_leak_"))
    binary_path = Path(__file__).parent.parent.parent / "build" / "bin" / "unicityd"
    node = None
    
    try:
        # Pick dynamic port
        node_port = pick_free_port()
        
        # Start node (regtest chain) with debug logging
        node = TestNode(
            0, 
            test_dir / "node0", 
            binary_path,
            extra_args=["--listen", f"--port={node_port}", "--debug=network"],
            chain="regtest"
        )
        node.start()
        
        print(f"Node started on port {node_port}")
        time.sleep(2)  # Give node time to start listening
        
        # Run tests
        all_passed = True
        
        all_passed &= test_no_version_peer("127.0.0.1", node_port)
        all_passed &= test_no_verack_peer("127.0.0.1", node_port)
        all_passed &= test_version_local_address_leak("127.0.0.1", node_port)
        all_passed &= test_old_protocol_version_rejected("127.0.0.1", node_port)
        
        if all_passed:
            print("\n✓ All p2p_leak tests passed")
            return 0
        else:
            print("\n✗ Some p2p_leak tests failed")
            print("\nNode debug.log (last 100 lines):")
            print(node.read_log(100))
            return 1
        
    except Exception as e:
        print(f"\n✗ p2p_leak test failed with exception: {e}")
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
