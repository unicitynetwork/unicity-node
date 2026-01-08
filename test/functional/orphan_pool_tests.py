#!/usr/bin/env python3
"""Orphan pool tests using test RPCs.

Covers:
- Adding orphan headers from different peer_ids
- Inspecting orphan stats (count and by_peer)
- Evicting via expiry by advancing mock time
- Manual eviction call
"""

import sys
import tempfile
import shutil
from pathlib import Path
import struct

# Add test framework to path
sys.path.insert(0, str(Path(__file__).parent / "test_framework"))
from test_node import TestNode


def u32le(n: int) -> bytes:
    import struct as _s
    return _s.pack('<I', n & 0xFFFFFFFF)


def hex_to_le32(hex_str: str) -> bytes:
    b = bytes.fromhex(hex_str)
    if len(b) != 32:
        raise ValueError("hash must be 32 bytes")
    return b[::-1]


def build_header_hex(prev_hash_hex_be: str, n_time: int, n_bits_u32: int, n_nonce: int = 0, version: int = 1) -> str:
    prev_le = hex_to_le32(prev_hash_hex_be)
    miner = b"\x00" * 20
    rx = b"\x00" * 32
    header = b"".join([
        u32le(version),
        prev_le,
        miner,
        u32le(n_time),
        u32le(n_bits_u32),
        u32le(n_nonce),
        rx,
    ])
    assert len(header) == 100
    return header.hex()


def main():
    print("Starting orphan_pool_tests...")

    test_dir = Path(tempfile.mkdtemp(prefix="unicity_orphan_tests_"))
    binary_path = Path(__file__).parent.parent.parent / "build" / "bin" / "unicityd"

    node = None
    try:
        node = TestNode(0, test_dir / "node0", binary_path, extra_args=["--regtest"])  # regtest
        node.start()

        # Establish baseline
        stats0 = node.rpc("getorphanstats")
        assert stats0.get("count") == 0

        # Build an orphan header (unknown parent)
        ghash = node.rpc("getblockhash", 0)
        ghdr = node.rpc("getblockheader", str(ghash))
        powlimit_bits = int(ghdr.get("bits"), 16)
        # Use a random prevhash (all 0x11) so it's unknown
        prev_hex = ("11" * 32)
        t0 = int(ghdr.get("time"))
        node.rpc("setmocktime", t0)

        # Add 3 orphans for peer 1
        for i in range(3):
            h_hex = build_header_hex(prev_hex, t0 + 60 + i, powlimit_bits)
            res = node.rpc("addorphanheader", h_hex, 1)
            assert res.get("count") >= 1

        # Add 2 orphans for peer 2
        for i in range(2):
            h_hex = build_header_hex(prev_hex, t0 + 120 + i, powlimit_bits)
            res = node.rpc("addorphanheader", h_hex, 2)
            assert res.get("count") >= 1

        stats1 = node.rpc("getorphanstats")
        assert stats1.get("count") == 5, f"unexpected count {stats1}"
        # by_peer counts should reflect 3 and 2
        byp = {e["peer_id"]: e["count"] for e in stats1.get("by_peer", [])}
        assert byp.get(1, 0) >= 1 and byp.get(2, 0) >= 1

        # Advance time beyond expiry (regtest orphan expire = 12 minutes)
        node.rpc("setmocktime", t0 + 13*60)
        ev = node.rpc("evictorphans")
        assert ev.get("evicted") >= 1
        stats2 = node.rpc("getorphanstats")
        assert stats2.get("count") == 0

        # Idempotent evict
        ev2 = node.rpc("evictorphans")
        assert ev2.get("evicted") == 0

        print("✓ orphan_pool_tests passed")
        return 0

    except Exception as e:
        print(f"✗ orphan_pool_tests failed: {e}")
        return 1
    finally:
        if node and node.is_running():
            print("Stopping node...")
            node.stop()
        print(f"Cleaning up {test_dir}")
        shutil.rmtree(test_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
