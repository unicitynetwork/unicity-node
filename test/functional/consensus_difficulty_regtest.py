#!/usr/bin/env python3
"""Consensus: difficulty behavior on regtest (constant powLimit) using submitheader skip_pow.

Scenarios:
- Next-work-required is constant (powLimit) on regtest regardless of timestamps
- Accept several headers with varying timestamp deltas; bits remain equal to genesis bits (powLimit)
"""

import sys
import tempfile
import shutil
from pathlib import Path
import struct

# Add test framework to path
sys.path.insert(0, str(Path(__file__).parent / "test_framework"))
from test_node import TestNode

POW_LIMIT_BITS = 0x207fffff  # from regtest params


def u32le(n: int) -> bytes:
    return struct.pack('<I', n & 0xFFFFFFFF)


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
    print("Starting consensus_difficulty_regtest test...")

    test_dir = Path(tempfile.mkdtemp(prefix="unicity_consensus_diff_rt_"))
    binary_path = Path(__file__).parent.parent.parent / "build" / "bin" / "unicityd"

    node = None
    try:
        node = TestNode(0, test_dir / "node0", binary_path, extra_args=["--regtest"])  # default regtest
        node.start()

        # Genesis
        genesis_hash = node.rpc("getblockhash", 0)
        hdr0 = node.rpc("getblockheader", str(genesis_hash))
        assert int(hdr0.get("bits"), 16) == POW_LIMIT_BITS

        prev_hash = str(genesis_hash)
        prev_time = int(hdr0.get("time"))

        # Submit a few headers with varied timestamps; bits must stay at powLimit
        for dt in [3600, 10, 7200, 86400, 1, 12345]:
            t_next = prev_time + dt
            h_hex = build_header_hex(prev_hash, t_next, POW_LIMIT_BITS)
            r = node.rpc("submitheader", h_hex, "true")
            assert r.get("success") is True
            prev_hash = r.get("hash")
            hdr = node.rpc("getblockheader", prev_hash)
            assert int(hdr.get("bits"), 16) == POW_LIMIT_BITS, f"bits changed on regtest: {hdr}"
            prev_time = int(hdr.get("time"))

        print("✓ consensus_difficulty_regtest passed")
        return 0

    except Exception as e:
        print(f"✗ consensus_difficulty_regtest failed: {e}")
        return 1

    finally:
        if node and node.is_running():
            print("Stopping node...")
            node.stop()
        print(f"Cleaning up {test_dir}")
        shutil.rmtree(test_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
