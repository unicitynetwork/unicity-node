#!/usr/bin/env python3
"""Consensus: ASERT difficulty behavior tests using submitheader skip_pow.

On regtest, difficulty adjustment is disabled (always powLimit). This test
verifies steady-spacing invariance on regtest and performs the negative
bad-diffbits check only when difficulty adjustment is active.
"""

import sys
import tempfile
import shutil
from pathlib import Path
import struct

# Add test framework to path
sys.path.insert(0, str(Path(__file__).parent / "test_framework"))
from test_node import TestNode

TARGET_SPACING = 8640  # 2.4 hours


def u32le(n: int) -> bytes:
    return struct.pack('<I', n & 0xFFFFFFFF)


def hex_to_le32(hex_str: str) -> bytes:
    b = bytes.fromhex(hex_str)
    if len(b) != 32:
        raise ValueError("hash must be 32 bytes")
    return b[::-1]


def hex_to_20(hex_str: str) -> bytes:
    b = bytes.fromhex(hex_str)
    if len(b) != 20:
        raise ValueError("address must be 20 bytes (40 hex chars)")
    return b


def build_header_hex(prev_hash_hex_be: str, n_time: int, n_bits_u32: int, n_nonce: int = 0, version: int = 1, miner_addr_hex: str | None = None) -> str:
    prev_le = hex_to_le32(prev_hash_hex_be)
    miner = hex_to_20(miner_addr_hex) if miner_addr_hex else (b"\x00" * 20)
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
    print("Starting consensus_asert_difficulty test...")

    test_dir = Path(tempfile.mkdtemp(prefix="unicity_consensus_asert_"))
    binary_path = Path(__file__).parent.parent.parent / "build" / "bin" / "unicityd"

    node = None
    try:
        node = TestNode(0, test_dir / "node0", binary_path, extra_args=["--regtest"])  # default regtest
        node.start()

        # Genesis info
        genesis_hash = node.rpc("getblockhash", 0)
        hdr0 = node.rpc("getblockheader", str(genesis_hash))
        prev_hash = str(genesis_hash)
        prev_time = int(hdr0.get("time"))
        prev_bits = int(hdr0.get("bits"), 16)

        # 1) Steady spacing invariance
        t1 = prev_time + TARGET_SPACING
        h1_hex = build_header_hex(prev_hash, t1, prev_bits)
        r1 = node.rpc("submitheader", h1_hex, "true")
        assert r1.get("success") is True, f"H1 accept failed: {r1}"
        h1_hash = r1.get("hash")
        hdr1 = node.rpc("getblockheader", h1_hash)
        assert int(hdr1.get("time")) == t1
        bits1 = int(hdr1.get("bits"), 16)
        assert bits1 == prev_bits, f"Expected bits unchanged at target spacing, got {bits1:x} vs {prev_bits:x}"

        t2 = t1 + TARGET_SPACING
        h2_hex = build_header_hex(h1_hash, t2, bits1)
        r2 = node.rpc("submitheader", h2_hex, "true")
        assert r2.get("success") is True, f"H2 accept failed: {r2}"
        h2_hash = r2.get("hash")
        hdr2 = node.rpc("getblockheader", h2_hash)
        bits2 = int(hdr2.get("bits"), 16)
        assert bits2 == bits1, f"Expected bits unchanged at target spacing, got {bits2:x} vs {bits1:x}"

        # 2) Negative case only when difficulty adjusts (non-regtest)
        chain = node.get_info().get("chain")
        if chain != "regtest":
            big_t = int(hdr2.get("time")) + 3 * 24 * 3600  # +3 days deviation
            h3_hex = build_header_hex(h2_hash, big_t, bits2)
            r3 = node.rpc("submitheader", h3_hex, "true")
            assert isinstance(r3, dict) and "error" in r3 and "bad-diffbits" in r3["error"], f"Expected bad-diffbits, got: {r3}"

        print("✓ consensus_asert_difficulty passed")
        return 0

    except Exception as e:
        print(f"✗ consensus_asert_difficulty failed: {e}")
        return 1

    finally:
        if node and node.is_running():
            print("Stopping node...")
            node.stop()
        print(f"Cleaning up {test_dir}")
        shutil.rmtree(test_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
