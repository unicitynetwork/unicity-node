#!/usr/bin/env python3
"""Consensus: timestamp bounds tests (MTP and future limit) using submitheader skip_pow.

Scenarios:
- Accept header H1 with time = prev.time + target_spacing (bits unchanged)
- Reject H2 where time == MTP(prev) (time-too-old)
- Reject H3 where time > adjusted_time + 2h (time-too-new)
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
    # Convert 64-char big-endian hex to 32-byte little-endian
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
    # Fields: nVersion(4) | prevhash(32 LE raw) | minerAddress(20) | nTime(4 LE) | nBits(4 LE) | nNonce(4 LE) | hashRandomX(32)
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
    print("Starting consensus_timestamp_bounds test...")

    test_dir = Path(tempfile.mkdtemp(prefix="unicity_consensus_ts_"))
    binary_path = Path(__file__).parent.parent.parent / "build" / "bin" / "unicityd"

    node = None
    try:
        node = TestNode(0, test_dir / "node0", binary_path, extra_args=["--regtest"])  # default regtest
        node.start()

        # Genesis info
        genesis_hash = node.rpc("getblockhash", 0)
        if isinstance(genesis_hash, dict):
            # Some RPCs return string directly; ensure we have a str
            genesis_hash = genesis_hash.get("error") or genesis_hash  # fallback
        hdr0 = node.rpc("getblockheader", str(genesis_hash))
        prev_hash = str(genesis_hash)
        prev_time = int(hdr0.get("time"))
        prev_bits_hex = hdr0.get("bits")
        prev_bits_u32 = int(prev_bits_hex, 16)

        # 1) Accept H1 with time = prev_time + target_spacing, bits unchanged
        t1 = prev_time + TARGET_SPACING
        h1_hex = build_header_hex(prev_hash, t1, prev_bits_u32)
        r1 = node.rpc("submitheader", h1_hex, "true")  # skip_pow
        assert isinstance(r1, dict) and r1.get("success") is True, f"H1 accept failed: {r1}"
        h1_hash = r1.get("hash")
        hdr1 = node.rpc("getblockheader", h1_hash)
        assert int(hdr1.get("time")) == t1

        # 2) Reject H2 where time == MTP(prev) (strictly greater required)
        # For height 1, MTP(prev) equals prev's time (hdr1.mediantime equals hdr1.time)
        prev_hash = h1_hash
        prev_bits_u32 = int(hdr1.get("bits"), 16)
        mtp_prev = int(hdr1.get("mediantime"))
        t2 = mtp_prev  # equal -> should fail
        h2_hex = build_header_hex(prev_hash, t2, prev_bits_u32)
        r2 = node.rpc("submitheader", h2_hex, "true")
        assert isinstance(r2, dict) and "error" in r2, f"Expected failure for time-too-old, got: {r2}"
        assert "time-too-old" in r2["error"], f"Unexpected error: {r2['error']}"

        # 3) Reject H3 where time > adjusted_time + 2h (future too far)
        # Set mocktime near prev_time, then set header time > mock + 2h
        node.rpc("setmocktime", int(hdr1.get("time")))
        future_t = int(hdr1.get("time")) + 2*3600 + 1
        h3_hex = build_header_hex(prev_hash, future_t, prev_bits_u32)
        r3 = node.rpc("submitheader", h3_hex, "true")
        assert isinstance(r3, dict) and "error" in r3, f"Expected failure for time-too-new, got: {r3}"
        assert "time-too-new" in r3["error"], f"Unexpected error: {r3['error']}"

        print("✓ consensus_timestamp_bounds passed")
        return 0

    except Exception as e:
        print(f"✗ consensus_timestamp_bounds failed: {e}")
        return 1

    finally:
        if node and node.is_running():
            print("Stopping node...")
            node.stop()
        print(f"Cleaning up {test_dir}")
        shutil.rmtree(test_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
