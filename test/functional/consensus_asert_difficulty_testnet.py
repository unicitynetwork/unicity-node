#!/usr/bin/env python3
"""Consensus: ASERT/testnet RPC behavior without PoW skip.

Historically this test used `submitheader ... skip_pow=true` on testnet to
exercise ASERT difficulty evolution. The node now enforces that PoW skipping is
**regtest-only**, so this test instead verifies:

- `getnextworkrequired` is available on testnet and matches the genesis bits at
  height 0.
- `submitheader` with `skip_pow=true` on testnet is rejected with a clear
  error mentioning regtest-only PoW skipping.
- `submitheader` without `skip_pow` on testnet fails with a PoW-related error
  when the header is not actually mined.

ASERT correctness itself is covered by C++ unit tests; this functional test
focuses on the RPC surface and safety semantics on testnet.
"""

import sys
import tempfile
import shutil
from pathlib import Path
import struct

# Add test framework to path
sys.path.insert(0, str(Path(__file__).parent / "test_framework"))
from test_node import TestNode

TESTNET_SPACING = 120  # 2 minutes


def u32le(n: int) -> bytes:
    return struct.pack('<I', n & 0xFFFFFFFF)


def hex_to_le32(hex_str: str) -> bytes:
    b = bytes.fromhex(hex_str)
    if len(b) != 32:
        raise ValueError("hash must be 32 bytes")
    return b[::-1]


def build_header_hex(prev_hash_hex_be: str, n_time: int, n_bits_u32: int, n_nonce: int = 0, version: int = 1) -> str:
    """Build a 100-byte Unicity header for testing.

    Layout: nVersion(4) | prevhash(32 LE) | miner(20) | nTime(4 LE) |
            nBits(4 LE) | nNonce(4 LE) | hashRandomX(32)
    """
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
    print("Starting consensus_asert_difficulty_testnet test...")

    test_dir = Path(tempfile.mkdtemp(prefix="unicity_consensus_asert_tn_"))
    binary_path = Path(__file__).parent.parent.parent / "build" / "bin" / "unicityd"

    node = None
    try:
        node = TestNode(0, test_dir / "node0", binary_path, extra_args=["--nolisten"], chain="testnet")
        node.start()

        # Genesis
        genesis_hash = node.rpc("getblockhash", 0)
        hdr0 = node.rpc("getblockheader", str(genesis_hash))
        prev_hash = str(genesis_hash)
        t0 = int(hdr0.get("time"))
        powlimit_bits = int(hdr0.get("bits"), 16)

        # 1) getnextworkrequired must be available on testnet and equal powLimit at height 0
        nw = node.rpc("getnextworkrequired")
        bits1 = int(nw.get("bits_u32"))
        print(f"powlimit_bits={powlimit_bits:#x} bits1={bits1:#x}")
        assert bits1 == powlimit_bits, f"Expected powlimit bits {powlimit_bits:#x}, got {bits1:#x}"

        # Build a header for the next block using those bits
        t1 = t0 + TESTNET_SPACING
        h1_hex = build_header_hex(prev_hash, t1, bits1)

        # 2) On testnet, skip_pow=true must be rejected (regtest-only PoW skipping)
        r_skip = node.rpc("submitheader", h1_hex, "true")
        assert isinstance(r_skip, dict) and "error" in r_skip, f"Expected JSON error for skip_pow on testnet, got: {r_skip}"
        err = str(r_skip.get("error", "")).lower()
        # The exact wording is implementation-defined; require mention of regtest and pow/skip
        assert "regtest" in err and "pow" in err and "skip" in err, f"Unexpected skip_pow error on testnet: {r_skip}"

        # 3) Without skip_pow, header should fail PoW (high-hash style error)
        r_pow = node.rpc("submitheader", h1_hex)
        assert isinstance(r_pow, dict) and "error" in r_pow, f"Expected JSON error for invalid PoW header, got: {r_pow}"
        pow_err = str(r_pow.get("error", "")).lower()
        # Accept either the explicit reject reason or a generic PoW failure message
        assert "high-hash" in pow_err or "pow" in pow_err, f"Unexpected PoW error: {r_pow}"

        print("✓ consensus_asert_difficulty_testnet passed")
        return 0

    except Exception as e:
        print(f"✗ consensus_asert_difficulty_testnet failed: {e}")
        return 1

    finally:
        if node and node.is_running():
            print("Stopping node...")
            node.stop()
        print(f"Cleaning up {test_dir}")
        shutil.rmtree(test_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
