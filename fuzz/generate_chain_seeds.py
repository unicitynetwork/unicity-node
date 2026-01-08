#!/usr/bin/env python3
"""Generate seed corpus for chain reorganization fuzzer"""

import struct
import os

CORPUS_DIR = "fuzz/corpus"

def write_seed(filename, data):
    """Write seed file to corpus directory"""
    # Create corpus directory if it doesn't exist
    os.makedirs(CORPUS_DIR, exist_ok=True)

    path = os.path.join(CORPUS_DIR, filename)
    with open(path, "wb") as f:
        f.write(data)
    print(f"Created {path} ({len(data)} bytes)")

def build_simple_chain():
    """Build a simple linear chain (tests basic chain building)"""
    data = bytearray()

    # Config: suspicious_reorg_depth=50, test_orphans=False, test_invalidate=False, num_chains=1
    data.append(40)  # suspicious_reorg_depth offset (10 + 40 = 50)
    data.append(0)   # test_orphans = false
    data.append(0)   # test_invalidate = false
    data.append(0)   # num_chains = 1

    # Action 0: Extend main chain (repeat 10 times)
    for i in range(10):
        data.append(0)  # action = extend main chain
        # Miner address (20 bytes)
        data.extend([i] * 20)
        data.append(i * 10)  # time offset
        data.extend([0, 0, 0, i])  # nonce
        data.extend([i] * 32)  # hashRandomX

        # Periodic activation
        data.append(0x00)  # trigger activation

    return bytes(data)

def build_fork_scenario():
    """Build competing forks (tests reorganization)"""
    data = bytearray()

    # Config: test fork creation
    data.append(20)  # suspicious_reorg_depth = 30
    data.append(0)   # test_orphans = false
    data.append(0)   # test_invalidate = false
    data.append(2)   # num_chains = 3 (1 + 2)

    # Build main chain (5 blocks)
    for i in range(5):
        data.append(0)  # action = extend main chain
        data.extend([i] * 20)  # miner address
        data.append(i * 10)  # time offset
        data.extend([0, 0, 0, i])  # nonce
        data.extend([i] * 32)  # hashRandomX
        data.append(0xFF)  # don't activate

    # Create fork
    for i in range(3):
        data.append(1)  # action = create competing fork
        data.extend([100 + i] * 20)  # different miner
        data.append(i * 10)
        data.extend([0, 0, 0, 100 + i])
        data.extend([100 + i] * 32)
        data.append(2)  # fork_height = 2
        data.append(0xFF)

    # Extend fork to make it longer
    for i in range(5):
        data.append(2)  # action = extend random chain tip
        data.append(1)  # tip_idx = 1 (the fork)
        data.extend([150 + i] * 20)
        data.append(i * 10)
        data.extend([0, 0, 0, 150 + i])
        data.extend([150 + i] * 32)
        data.append(0x00)  # trigger activation

    return bytes(data)

def build_orphan_scenario():
    """Test orphan header processing"""
    data = bytearray()

    # Config: enable orphan testing
    data.append(30)  # suspicious_reorg_depth = 40
    data.append(1)   # test_orphans = TRUE
    data.append(0)   # test_invalidate = false
    data.append(0)   # num_chains = 1

    # Build a few main chain blocks
    for i in range(3):
        data.append(0)  # extend main chain
        data.extend([i] * 20)
        data.append(i * 10)
        data.extend([0, 0, 0, i])
        data.extend([i] * 32)
        data.append(0xFF)

    # Send orphan blocks
    for i in range(5):
        data.append(3)  # action = orphan (missing parent)
        data.extend([200 + i] * 32)  # fake parent hash
        data.extend([50 + i] * 20)  # miner address
        data.append(i * 10)
        data.extend([0, 0, 0, 200 + i])
        data.extend([200 + i] * 32)
        data.append(i)  # peer_id
        data.append(0x00)  # try activation

    return bytes(data)

def build_invalidate_scenario():
    """Test InvalidateBlock cascades"""
    data = bytearray()

    # Config: enable invalidation testing
    data.append(50)  # suspicious_reorg_depth = 60
    data.append(0)   # test_orphans = false
    data.append(1)   # test_invalidate = TRUE
    data.append(1)   # num_chains = 2

    # Build main chain (10 blocks)
    for i in range(10):
        data.append(0)
        data.extend([i] * 20)
        data.append(i * 10)
        data.extend([0, 0, 0, i])
        data.extend([i] * 32)
        data.append(0xFF)

    # Create a fork
    for i in range(3):
        data.append(1)  # create fork
        data.extend([100 + i] * 20)
        data.append(i * 10)
        data.extend([0, 0, 0, 100 + i])
        data.extend([100 + i] * 32)
        data.append(3)  # fork at height 3
        data.append(0xFF)

    # Invalidate middle block
    data.append(4)  # action = invalidate
    data.append(5)  # invalidate at height 5
    data.append(0x00)  # activate

    # Try to extend (should rebuild from fork)
    for i in range(3):
        data.append(0)
        data.extend([200 + i] * 20)
        data.append(i * 10)
        data.extend([0, 0, 0, 200 + i])
        data.extend([200 + i] * 32)
        data.append(0x00)

    return bytes(data)

def build_deep_reorg():
    """Test deep reorganization near suspicious limit"""
    data = bytearray()

    # Config: low suspicious reorg depth
    data.append(5)   # suspicious_reorg_depth = 15
    data.append(0)
    data.append(0)
    data.append(3)   # num_chains = 4

    # Build main chain (20 blocks - will exceed suspicious depth)
    for i in range(20):
        data.append(0)
        data.extend([i] * 20)
        data.append(i * 10)
        data.extend([0, 0, 0, i])
        data.extend([i] * 32)
        data.append(0xFF)

    # Fork at early height
    data.append(1)
    data.extend([100] * 20)
    data.append(10)
    data.extend([0, 0, 0, 100])
    data.extend([100] * 32)
    data.append(2)  # fork at height 2
    data.append(0xFF)

    # Extend fork to be longer (25 blocks - should trigger suspicious reorg)
    for i in range(25):
        data.append(2)  # extend random tip
        data.append(1)
        data.extend([150 + i] * 20)
        data.append(i * 10)
        data.extend([0, 0, 0, 150 + i])
        data.extend([150 + i] * 32)
        data.append(0x00)  # try activation

    return bytes(data)

# Generate seed corpus
print("Generating chain reorganization seed corpus...")

write_seed("simple_chain", build_simple_chain())
write_seed("fork_scenario", build_fork_scenario())
write_seed("orphan_scenario", build_orphan_scenario())
write_seed("invalidate_scenario", build_invalidate_scenario())
write_seed("deep_reorg", build_deep_reorg())

# Minimal seeds
write_seed("minimal", b"\x00" * 10)
write_seed("all_zeros", b"\x00" * 100)
write_seed("all_ones", b"\xFF" * 100)
write_seed("alternating", bytes([i % 256 for i in range(200)]))

print(f"\nCreated 8 seed files in {CORPUS_DIR}/")
print(f"Run with: ./fuzz/fuzz_chain_reorg {CORPUS_DIR}/")
