#!/usr/bin/env python3
"""Generate test chains for massive reorg testing.

Creates three chains with a shared base that fork:
- Base: 1000 blocks (shared by all)
- Chain A: base + 2000 more = 3000 total
- Chain B: base + 3000 more (fork) = 4000 total (1000 block reorg from A)
- Chain C: base + 4000 more (fork) = 5000 total (2000 block reorg from A)

These chains test massive legitimate reorgs (>1000 blocks).
With the sync peer isolation fix, nodes properly sync only from
their designated sync peer, preventing premature disconnects.
"""

import sys
import time
import tempfile
import shutil
from pathlib import Path

# Add test framework to path
sys.path.insert(0, str(Path(__file__).parent / "test_framework"))

from test_node import TestNode
from util import pick_free_port


def generate_chain(node, num_blocks, miner_address="0000000000000000000000000000000000000000"):
    """Generate blocks in batches."""
    print(f"    Generating {num_blocks} blocks...")
    batch_size = 1000
    remaining = num_blocks
    start = time.time()
    
    while remaining > 0:
        to_generate = min(remaining, batch_size)
        node.generate(to_generate, miner_address, timeout=300)
        remaining -= to_generate
        if remaining > 0:
            elapsed = time.time() - start
            rate = (num_blocks - remaining) / elapsed if elapsed > 0 else 0
            print(f"      Progress: {num_blocks - remaining}/{num_blocks} blocks ({rate:.1f} blk/s)")
    
    elapsed = time.time() - start
    rate = num_blocks / elapsed if elapsed > 0 else 0
    print(f"    ✓ Generated {num_blocks} blocks in {elapsed:.0f}s ({rate:.1f} blk/s)")
    return node.get_info()


def main():
    print("=== Generating Massive Reorg Test Chains ===\n")
    
    output_dir = Path(__file__).parent / "test_chains"
    output_dir.mkdir(exist_ok=True)
    
    # Paths for output chains
    chain_base_path = output_dir / "chain_1000_blocks_base"
    chain_a_path = output_dir / "chain_3000_blocks"
    chain_b_path = output_dir / "chain_4000_blocks"
    chain_c_path = output_dir / "chain_5000_blocks"
    
    # Check if chains already exist
    if all(p.exists() for p in [chain_base_path, chain_a_path, chain_b_path, chain_c_path]):
        print("✓ All chains already exist:")
        print(f"  - {chain_base_path}")
        print(f"  - {chain_a_path}")
        print(f"  - {chain_b_path}")
        print(f"  - {chain_c_path}")
        print("\nDelete these directories to regenerate.")
        return 0
    
    temp_base = Path(tempfile.mkdtemp(prefix="unicity_reorg_gen_"))
    node = None
    
    try:
        port = pick_free_port()
        
        # Step 1: Generate base chain (1000 blocks)
        print("Step 1: Generating BASE chain (1000 blocks)...")
        print(f"  Output: {chain_base_path}")
        
        node = TestNode(0, temp_base / "base", 
                       extra_args=["--listen", f"--port={port}", "--connect=0"])
        node.start()
        time.sleep(1)
        
        info = generate_chain(node, 1000)
        base_tip = info["bestblockhash"]
        print(f"  Base tip: {base_tip[:16]}...\n")
        
        # Save base chain
        node.stop()
        time.sleep(1)
        
        if chain_base_path.exists():
            shutil.rmtree(chain_base_path)
        shutil.copytree(temp_base / "base", chain_base_path)
        print(f"  ✓ Saved to {chain_base_path}\n")
        
        # Step 2: Generate Chain A (base + 2000 = 3000 total)
        print("Step 2: Generating Chain A (3000 blocks = base + 2000 more)...")
        print(f"  Output: {chain_a_path}")
        
        shutil.rmtree(temp_base / "chain_a", ignore_errors=True)
        shutil.copytree(chain_base_path, temp_base / "chain_a")
        
        node = TestNode(0, temp_base / "chain_a",
                       extra_args=["--listen", f"--port={port}", "--connect=0"])
        node.start()
        time.sleep(1)
        
        info = generate_chain(node, 2000)
        tip_a = info["bestblockhash"]
        print(f"  Chain A tip: {tip_a[:16]}...\n")
        
        node.stop()
        time.sleep(1)
        
        if chain_a_path.exists():
            shutil.rmtree(chain_a_path)
        shutil.copytree(temp_base / "chain_a", chain_a_path)
        print(f"  ✓ Saved to {chain_a_path}\n")
        
        # Step 3: Generate Chain B (base + 3000 different = 4000 total)
        print("Step 3: Generating Chain B (4000 blocks = base + 3000 more, FORKED)...")
        print(f"  Output: {chain_b_path}")
        print("  Note: This forks from base with different blocks than Chain A")
        
        shutil.rmtree(temp_base / "chain_b", ignore_errors=True)
        shutil.copytree(chain_base_path, temp_base / "chain_b")
        
        node = TestNode(0, temp_base / "chain_b",
                       extra_args=["--listen", f"--port={port}", "--connect=0"])
        node.start()
        time.sleep(1)
        
        # Use different miner address to create different blocks
        info = generate_chain(node, 3000, miner_address="1111111111111111111111111111111111111111")
        tip_b = info["bestblockhash"]
        print(f"  Chain B tip: {tip_b[:16]}...\n")
        
        node.stop()
        time.sleep(1)
        
        if chain_b_path.exists():
            shutil.rmtree(chain_b_path)
        shutil.copytree(temp_base / "chain_b", chain_b_path)
        print(f"  ✓ Saved to {chain_b_path}\n")
        
        # Step 4: Generate Chain C (base + 4000 different = 5000 total)
        print("Step 4: Generating Chain C (5000 blocks = base + 4000 more, FORKED)...")
        print(f"  Output: {chain_c_path}")
        print("  Note: This forks from base with different blocks than A and B")
        
        shutil.rmtree(temp_base / "chain_c", ignore_errors=True)
        shutil.copytree(chain_base_path, temp_base / "chain_c")
        
        node = TestNode(0, temp_base / "chain_c",
                       extra_args=["--listen", f"--port={port}", "--connect=0"])
        node.start()
        time.sleep(1)
        
        # Use yet another miner address to create different blocks
        info = generate_chain(node, 4000, miner_address="2222222222222222222222222222222222222222")
        tip_c = info["bestblockhash"]
        print(f"  Chain C tip: {tip_c[:16]}...\n")
        
        node.stop()
        time.sleep(1)
        
        if chain_c_path.exists():
            shutil.rmtree(chain_c_path)
        shutil.copytree(temp_base / "chain_c", chain_c_path)
        print(f"  ✓ Saved to {chain_c_path}\n")
        
        # Verify all chains are different but share base
        print("=" * 60)
        print("✓ Chain generation complete!")
        print("=" * 60)
        print(f"Base (1000):  {base_tip[:16]}... (shared)")
        print(f"Chain A (3000): {tip_a[:16]}... (base + 2000)")
        print(f"Chain B (4000): {tip_b[:16]}... (base + 3000 fork)")
        print(f"Chain C (5000): {tip_c[:16]}... (base + 4000 fork)")
        print()
        print("These chains test massive reorgs:")
        print("  - A (3000) → B (4000): 1000 block reorg")
        print("  - A (3000) → C (5000): 2000 block reorg")
        print("  - Tests sync peer isolation fix (prevents premature disconnect)")
        print("=" * 60)
        
        return 0
        
    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()
        return 1
        
    finally:
        if node and node.is_running():
            node.stop()
        print(f"\nCleaning up temp directory: {temp_base}")
        shutil.rmtree(temp_base, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
