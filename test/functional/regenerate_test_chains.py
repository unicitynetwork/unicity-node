#!/usr/bin/env python3
"""Regenerate large test chains for batching/persistence tests."""

import sys
import time
import tempfile
import shutil
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "test_framework"))
from test_node import TestNode

def generate_chain(height, output_name):
    """Generate a test chain and save it."""
    print(f"\n{'='*70}")
    print(f"Generating {height}-block chain: {output_name}")
    print(f"{'='*70}")
    
    test_dir = Path(tempfile.mkdtemp(prefix=f"gen_{height}_"))

    node = TestNode(0, test_dir / "node0")
    try:
        print("Starting node...")
        node.start()
        time.sleep(1)
        
        print(f"Mining {height} blocks...")
        start = time.time()
        
        # Mine in batches for progress updates
        batch_size = 100
        for i in range(0, height, batch_size):
            remaining = min(batch_size, height - i)
            node.generate(remaining)
            print(f"  Progress: {i + remaining}/{height} blocks ({int((i + remaining) / height * 100)}%)")
        
        elapsed = time.time() - start
        print(f"Mining complete in {elapsed:.1f}s")
        
        info = node.get_info()
        print(f"Final height: {info['blocks']}")
        print(f"Tip: {info['bestblockhash'][:16]}...")
        
        node.stop()
        time.sleep(1)
        
        # Save to test_chains
        output_dir = Path(__file__).parent / "test_chains" / output_name
        if output_dir.exists():
            shutil.rmtree(output_dir)
        output_dir.parent.mkdir(parents=True, exist_ok=True)
        
        print(f"Saving chain to {output_dir}...")
        shutil.copytree(test_dir / "node0", output_dir)
        
        # Verify
        print("Verifying saved chain...")
        with open(output_dir / "headers.json") as f:
            data = json.load(f)
            saved_height = data['block_count'] - 1
            print(f"Saved {saved_height} blocks (+ genesis = {saved_height + 1} total)")
            assert saved_height == height, f"Height mismatch: expected {height}, got {saved_height}"
        
        print(f"✓ Successfully generated {output_name}")
        return 0
        
    except Exception as e:
        print(f"✗ Error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    finally:
        if node:
            node.stop()
        # Clean up temp dir
        shutil.rmtree(test_dir, ignore_errors=True)

def main():
    print("\n" + "="*70)
    print("REGENERATING TEST CHAINS")
    print("="*70)
    
    # Generate the chains needed by tests
    chains = [
        (200, "chain_200_blocks"),
        (2500, "chain_2500_blocks"),
        (12000, "chain_12000_blocks"),
    ]
    
    for height, name in chains:
        result = generate_chain(height, name)
        if result != 0:
            print(f"\n✗ Failed to generate {name}")
            return result
    
    print("\n" + "="*70)
    print("✓ ALL TEST CHAINS REGENERATED SUCCESSFULLY")
    print("="*70)
    return 0

if __name__ == "__main__":
    sys.exit(main())
