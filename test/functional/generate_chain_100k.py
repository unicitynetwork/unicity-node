#!/usr/bin/env python3
"""Generate 100,000 block test chain."""

import sys
import time
import tempfile
import shutil
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "test_framework"))
from test_node import TestNode

def main():
    height = 100000
    output_name = "chain_100000_blocks"
    
    print(f"\n{'='*70}")
    print(f"Generating {height:,}-block chain: {output_name}")
    print(f"{'='*70}")
    
    test_dir = Path(tempfile.mkdtemp(prefix=f"gen_100k_"))
    print(f"Working directory: {test_dir}")

    node = TestNode(0, test_dir / "node0")
    try:
        print("\nStarting node...")
        node.start()
        time.sleep(2)
        
        print(f"\nMining {height:,} blocks...")
        print("(This will take a while - mining in batches of 100)")
        print("Estimated time: ~30-60 minutes depending on CPU")
        start = time.time()
        
        # Mine in batches for progress updates  
        # Use smaller batches to avoid RPC timeout (120s default)
        batch_size = 100
        for i in range(0, height, batch_size):
            batch_start = time.time()
            remaining = min(batch_size, height - i)
            node.generate(remaining)
            batch_elapsed = time.time() - batch_start
            total_elapsed = time.time() - start
            progress_pct = int((i + remaining) / height * 100)
            
            # Estimate time remaining
            blocks_per_sec = (i + remaining) / total_elapsed if total_elapsed > 0 else 0
            remaining_blocks = height - (i + remaining)
            eta_seconds = remaining_blocks / blocks_per_sec if blocks_per_sec > 0 else 0
            eta_min = int(eta_seconds / 60)
            
            print(f"  [{progress_pct:3d}%] {i + remaining:6,}/{height:,} blocks | "
                  f"Batch: {batch_elapsed:5.1f}s | "
                  f"Total: {int(total_elapsed/60):3d}m {int(total_elapsed%60):02d}s | "
                  f"ETA: ~{eta_min:3d}m")
        
        elapsed = time.time() - start
        print(f"\n✓ Mining complete in {int(elapsed/60)}m {int(elapsed%60)}s")
        print(f"  Average: {height/elapsed:.1f} blocks/sec")
        
        info = node.get_info()
        print(f"\nFinal height: {info['blocks']:,}")
        print(f"Tip hash: {info['bestblockhash'][:16]}...")
        
        node.stop()
        time.sleep(2)
        
        # Save to test_chains
        output_dir = Path(__file__).parent / "test_chains" / output_name
        if output_dir.exists():
            print(f"\nRemoving existing {output_name}...")
            shutil.rmtree(output_dir)
        output_dir.parent.mkdir(parents=True, exist_ok=True)
        
        print(f"\nSaving chain to {output_dir}...")
        save_start = time.time()
        shutil.copytree(test_dir / "node0", output_dir)
        save_elapsed = time.time() - save_start
        print(f"  Saved in {save_elapsed:.1f}s")
        
        # Calculate size
        total_size = sum(f.stat().st_size for f in output_dir.rglob('*') if f.is_file())
        size_mb = total_size / (1024 * 1024)
        print(f"  Chain size: {size_mb:.1f} MB")
        
        # Verify
        print("\nVerifying saved chain...")
        with open(output_dir / "headers.json") as f:
            data = json.load(f)
            saved_height = data['block_count'] - 1
            print(f"  Block count in headers.json: {saved_height:,}")
            
            if saved_height != height:
                print(f"✗ Height mismatch: expected {height:,}, got {saved_height:,}")
                return 1
        
        print(f"\n{'='*70}")
        print(f"✓ Successfully generated {output_name}")
        print(f"  Location: {output_dir}")
        print(f"  Height: {height:,} blocks")
        print(f"  Size: {size_mb:.1f} MB")
        print(f"{'='*70}")
        return 0
        
    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    finally:
        if node:
            node.stop()
        # Clean up temp dir
        print(f"\nCleaning up {test_dir}...")
        shutil.rmtree(test_dir, ignore_errors=True)

if __name__ == "__main__":
    sys.exit(main())
