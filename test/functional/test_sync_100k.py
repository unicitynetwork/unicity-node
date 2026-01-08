#!/usr/bin/env python3
"""Test sync performance with 100k block chain."""

import sys
import time
import tempfile
import shutil
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "test_framework"))
from test_node import TestNode
from util import wait_until

def main():
    print(f"\n{'='*70}")
    print("100k BLOCK SYNC PERFORMANCE TEST")
    print(f"{'='*70}")
    
    # Check if chain exists
    chain_dir = Path(__file__).parent / "test_chains" / "chain_100000_blocks"
    if not chain_dir.exists():
        print(f"✗ Error: Chain not found at {chain_dir}")
        print("  Run: python3 test/functional/generate_chain_100k.py")
        return 1
    
    print(f"\nUsing pre-generated chain: {chain_dir}")
    print(f"Chain size: {sum(f.stat().st_size for f in chain_dir.rglob('*') if f.is_file()) / (1024*1024):.1f} MB")
    
    # Create temp dirs
    test_dir = Path(tempfile.mkdtemp(prefix="sync_test_"))
    print(f"Test directory: {test_dir}")
    
    # Copy chain to node1 (source node with full chain)
    print("\nSetting up source node (node1) with 100k blocks...")
    node1_dir = test_dir / "node1"
    shutil.copytree(chain_dir, node1_dir)
    
    # Create empty node2 (sync target)
    node2_dir = test_dir / "node2"
    node2_dir.mkdir(parents=True)
    
    node1 = None
    node2 = None
    
    try:
        # Start node1 (source)
        print("\nStarting node1 (source with 100k blocks)...")
        node1 = TestNode(1, node1_dir, extra_args=["--port=19590"])
        node1.start()
        time.sleep(2)
        
        info1 = node1.get_info()
        print(f"  Node1 height: {info1['blocks']:,}")
        print(f"  Node1 tip: {info1['bestblockhash'][:16]}...")
        
        # Start node2 (empty, will sync)
        print("\nStarting node2 (empty, will sync)...")
        print(f"  Node2 datadir: {node2_dir}")
        node2 = TestNode(2, node2_dir, extra_args=["--port=19591", "--connect=127.0.0.1:19590", "--listen"])
        try:
            node2.start()
        except Exception as e:
            print(f"  Error starting node2: {e}")
            # Try to read debug log if it exists
            log_file = node2_dir / "debug.log"
            if log_file.exists():
                print(f"\n  Debug log content:")
                with open(log_file) as f:
                    print(f.read())
            raise
        time.sleep(2)
        
        info2_start = node2.get_info()
        print(f"  Node2 initial height: {info2_start['blocks']}")
        
        # Wait for connection
        print("\nWaiting for nodes to connect...")
        def nodes_connected():
            try:
                info1 = node1.get_info()
                info2 = node2.get_info()
                return info1.get('connections', 0) > 0 and info2.get('connections', 0) > 0
            except:
                return False
        
        wait_until(nodes_connected, timeout=30, check_interval=1)
        print("  ✓ Nodes connected")
        
        # Monitor sync progress
        print(f"\n{'='*70}")
        print("SYNCING 100,000 BLOCKS...")
        print(f"{'='*70}")
        print(f"{'Time':>8} | {'Height':>8} | {'Progress':>8} | {'Rate':>15} | {'ETA':>8}")
        print(f"{'-'*70}")
        
        sync_start = time.time()
        last_height = 0
        last_time = sync_start
        
        target_height = info1['blocks']
        
        while True:
            time.sleep(5)  # Check every 5 seconds
            
            try:
                info2 = node2.get_info()
                current_height = info2['blocks']
                current_time = time.time()
                elapsed = current_time - sync_start
                
                # Calculate sync rate
                blocks_synced = current_height - info2_start['blocks']
                interval_blocks = current_height - last_height
                interval_time = current_time - last_time
                
                if interval_time > 0:
                    current_rate = interval_blocks / interval_time
                else:
                    current_rate = 0
                
                # Calculate progress
                progress_pct = (blocks_synced / target_height * 100) if target_height > 0 else 0
                
                # Estimate time remaining
                remaining_blocks = target_height - current_height
                if current_rate > 0:
                    eta_seconds = remaining_blocks / current_rate
                    eta_str = f"{int(eta_seconds/60):3d}m {int(eta_seconds%60):02d}s"
                else:
                    eta_str = "N/A"
                
                print(f"{int(elapsed):5d}s | {current_height:8,} | {progress_pct:6.2f}% | "
                      f"{current_rate:6.1f} blk/s | {eta_str:>8}")
                
                last_height = current_height
                last_time = current_time
                
                # Check if sync complete
                if current_height >= target_height:
                    print(f"{'-'*70}")
                    print("✓ SYNC COMPLETE!")
                    break
                    
            except Exception as e:
                print(f"  Error checking sync status: {e}")
                break
        
        sync_end = time.time()
        total_time = sync_end - sync_start
        
        # Final verification
        print(f"\n{'='*70}")
        print("SYNC RESULTS")
        print(f"{'='*70}")
        
        info1_final = node1.get_info()
        info2_final = node2.get_info()
        
        print(f"Node1 height: {info1_final['blocks']:,}")
        print(f"Node2 height: {info2_final['blocks']:,}")
        print(f"Node1 tip: {info1_final['bestblockhash']}")
        print(f"Node2 tip: {info2_final['bestblockhash']}")
        
        if info1_final['bestblockhash'] == info2_final['bestblockhash']:
            print("\n✓ Tips match - sync successful!")
        else:
            print("\n✗ Tips don't match - sync may have failed")
        
        print(f"\n{'='*70}")
        print("PERFORMANCE METRICS")
        print(f"{'='*70}")
        print(f"Total blocks synced: {info2_final['blocks'] - info2_start['blocks']:,}")
        print(f"Total time: {int(total_time/60)}m {int(total_time%60)}s")
        print(f"Average rate: {(info2_final['blocks'] - info2_start['blocks'])/total_time:.1f} blocks/sec")
        print(f"Data transferred: ~{(info2_final['blocks'] - info2_start['blocks']) * 100 / (1024*1024):.1f} MB "
              f"(~100 bytes/header)")
        print(f"{'='*70}")
        
        return 0
        
    except KeyboardInterrupt:
        print("\n\n✗ Interrupted by user")
        return 1
    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    finally:
        print("\nCleaning up...")
        if node1:
            node1.stop()
        if node2:
            node2.stop()
        time.sleep(1)
        
        # Clean up test dir
        try:
            shutil.rmtree(test_dir)
            print(f"Removed test directory: {test_dir}")
        except Exception as e:
            print(f"Warning: Could not remove test directory: {e}")

if __name__ == "__main__":
    sys.exit(main())
