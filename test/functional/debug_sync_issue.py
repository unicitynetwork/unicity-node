#!/usr/bin/env python3
# Debug sync issue - why doesn't Node0 sync all 100 blocks?

import sys
import time
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "test_framework"))
from test_node import TestNode

def main():
    test_dir = Path(tempfile.mkdtemp(prefix='debug_sync_'))
    binary_path = Path(__file__).parent.parent.parent / "build" / "bin" / "unicity"
    
    print("=== DEBUGGING SYNC ISSUE ===")
    print(f"Test directory: {test_dir}\n")
    
    # Node0: Starts at genesis with DEBUG logging
    node0 = TestNode(0, test_dir / 'node0', binary_path,
                     extra_args=["--listen", "--port=18444", "--debug=network,sync"])
    
    # Node1: Will mine 100 blocks
    node1 = TestNode(1, test_dir / 'node1', binary_path,
                     extra_args=["--listen", "--port=18445"])
    
    try:
        print("1. Starting Node0 (at genesis, with debug logging)...")
        node0.start()
        info0 = node0.get_info()
        print(f"   Node0: height={info0['blocks']}\n")
        
        print("2. Starting Node1 and mining 100 blocks...")
        node1.start()
        result = node1.generate(100)
        print(f"   Generated {result.get('blocks', 0)} blocks")
        info1 = node1.get_info()
        print(f"   Node1: height={info1['blocks']}, hash={info1['bestblockhash'][:16]}...\n")
        
        print("3. Connecting Node0 to Node1...")
        node0.add_node("127.0.0.1:18445", "add")
        print("   Connection initiated\n")
        
        print("4. Monitoring sync for 30 seconds...")
        for i in range(6):
            time.sleep(5)
            info0 = node0.get_info()
            print(f"   {(i+1)*5}s: Node0 height={info0['blocks']}/100")
            if info0['blocks'] == 100:
                print("   Sync complete!")
                break
        
        print("\n5. Final state:")
        info0 = node0.get_info()
        info1 = node1.get_info()
        print(f"   Node0: height={info0['blocks']}, hash={info0['bestblockhash'][:16]}...")
        print(f"   Node1: height={info1['blocks']}, hash={info1['bestblockhash'][:16]}...")
        
        if info0['blocks'] == 100 and info0['bestblockhash'] == info1['bestblockhash']:
            print("\n✓ SUCCESS: Full sync achieved!")
            return 0
        else:
            print(f"\n✗ SYNC INCOMPLETE: Node0 at {info0['blocks']}/100")
            print(f"\nCheck debug logs for sync messages:")
            print(f"  {test_dir}/node0/debug.log")
            return 1
            
    finally:
        print("\n6. Stopping nodes...")
        if node0.is_running():
            node0.stop()
        if node1.is_running():
            node1.stop()

if __name__ == '__main__':
    sys.exit(main())
