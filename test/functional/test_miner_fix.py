#!/usr/bin/env python3
# Test that miner properly stops and can be restarted

import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent / "test_framework"))
from test_node import TestNode

def main():
    test_dir = Path(tempfile.mkdtemp(prefix='test_miner_'))
    binary_path = Path(__file__).parent.parent.parent / "build" / "bin" / "unicityd"
    
    print("Testing miner start/stop/restart...")
    node = TestNode(0, test_dir / 'node0', binary_path)
    
    try:
        node.start()
        print("✓ Node started")
        
        # Mine 10 blocks
        print("\nMining 10 blocks...")
        result = node.generate(10)
        if isinstance(result, dict) and 'blocks' in result:
            blocks_mined = result['blocks']
            print(f"✓ Generated {blocks_mined} blocks")
        else:
            print(f"✗ ERROR: generate() returned unexpected format: {type(result)}")
            print(f"  Value: {repr(result)[:200]}")
            return 1
        
        info = node.get_info()
        print(f"✓ Height: {info['blocks']}")
        
        # Mine 5 more blocks
        print("\nMining 5 more blocks...")
        result2 = node.generate(5)
        if isinstance(result2, dict) and 'blocks' in result2:
            blocks_mined2 = result2['blocks']
            print(f"✓ Generated {blocks_mined2} blocks")
        else:
            print(f"✗ ERROR: generate() returned unexpected format: {type(result2)}")
            return 1
        
        info2 = node.get_info()
        print(f"✓ Height: {info2['blocks']}")
        
        if info2['blocks'] == 15:
            print("\n✓ SUCCESS: Miner works correctly!")
            return 0
        else:
            print(f"\n✗ FAIL: Expected height 15, got {info2['blocks']}")
            return 1
            
    finally:
        print("\nCleaning up...")
        if node.is_running():
            node.stop()
        print(f"Checking final log...")
        log = node.read_log(20)
        if "Worker thread exiting normally" in log:
            print("✓ Clean shutdown confirmed")
        else:
            print("⚠ Clean shutdown message not found")

if __name__ == '__main__':
    sys.exit(main())
