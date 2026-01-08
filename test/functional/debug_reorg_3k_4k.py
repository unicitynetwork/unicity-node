#!/usr/bin/env python3
"""Debug test: Why doesn't 3000-block node reorg to 4000-block node?"""

import sys
import time
import tempfile
import shutil
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "test_framework"))
from test_node import TestNode
from util import pick_free_port

def main():
    print("=== Debug: 3000 vs 4000 block reorg ===\n")
    
    # Need to generate 3k and 4k chains first
    test_chains = Path(__file__).parent / "test_chains"
    base_chain = test_chains / "chain_1000_blocks_base"
    
    if not base_chain.exists():
        print("ERROR: Base chain not found. Run generate_reorg_chains.py first")
        return 1
    
    print("Step 1: Generating 3000 and 4000 block chains...")
    temp_gen = Path(tempfile.mkdtemp(prefix="gen_"))
    
    # Generate 3k chain
    print("  Generating 3000-block chain...")
    chain_3k = temp_gen / "chain_3k"
    shutil.copytree(base_chain, chain_3k)
    
    port = pick_free_port()
    node = TestNode(0, chain_3k, extra_args=["--listen", f"--port={port}", "--connect=0"])
    node.start()
    time.sleep(1)
    node.generate(2000, "0000000000000000000000000000000000000000", timeout=300)
    info_3k = node.get_info()
    print(f"    Chain 3k: height={info_3k['blocks']}, tip={info_3k['bestblockhash'][:16]}...")
    node.stop()
    time.sleep(1)
    
    # Generate 4k chain  
    print("  Generating 4000-block chain...")
    chain_4k = temp_gen / "chain_4k"
    shutil.copytree(base_chain, chain_4k)
    
    node = TestNode(0, chain_4k, extra_args=["--listen", f"--port={port}", "--connect=0"])
    node.start()
    time.sleep(1)
    node.generate(3000, "1111111111111111111111111111111111111111", timeout=300)
    info_4k = node.get_info()
    print(f"    Chain 4k: height={info_4k['blocks']}, tip={info_4k['bestblockhash'][:16]}...")
    node.stop()
    time.sleep(1)
    
    print("\nStep 2: Starting test with 3k and 4k chains...")
    test_base = Path(tempfile.mkdtemp(prefix="debug_reorg_"))
    
    # Copy chains
    shutil.copytree(chain_3k, test_base / "node0")
    shutil.copytree(chain_4k, test_base / "node1")
    
    port0 = pick_free_port()
    port1 = pick_free_port()
    
    # Start both nodes with DEBUG logging on node0
    node0 = TestNode(0, test_base / "node0",
                    extra_args=["--listen", f"--port={port0}", "--connect=0",
                               "--suspiciousreorgdepth=10000", "--loglevel=debug"])
    node1 = TestNode(1, test_base / "node1",
                    extra_args=["--listen", f"--port={port1}", "--connect=0",
                               "--suspiciousreorgdepth=10000", "--loglevel=debug"])
    
    node0.start()
    node1.start()
    time.sleep(2)
    
    print(f"\nNode 0: port {port0}, height={node0.get_info()['blocks']}")
    print(f"Node 1: port {port1}, height={node1.get_info()['blocks']}")
    
    # Connect node0 to node1
    print(f"\nStep 3: Connecting Node 0 → Node 1...")
    node0.add_node(f"127.0.0.1:{port1}", "add")
    
    print("  Waiting 60 seconds for sync...")
    for i in range(12):
        time.sleep(5)
        info0 = node0.get_info()
        info1 = node1.get_info()
        print(f"    [{(i+1)*5:2d}s] Node0: height={info0['blocks']}, headers={info0.get('headers', info0['blocks'])} | " +
              f"Node1: height={info1['blocks']}, headers={info1.get('headers', info1['blocks'])}")
        
        if info0['blocks'] == 4000:
            print(f"\n✓ SUCCESS! Node 0 reorged to 4000 blocks")
            print(f"  Node 0 tip: {info0['bestblockhash']}")
            print(f"  Node 1 tip: {info1['bestblockhash']}")
            break
    else:
        print(f"\n✗ FAILED: Node 0 did not reorg to 4000 blocks")
        print(f"\n=== Node 0 Log (last 200 lines) ===")
        print(node0.read_log(200))
        print(f"\n=== Node 1 Log (last 200 lines) ===")
        print(node1.read_log(200))
        
        # Check peer info
        print(f"\n=== Node 0 Peer Info ===")
        try:
            peers = node0.get_peer_info()
            print(f"Peers: {len(peers)}")
            for p in peers:
                print(f"  Peer {p.get('id')}: addr={p.get('addr')}, inbound={p.get('inbound')}, " +
                      f"height={p.get('startingheight')}")
        except Exception as e:
            print(f"  Error getting peer info: {e}")
    
    # Cleanup
    node0.stop()
    node1.stop()
    shutil.rmtree(test_base, ignore_errors=True)
    shutil.rmtree(temp_gen, ignore_errors=True)
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
