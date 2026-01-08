#!/bin/bash

# Time each functional test
TESTS=(
    "basic_mining.py"
    "feature_fork_resolution.py"
    "feature_chainstate_persistence.py"
    "p2p_connect.py"
    "p2p_three_nodes.py"
    "feature_multinode_sync.py"
    "p2p_ibd.py"
    "feature_suspicious_reorg.py"
    "p2p_batching.py"
    "p2p_dos_headers.py"
    "p2p_eviction.py"
    "p2p_reorg.py"
    "feature_concurrent_peer_validation.py"
    "feature_concurrent_stress.py"
    "feature_chaos_convergence.py"
)

echo "=== FUNCTIONAL TEST TIMING ANALYSIS ==="
echo

for test in "${TESTS[@]}"; do
    echo -n "Testing: $test ... "
    
    start=$(date +%s)
    if timeout 300 python3 "$test" > /tmp/test_out.txt 2>&1; then
        end=$(date +%s)
        elapsed=$((end - start))
        echo "✓ PASS (${elapsed}s)"
    else
        end=$(date +%s)
        elapsed=$((end - start))
        status=$?
        if [ $status -eq 124 ]; then
            echo "✗ TIMEOUT (>300s)"
        else
            echo "✗ FAIL (${elapsed}s)"
        fi
    fi
done

echo
