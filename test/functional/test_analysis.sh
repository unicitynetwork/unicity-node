#!/bin/bash

# Test each functional test with timeout
TESTS=(
    "basic_mining.py:30:Basic mining test"
    "feature_fork_resolution.py:60:Fork resolution"
    "feature_chainstate_persistence.py:90:Chainstate persistence"
    "p2p_connect.py:60:P2P connection"
    "p2p_three_nodes.py:60:3-node network"
    "feature_multinode_sync.py:90:Multinode sync"
    "p2p_ibd.py:90:Initial block download"
)

echo "=== FUNCTIONAL TEST ANALYSIS ==="
echo

PASSED=0
FAILED=0
TIMEOUT=0

for test in "${TESTS[@]}"; do
    IFS=':' read -r file timeout desc <<< "$test"
    echo -n "Testing: $desc ... "
    
    if timeout $timeout python3 "$file" > /tmp/test_out.txt 2>&1; then
        echo "✓ PASS"
        ((PASSED++))
    else
        status=$?
        if [ $status -eq 124 ]; then
            echo "✗ TIMEOUT (>${timeout}s)"
            ((TIMEOUT++))
        else
            echo "✗ FAIL"
            ((FAILED++))
            tail -5 /tmp/test_out.txt | sed 's/^/  /'
        fi
    fi
done

echo
echo "=== RESULTS ==="
echo "Passed:  $PASSED"
echo "Failed:  $FAILED"
echo "Timeout: $TIMEOUT"
