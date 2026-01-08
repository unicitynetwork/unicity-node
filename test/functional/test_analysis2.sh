#!/bin/bash

# Test remaining tests including stress tests
TESTS=(
    "feature_suspicious_reorg.py:60:Suspicious reorg detection"
    "p2p_batching.py:60:P2P message batching"
    "p2p_dos_headers.py:60:DoS headers protection"
    "p2p_eviction.py:60:Peer eviction"
    "p2p_reorg.py:120:P2P reorg handling"
    "feature_concurrent_peer_validation.py:120:Concurrent peer validation"
    "feature_concurrent_stress.py:300:Concurrent stress (20 peers)"
    "feature_chaos_convergence.py:600:Chaos convergence (20 peers)"
)

echo "=== ADDITIONAL TEST ANALYSIS ==="
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
            echo "  Error:" 
            tail -3 /tmp/test_out.txt | sed 's/^/    /'
        fi
    fi
done

echo
echo "=== RESULTS ==="
echo "Passed:  $PASSED"
echo "Failed:  $FAILED"  
echo "Timeout: $TIMEOUT"
