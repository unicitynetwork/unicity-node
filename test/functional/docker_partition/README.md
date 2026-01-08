# Network Partition Tests

Docker-based tests for network partition tolerance and recovery.

## Overview

These tests verify that the node handles network partitions correctly:
- Continues operating during partitions
- Converges to the correct chain after recovery
- Detects stale tips appropriately

## Network Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Partition A: 172.31.0.0/16                                 │
│    Node A1: 172.31.1.1 (also on bridge: 172.33.1.1)        │
│    Node A2: 172.31.2.1                                      │
│    Node A3: 172.31.3.1                                      │
├─────────────────────────────────────────────────────────────┤
│  Partition B: 172.32.0.0/16                                 │
│    Node B1: 172.32.1.1 (also on bridge: 172.33.2.1)        │
│    Node B2: 172.32.2.1                                      │
│    Node B3: 172.32.3.1                                      │
├─────────────────────────────────────────────────────────────┤
│  Bridge Network: 172.33.0.0/16                              │
│    Bridge Node: 172.33.100.1 (connects A and B)            │
│    Test Runner: 172.33.200.1                                │
└─────────────────────────────────────────────────────────────┘

Total: 7 nodes + 1 test runner = 8 containers
```

## How Partitions Work

Partitions are created using `iptables` inside containers:

```bash
# Block traffic from bridge to partition A
iptables -A OUTPUT -d 172.31.1.1 -j DROP

# Restore traffic
iptables -D OUTPUT -d 172.31.1.1 -j DROP
```

All containers have `CAP_NET_ADMIN` to allow iptables manipulation.

## Tests

| # | Test | Description |
|---|------|-------------|
| 1 | `basic_partition` | Verify iptables isolation works |
| 2 | `partition_sync` | Nodes sync within isolated partitions |
| 3 | `partition_divergence` | Different chains grow on each side |
| 4 | `partition_recovery` | Reconnect and verify convergence |
| 5 | `stale_tip_detection` | Detect stale tip after partition |

## Quick Start

```bash
# From repo root, ensure image is built
docker build -t eclipse-test -f test/functional/docker_eclipse/Dockerfile .

# Start partition containers
cd test/functional/docker_partition
docker-compose up -d

# Wait for nodes to sync (10-15 seconds)
sleep 15

# Run all tests
python3 run_partition_tests.py

# Run specific test
python3 run_partition_tests.py --test basic_partition

# Cleanup
docker-compose down -v
```

## Container Commands

```bash
# Check node logs
docker logs partition_node_bridge

# Execute command in container
docker exec partition_node_a1 /app/build/bin/unicityd --help

# Check iptables rules
docker exec partition_node_bridge iptables -L OUTPUT -n

# Manual partition (block A1 from bridge)
docker exec partition_node_bridge iptables -A OUTPUT -d 172.31.1.1 -j DROP

# Manual restore
docker exec partition_node_bridge iptables -D OUTPUT -d 172.31.1.1 -j DROP

# Clear all rules
docker exec partition_node_bridge iptables -F OUTPUT
```

## Test Scenarios

### Basic Partition Test

Verifies that iptables can effectively isolate networks:

1. Verify initial connectivity (bridge can reach A1)
2. Add iptables DROP rule
3. Verify isolation (bridge cannot reach A1)
4. Remove iptables rule
5. Verify connectivity restored

### Partition Sync Test

Verifies nodes continue syncing within their partition:

1. Create partition between A and B
2. Verify nodes in partition A sync with each other
3. Verify nodes in partition B sync with each other
4. Verify cross-partition communication blocked

### Partition Divergence Test

Verifies chains can diverge during partition (requires mining):

1. Create partition
2. Mine blocks only on partition A
3. Mine different blocks on partition B
4. Verify different chain tips

### Partition Recovery Test

Verifies correct chain selection after recovery:

1. Create partition
2. Allow chains to diverge
3. Restore connectivity
4. Verify all nodes converge to longest chain

### Stale Tip Detection Test

Verifies nodes detect when their tip is stale:

1. Create partition
2. Mine blocks on one side only
3. Restore connectivity
4. Verify stale side detects it's behind
5. Verify stale side catches up

## Adding Mining Capability

For full partition divergence testing, the test needs mining capability.
This can be added by:

1. Using the `generatetoaddress` RPC call
2. Implementing a simple CPU miner in the test
3. Using pre-mined test blocks

## Troubleshooting

### Containers not starting

```bash
# Check container status
docker-compose ps

# Check logs for errors
docker logs partition_node_bridge
```

### iptables not working

```bash
# Verify NET_ADMIN capability
docker exec partition_node_bridge capsh --print | grep net_admin

# Check if iptables is available
docker exec partition_node_bridge which iptables
```

### Nodes not connecting

```bash
# Check if nodes are listening
docker exec partition_node_a1 netstat -tlnp | grep 29590

# Check connection attempts in logs
docker logs partition_node_bridge 2>&1 | grep -i connect
```

## Files

| File | Purpose |
|------|---------|
| `docker-compose.yml` | Container and network configuration |
| `run_partition_tests.py` | Python test orchestrator |
| `README.md` | This documentation |
