# Docker-Based Testing Framework

Docker enables testing scenarios that are impossible with localhost-only tests:

- **Multiple IP addresses** - Test per-IP and per-netgroup limits
- **Network partitions** - Simulate network splits
- **Multi-node topologies** - Test realistic network configurations
- **Latency/bandwidth** - Simulate real network conditions
- **Persistence** - Test data survival across restarts

## Test Scenarios

| Scenario | Directory | Status | Description |
|----------|-----------|--------|-------------|
| Eclipse Attacks | `docker_eclipse/` | Ready | Multi-IP eclipse attack resistance (10 tests) |
| Network Partitions | `docker_partition/` | Ready | Network split and recovery (5 tests) |
| Multi-Node Sync | `docker_sync/` | TODO | IBD and sync across many nodes |
| Latency Testing | `docker_latency/` | TODO | High-latency network conditions |

## Shared Infrastructure

All Docker tests share:
- `Dockerfile` - Base image with `unicityd` and `node_simulator`
- Pre-built image: `eclipse-test` (can be renamed to `unicity-test`)

## Quick Start

```bash
# Build shared image (from repo root)
docker build -t unicity-test -f test/functional/docker_eclipse/Dockerfile .

# Run eclipse tests
cd test/functional/docker_eclipse
docker-compose up -d
python3 run_eclipse_tests.py
docker-compose down -v
```

## Creating New Docker Tests

1. Create new directory: `docker_<scenario>/`
2. Create `docker-compose.yml` using `image: unicity-test`
3. Create test runner script
4. Document in this README

## Available Test Types

### 1. Eclipse Attack Tests (`docker_eclipse/`)

Tests requiring multiple source IPs:
- Eviction-based netgroup limiting (Bitcoin Core parity)
- Netgroup-aware eviction (targets overrepresented netgroups)
- Multi-netgroup Sybil attacks
- Malformed packet handling (via node_simulator)
- Misbehavior banning

### 2. Network Partition Tests (`docker_partition/`)

Test network split scenarios using iptables:
- **basic_partition**: Verify iptables isolation works
- **partition_sync**: Nodes sync within isolated partitions
- **partition_divergence**: Different chains grow on each side
- **partition_recovery**: Reconnect and verify convergence
- **stale_tip_detection**: Detect stale tip after partition

```bash
cd test/functional/docker_partition
docker-compose up -d
python3 run_partition_tests.py
docker-compose down -v
```

### 3. Multi-Node Sync Tests (TODO: `docker_sync/`)

Test sync across realistic topologies:
- Hub-and-spoke network
- Linear chain of nodes
- Mesh network
- IBD from multiple peers

### 4. Latency Tests (TODO: `docker_latency/`)

Test behavior under poor network conditions:
- High latency (100ms+)
- Packet loss
- Bandwidth limits
- Jitter

## Network Configuration Examples

### Multi-Netgroup (Eclipse Tests)
```yaml
networks:
  net_172_28:
    ipam:
      config:
        - subnet: 172.28.0.0/16
  net_172_29:
    ipam:
      config:
        - subnet: 172.29.0.0/16
```

### Network with Latency (tc/netem)
```yaml
services:
  node_slow:
    cap_add:
      - NET_ADMIN
    command: >
      sh -c "tc qdisc add dev eth0 root netem delay 100ms &&
             /app/build/bin/unicityd --regtest"
```

### Network Partition (iptables)
```yaml
services:
  node_isolated:
    cap_add:
      - NET_ADMIN
    # Use iptables to block specific IPs
```

## Comparison with Functional Tests

| Aspect | Functional Tests | Docker Tests |
|--------|-----------------|--------------|
| Multiple IPs | No (localhost only) | Yes |
| Network partitions | No | Yes |
| Latency simulation | No | Yes |
| Speed | Fast | Slower |
| CI complexity | Low | Higher |
| Real TCP stack | Yes | Yes |
