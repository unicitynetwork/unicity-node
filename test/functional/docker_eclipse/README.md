# Docker-based Eclipse Attack Tests

Tests eclipse attack defenses using real TCP connections from multiple source IPs.

## Why Docker?

Eclipse attack defenses like per-netgroup limits require connections from different IPs.
Regular functional tests run from localhost (single IP), so they can't test:

- `MAX_INBOUND_PER_NETGROUP` (4 connections per /16 subnet)
- Sybil attacks from distributed IPs
- Eviction algorithm behavior under realistic attack

Docker containers provide isolated network namespaces with different IPs.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Docker Network: 172.28.0.0/16            │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐     │
│  │   Victim    │    │  Attacker1  │    │  Attacker2  │     │
│  │ 172.28.1.1  │◄───│ 172.28.2.1  │    │ 172.28.3.1  │     │
│  │  unicityd   │◄───│             │    │             │     │
│  └─────────────┘    └─────────────┘    └─────────────┘     │
│         ▲                                                   │
│         │           ┌─────────────┐    ┌─────────────┐     │
│         │           │  Attacker3  │    │  Attacker4  │     │
│         └───────────│ 172.28.4.1  │    │ 172.28.5.1  │     │
│                     │             │    │             │     │
│                     └─────────────┘    └─────────────┘     │
│                                                             │
│  ┌─────────────┐                                           │
│  │ Test Runner │  Orchestrates attacks, verifies results   │
│  │ 172.28.100.1│                                           │
│  └─────────────┘                                           │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start

```bash
# Build and start containers
cd test/functional/docker_eclipse
docker-compose build
docker-compose up -d

# Wait for victim to initialize
sleep 5

# Run all eclipse tests
python3 run_eclipse_tests.py

# Or run specific test
python3 run_eclipse_tests.py --test netgroup_limit

# Cleanup
docker-compose down -v
```

## Tests

### 1. Netgroup Limit Test

Verifies `MAX_INBOUND_PER_NETGROUP = 4` is enforced.

All 5 attacker containers are in the same /16 subnet (172.28.x.x).
Only 4 connections should succeed.

```bash
python3 run_eclipse_tests.py --test netgroup_limit
```

### 2. Sybil Flood Test

Simulates a Sybil attack where each attacker attempts multiple connections.

Connections are limited by:
- `MAX_INBOUND_PER_NETGROUP = 4` (per /16 subnet)
- Note: Bitcoin Core parity - no per-IP limit; relies on netgroup eviction

```bash
python3 run_eclipse_tests.py --test sybil_flood
```

### 3. Eviction Test

Verifies the eviction algorithm limits total inbound connections.

```bash
python3 run_eclipse_tests.py --test eviction
```

## Expected Results

```
=== TEST: Netgroup Limit ===
Connecting from attacker1... SUCCESS
Connecting from attacker2... SUCCESS
Connecting from attacker3... SUCCESS
Connecting from attacker4... SUCCESS
Connecting from attacker5... REJECTED  <-- 5th rejected (limit = 4)

Results: 4/5 connections accepted
PASS: Netgroup limit enforced
```

## Extending Tests

To add more attackers in different netgroups, create additional networks:

```yaml
networks:
  eclipse_net_1:
    ipam:
      config:
        - subnet: 172.28.0.0/16
  eclipse_net_2:
    ipam:
      config:
        - subnet: 172.29.0.0/16  # Different /16 = different netgroup
```

## Troubleshooting

### Containers not starting

```bash
docker-compose logs victim
```

### Connection tests failing

```bash
# Check victim is listening
docker exec eclipse_victim netstat -tlnp

# Check from attacker
docker exec eclipse_attacker1 nc -zv 172.28.1.1 29590
```

### RPC not responding

```bash
docker exec eclipse_victim /app/build/bin/unicity-cli --regtest getinfo
```

## Block-Relay-Only Tests

Test the eclipse attack resistance of BLOCK_RELAY_ONLY connections:

```bash
# Run all block-relay tests
python3 run_block_relay_tests.py

# Run specific test
python3 run_block_relay_tests.py --test invisibility
```

### Available Tests

1. **invisibility** - Block-relay peers are NOT returned in GETADDR responses
2. **addr_filter** - ADDR message filtering for block-relay connections
3. **eclipse_resistance** - Block-relay connections survive AddrMan poisoning
4. **slot_saturation** - Attackers cannot consume block-relay (outbound) slots
5. **enumeration** - Multi-phase enumeration attack resistance

### Why Block-Relay Matters

Block-relay connections are "secret" outbound connections that:
- Don't participate in address relay (ADDR/GETADDR)
- Are NOT added to AddrMan (invisible to attackers)
- Provide eclipse attack resistance even if attacker controls all known addresses
- Are established to anchors/seeds, not from (potentially poisoned) AddrMan

```
Normal Attack:
1. Attacker poisons AddrMan with only attacker addresses
2. Node restarts, connects to AddrMan addresses (all attacker!)
3. Node is eclipsed

With Block-Relay Defense:
1. Attacker poisons AddrMan with only attacker addresses
2. Node restarts, connects to AddrMan addresses (attacker) BUT ALSO
3. Node makes 2 block-relay connections to anchors (NOT from AddrMan)
4. Block-relay connections provide honest chain view
5. Eclipse attack FAILS
```

## Comparison with Unit Tests

| Aspect | Unit Tests (C++) | Docker Tests |
|--------|-----------------|--------------|
| Speed | Fast (ms) | Slow (seconds) |
| Setup | None | Docker required |
| Multiple IPs | Simulated | Real |
| Network stack | Mocked | Real TCP |
| CI friendly | Yes | Needs Docker |

Both are valuable:
- Unit tests: Fast feedback during development
- Docker tests: Verify real-world behavior before deployment
