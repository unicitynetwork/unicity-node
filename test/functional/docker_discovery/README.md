# Peer Discovery Functional Tests

Docker-based functional tests for PeerDiscoveryManager, testing ADDR/GETADDR message handling, rate limiting, and address management with real TCP connections.

## Overview

These tests verify the peer discovery subsystem using real network connections from multiple containers across different netgroups (IP /16 subnets). This complements the unit tests by testing actual protocol behavior over the wire.

## Architecture

```
Network Layout:
  discovery_net_1 (172.40.0.0/16)     discovery_net_2 (172.41.0.0/16)     discovery_net_3 (172.42.0.0/16)
  +---------------------------+       +---------------------------+       +---------------------------+
  |  target (172.40.1.1)      |       |  target (172.41.1.1)      |       |  target (172.42.1.1)      |
  |  peer1  (172.40.2.1)      |       |  peer4  (172.41.2.1)      |       |  peer7  (172.42.2.1)      |
  |  peer2  (172.40.3.1)      |       |  peer5  (172.41.3.1)      |       |  peer8  (172.42.3.1)      |
  |  peer3  (172.40.4.1)      |       |  peer6  (172.41.4.1)      |       |  peer9  (172.42.4.1)      |
  |  test_runner (172.40.100.1)|      |  test_runner (172.41.100.1)|      |  test_runner (172.42.100.1)|
  +---------------------------+       +---------------------------+       +---------------------------+

Containers:
  - 1 target node (unicityd under test) - connected to all 3 networks
  - 9 peer containers (3 per netgroup) - for sending P2P messages
  - 1 test_runner container - for orchestrating tests
```

## Tests

| Test | Description |
|------|-------------|
| `addr_rate_limit` | Verify ADDR messages are rate limited by token bucket |
| `addr_netgroup_limit` | Verify MAX_PER_NETGROUP_NEW (32) limit in AddrMan |
| `getaddr_response` | Verify GETADDR returns addresses from AddrMan |
| `getaddr_once_per_connection` | Verify GETADDR only responded to once per connection |
| `token_bucket_boost` | Verify GETADDR boosts token bucket for ADDR response |
| `diverse_netgroup` | Verify addresses from diverse /16s bypass netgroup limit |

## Quick Start

```bash
# From repository root
cd test/functional/docker_discovery

# Build the image (shares Dockerfile with eclipse tests)
docker-compose build

# Start containers
docker-compose up -d

# Wait for target to start (few seconds)
sleep 5

# Run all tests
python3 run_discovery_tests.py

# Run specific test
python3 run_discovery_tests.py --test addr_netgroup_limit

# Cleanup
docker-compose down -v
```

## Security Constants Tested

These constants are defined in the C++ implementation and tested here:

| Constant | Value | Description |
|----------|-------|-------------|
| `MAX_PER_NETGROUP_NEW` | 32 | Max addresses from same /16 in NEW table |
| `MAX_ADDR_TO_SEND` | 1000 | Max addresses in ADDR response |
| `MAX_ADDR_RATE_PER_SECOND` | 0.1 | Token bucket refill rate |
| `MAX_ADDR_PROCESSING_TOKEN_BUCKET` | 1000 | Max token bucket capacity |

## Test Details

### Test 1: ADDR Rate Limiting

Sends multiple ADDR messages in rapid succession. Due to token bucket rate limiting, most should be dropped:

- Token bucket starts at 1.0
- Each address consumes 1.0 token
- Refill rate: 0.1 tokens/second
- Expected: First few addresses accepted, rest rate limited

### Test 2: Per-Netgroup Limit

Sends 50 addresses all from the same /16 netgroup:

- MAX_PER_NETGROUP_NEW = 32
- Expected: Only 32 addresses stored in AddrMan
- Prevents eclipse attacks from single IP range

### Test 3: GETADDR Response

Seeds target's AddrMan with addresses, then sends GETADDR:

- Addresses seeded from diverse /16s
- GETADDR should return subset of known addresses
- Verifies basic address discovery flow

### Test 4: GETADDR Once Per Connection

Sends GETADDR twice on the same connection:

- First GETADDR returns addresses
- Second GETADDR is ignored (returns 0)
- Prevents address enumeration attacks

### Test 5: Token Bucket Boost

Verifies that after sending GETADDR, the token bucket is boosted:

- Normally ADDR messages are heavily rate limited
- After sending GETADDR, we should accept the response
- Bucket boosted by MAX_ADDR_PROCESSING_TOKEN_BUCKET (1000)

### Test 6: Diverse Netgroup Acceptance

Sends 100 addresses from 100 different /16 netgroups:

- Should accept significantly more than MAX_PER_NETGROUP_NEW (32)
- Verifies per-netgroup limit is per-/16, not global
- Important for healthy address diversity

## Troubleshooting

### Containers not starting

```bash
# Check logs
docker-compose logs target
docker-compose logs peer1

# Rebuild image
docker-compose build --no-cache
```

### Tests failing with "Could not connect"

```bash
# Verify target is running
docker exec discovery_target ps aux | grep unicityd

# Check target logs
docker logs discovery_target

# Test connectivity manually
docker exec discovery_peer1 nc -zv 172.40.1.1 29590
```

### Port conflicts

The discovery tests use different ports than eclipse tests:
- P2P: 29690 (host) -> 29590 (container)
- RPC: 29691 (host) -> 29591 (container)

If conflicts occur, modify `docker-compose.yml` ports section.

## Comparison with Unit Tests

| Aspect | Unit Tests | Docker Tests |
|--------|------------|--------------|
| Speed | Fast (ms) | Slow (seconds) |
| Network | Mocked | Real TCP |
| Multiple IPs | Simulated addresses | Real source IPs |
| Netgroup testing | Address generation tricks | Actual /16 subnets |
| Rate limiting | Synthetic time | Real time |
| CI Integration | Always | Requires Docker |

Both test types are valuable - unit tests for rapid iteration, docker tests for integration confidence.

## Files

```
docker_discovery/
├── docker-compose.yml      # Container orchestration
├── run_discovery_tests.py  # Test script
└── README.md               # This file
```

Note: Uses shared Dockerfile from `docker_eclipse/Dockerfile`.
