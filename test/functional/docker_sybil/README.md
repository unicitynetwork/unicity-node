# Docker Sybil Attack Tests

Coordinated multi-node adversarial tests that simulate sophisticated attack scenarios using multiple attacker nodes.

## Tests

| Test | Description |
|------|-------------|
| `addr_poison` | 10 attackers flood ADDR messages to poison address manager |
| `partition_flood` | Partition target, then flood with connections on reconnect |
| `header_conflict` | Multiple peers send conflicting GETHEADERS simultaneously |
| `selective_relay` | Some peers refuse to respond to requests |

## Prerequisites

1. Build the test Docker image:
```bash
cd /path/to/unicity-node
docker build -t unicity-node:test -f test/functional/Dockerfile .
```

2. Start the containers:
```bash
cd test/functional/docker_sybil
docker-compose up -d
```

## Running Tests

Run all tests:
```bash
python3 run_sybil_tests.py
```

Run a specific test:
```bash
python3 run_sybil_tests.py --test addr_poison
python3 run_sybil_tests.py --test partition_flood
python3 run_sybil_tests.py --test header_conflict
python3 run_sybil_tests.py --test selective_relay
```

## Network Topology

```
172.50.0.0/16 (sybil_net)
├── 172.50.0.2    - sybil_target (target node)
├── 172.50.0.100  - sybil_runner (test runner)
└── 172.50.1.1-10 - sybil_attacker1-10 (attacker nodes)
```

All attackers are in the same /16 netgroup (172.50.x.x) to test:
- `MAX_PER_NETGROUP_NEW` limits in address manager
- Eviction-based netgroup limiting (~4 connections per /16)
- Netgroup-based eviction behavior (Bitcoin Core parity)

## Test Details

### addr_poison
Tests address manager resistance to coordinated ADDR flooding:
1. 10 attackers connect to target
2. Each sends ADDR with 110 addresses (10 attacker IPs + 100 fake IPs in same /16)
3. Repeat 5 times over 10 seconds
4. Verify target remains healthy and netgroup limits held

### partition_flood
Tests reconnection surge handling:
1. Establish connections from all attackers
2. Partition target using iptables (block all traffic)
3. Wait for connections to timeout
4. Remove partition - trigger reconnection flood
5. All reconnected peers send GETHEADERS simultaneously
6. Verify target handles surge without crash

### header_conflict
Tests concurrent header processing:
1. Connect 5 peers
2. All send GETHEADERS simultaneously
3. Verify no race conditions or crashes

### selective_relay
Tests handling of unresponsive peers:
1. Connect 6 peers (4 silent, 2 responsive)
2. Silent peers ignore requests
3. Verify target still functions with partial responses

## Cleanup

```bash
docker-compose down -v
```
