# Node Simulator - P2P Protocol Testing Tool

A C++ utility for testing P2P protocol behavior and DoS protection mechanisms in the Unicity network.

**WARNING: This tool sends adversarial P2P messages for testing. Only use on private test networks!**

## Purpose

This tool connects to a running node via TCP and sends various types of P2P messages to test protocol behavior, DoS protection, and edge case handling. It performs a proper P2P handshake before executing test scenarios.

## Building

The tool is built automatically with the main project:

```bash
cmake -S . -B build
cmake --build build --target node_simulator
```

Binary location: `build/bin/node_simulator`

## Usage

```bash
./build/bin/node_simulator [options]
```

### Options

| Option | Description |
|--------|-------------|
| `--host <host>` | Target host (default: 127.0.0.1) |
| `--port <port>` | Target port (default: 29590 regtest) |
| `--test <type>` | Test scenario type (default: all) |
| `--help` | Show help message |

### Examples

```bash
# Show help with all test types
./build/bin/node_simulator --help

# Test invalid PoW scenario
./build/bin/node_simulator --test invalid-pow

# Test slow-loris attack
./build/bin/node_simulator --test slow-loris

# Target a specific host/port
./build/bin/node_simulator --host 192.168.1.100 --port 29590 --test oversized

# Run all test scenarios
./build/bin/node_simulator --test all
```

## Test Scenarios

### Header Attacks
| Test | Description |
|------|-------------|
| `invalid-pow` | Send headers with invalid proof-of-work |
| `oversized` | Send oversized headers message (>2000 headers) |
| `non-continuous` | Send non-continuous headers (broken chain) |
| `spam-continuous` | Spam with non-continuous headers (5x) |

### Framing Attacks
| Test | Description |
|------|-------------|
| `slow-loris` | Drip a large payload slowly (chunked) |
| `bad-magic` | Wrong 4-byte message magic |
| `bad-checksum` | Corrupted header checksum |
| `bad-length` | Declared length > actual then close |
| `truncation` | Send half payload then close |
| `empty-command` | Message with empty command field |
| `length-short` | Declared length < actual payload |
| `length-max` | Declared length > MAX (16MB) |
| `command-null` | Command with embedded null bytes |
| `command-non-ascii` | Command with non-ASCII bytes |

### Handshake Attacks
| Test | Description |
|------|-------------|
| `pre-handshake` | Send HEADERS before VERSION/VERACK |
| `pre-handshake-gh` | Send GETHEADERS before handshake |
| `pre-handshake-inv` | Send INV before handshake |
| `pre-handshake-gd` | Send GETDATA before handshake |
| `verack-first` | Send VERACK without VERSION |
| `multi-verack` | Send VERACK twice |
| `silent` | Connect but send nothing |
| `stalled-handshake` | Send VERSION, never send VERACK |
| `duplicate-version` | Send VERSION twice |
| `bad-version` | VERSION with invalid fields |
| `partial-version` | Send truncated VERSION message |

### VERSION Variants
| Test | Description |
|------|-------------|
| `ver-bad-height` | VERSION with start_height = -1 |
| `ver-long-ua` | VERSION with 300-char user agent |
| `ver-old-proto` | VERSION with protocol version 209 |
| `ver-future-time` | VERSION timestamp 1 year in future |
| `sendheaders-pre` | SENDHEADERS before VERSION |

### Rate Limit Attacks
| Test | Description |
|------|-------------|
| `unknown-cmd` | Send unknown command |
| `unknown-cmd-flood` | Flood unknown commands (25x) |

### Header Validation Attacks
| Test | Description |
|------|-------------|
| `future-timestamp` | Headers with time > now + 10min |
| `timestamp-zero` | Headers with timestamp = 0 |
| `nbits-zero` | Headers with nBits = 0 |
| `nbits-max` | Headers with nBits = 0xFFFFFFFF |
| `self-ref` | Header with self-referential prevblock |
| `circular-chain` | Circular header chain (A->B->A) |
| `version-zero-hdr` | Header with nVersion = 0 |
| `neg-version-hdr` | Header with nVersion = -1 |
| `unconnecting-flood` | Flood with unconnecting headers (100x) |
| `getheaders-spam` | Rapid GETHEADERS requests (50x) |

### Message Type Attacks
| Test | Description |
|------|-------------|
| `addr-flood` | Large ADDR message (1000 addrs) |
| `inv-spam` | Spam INV messages (100x) |
| `inv-bad-type` | INV with invalid type (99) |
| `inv-repeat` | Same INV hash 100 times |
| `getaddr-spam` | 50 GETADDR requests |
| `sendheaders-dbl` | SENDHEADERS twice |

### PING/PONG Attacks
| Test | Description |
|------|-------------|
| `pong-no-ping` | PONG without receiving PING |
| `pong-wrong-nonce` | PONG with wrong nonce |
| `ping-zero-nonce` | PING with nonce = 0 |
| `ping-oversized` | PING with 100-byte payload |

### Payload Boundary Tests
| Test | Description |
|------|-------------|
| `payload-max` | 1MB payload message |
| `getheaders-empty` | GETHEADERS with empty locator |
| `locator-overflow` | GETHEADERS with 150 hashes (max 101) |

### Header Chain Attacks
| Test | Description |
|------|-------------|
| `headers-bad-merkle` | Header with 0xFFFF merkle root |
| `headers-deep-fork` | Header forking from random block |
| `headers-max-batch` | 2000 headers in one message |

### Resource Exhaustion
| Test | Description |
|------|-------------|
| `rapid-reconnect` | Connect/disconnect rapidly (20x) |
| `rapid-fire` | Send 500 PINGs as fast as possible |

### Meta
| Test | Description |
|------|-------------|
| `all` | Run all test scenarios |

## Testing DoS Protection

### Setup

1. Start a regtest node:
```bash
./build/bin/unicityd --regtest --datadir=/tmp/test-node --listen --port=29590
```

2. Run node simulator:
```bash
./build/bin/node_simulator --test non-continuous
```

3. Check node logs for misbehavior scoring:
```bash
tail -f /tmp/test-node/debug.log | grep -i misbehav
```

### Expected Results

The node should:
- Detect misbehavior and assign appropriate scores
- Disconnect peers that exceed the misbehavior threshold (100)
- Handle malformed messages gracefully without crashing
- Enforce rate limits on repeated requests
- Timeout slow/stalled connections

## Implementation Details

### P2P Handshake

The tool performs a proper P2P handshake before most tests:
1. Connects to target via TCP
2. Sends VERSION message
3. Waits for VERSION + VERACK from node
4. Sends VERACK
5. Executes test scenario
6. Receives and displays response messages

### Message Construction

- Uses the same P2P protocol serialization as the main node
- Creates properly formatted message headers with magic, command, length, checksum
- Deliberately constructs invalid/adversarial payloads for testing

## Files

- `node_simulator.cpp` - Main implementation (~2000 lines)
- `README.md` - This file

Built via `test/CMakeLists.txt` (target: `node_simulator`)

## Related Testing

This tool complements the automated test suite:
- **Unit tests**: Test DoS protection logic directly (misbehavior scoring, thresholds)
- **Integration tests**: Test multi-node scenarios with simulated network
- **Node simulator**: Test end-to-end P2P behavior against real running node

## Safety

This tool is designed for testing only:
- Never use on production networks
- Only use on private/regtest networks
- Tests may cause the target node to disconnect or ban the simulator's IP
- No persistence - single-shot tests
