# Node Simulator - P2P Protocol Testing Tool

A C++ utility for testing P2P protocol behavior and DoS protection mechanisms in the Unicity network.

**⚠️  WARNING: This tool sends custom P2P messages for testing. Only use on private test networks!**

## Purpose

This tool allows you to test the node's P2P behavior by sending various types of P2P messages:

1. **Invalid PoW Headers** - Headers with invalid proof-of-work (should trigger instant disconnect, score=100)
2. **Oversized Messages** - Headers messages exceeding MAX_HEADERS_COUNT (should trigger +20 misbehavior score)
3. **Non-Continuous Headers** - Headers that don't properly chain together (should trigger +20 misbehavior score)
4. **Spam Scenarios** - Repeated violations to test score accumulation and disconnection

## Building

The tool is built automatically with the main project:

```bash
cmake -S . -B build
cmake --build build --target node_simulator
```

Binary location: `build/bin/node_simulator`

## Usage

```bash
# Show help
./build/bin/node_simulator --help

# Test invalid PoW scenario
./build/bin/node_simulator --test invalid-pow

# Test oversized headers scenario
./build/bin/node_simulator --test oversized

# Test non-continuous headers
./build/bin/node_simulator --test non-continuous

# Test spam scenario (5x non-continuous)
./build/bin/node_simulator --test spam-continuous

# Run all test scenarios
./build/bin/node_simulator --test all

# Target a specific host/port
./build/bin/node_simulator --host 192.168.1.100 --port 29590 --test all
```

## Options

- `--host <host>` - Target host (default: 127.0.0.1)
- `--port <port>` - Target port (default: 29590 regtest)
- `--test <type>` - Test scenario type to perform
- `--help` - Show help message

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
tail -f /tmp/test-node/debug.log | grep -i misbehaving
```

### Expected Results

**Invalid PoW:**
- Misbehavior score: +100
- Result: Instant disconnect

**Oversized Headers:**
- Misbehavior score: +20
- Result: Disconnect after 5 violations (5×20=100)

**Non-Continuous Headers:**
- Misbehavior score: +20
- Result: Disconnect after 5 violations (5×20=100)

**Spam Scenario:**
- Sends 5 non-continuous headers messages
- Accumulated score: 100
- Result: Peer disconnected and discouraged

### Checking Misbehavior Scores

Use the `getpeerinfo` RPC to check peer misbehavior scores:

```bash
./build/bin/unicity-cli --datadir=/tmp/test-node getpeerinfo
```

Output includes:
- `misbehavior_score`: Current score for the peer
- `should_disconnect`: Whether peer should be disconnected

## Implementation Details

### P2P Handshake

The tool performs a proper P2P handshake:
1. Connects to target
2. Sends VERSION message
3. Waits for VERACK
4. Sends VERACK
5. Executes test scenario

### Message Construction

- Uses the same P2P protocol as the main node
- Creates properly formatted message headers
- Deliberately constructs invalid payloads for testing

### Test Scenarios

#### 1. Invalid PoW
```cpp
header.nBits = 0x00000001;  // Impossible difficulty
```

#### 2. Oversized Headers
```cpp
// Send 2100 headers (limit is 2000)
for (int i = 0; i < 2100; i++) {
    headers.push_back(header);
}
```

#### 3. Non-Continuous Headers
```cpp
header2.hashPrevBlock.SetNull();  // Wrong! Doesn't connect
```

## Files

- `node_simulator.cpp` - Main implementation
- Built via test/CMakeLists.txt (target: `node_simulator`)
- `README.md` - This file

## Related Testing

This tool complements the unit tests in the test suite:
- **Unit tests**: Test DoS protection logic directly (misbehavior scoring, thresholds)
- **Node simulator**: Test end-to-end P2P behavior (real network messages)

## Safety

This tool is designed for testing only:
- ⚠️ Never use on production networks
- ⚠️ Only use on private/regtest networks
- ⚠️ The tool warns before execution
- ⚠️ No persistence - single-shot tests

## Future Enhancements

Potential additions:
- Slow-loris and framing tests (added):
  - slow-loris: chunked drip with early close to exercise timeouts
  - bad-magic: wrong 4-byte magic
  - bad-checksum: corrupt header checksum
  - bad-length: declared length larger than sent bytes
  - truncation: send half payload then close
- Low-work header spam
- Future timestamp tests
- Checkpoint violation tests
- Ban evasion testing
- Multiple concurrent connections
- Fuzzing support
