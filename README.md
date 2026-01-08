Unicity Proof of Work
=====================================

[![Docs](https://img.shields.io/badge/docs-README-blue.svg)](docs/README.md) [![Functional Tests](https://img.shields.io/badge/tests-functional-blueviolet.svg)](test/functional/README.md)
Unicity PoW is a headers-only blockchain with RandomX proof-of-work and ASERT difficulty adjustment. There are no transactions, mempool or wallets. Each block is only a header which contains the miner's address. Coins that are mined here can be minted off-chain using the Unicity Token SDK. The end result is a portable trust anchor and coin-genesis blockchain purpose-built for the Unicity off-chain system that grows at approx 1MB a year.

The implementation is Bitcoin Core-inspired and closely follows the architectural patterns for P2P networking and chainstate management, adapted for a headers-only implementation. Without transactions the attack surface is vastly reduced and the codebase is 5% of Core.

## Quick Links

- [Documentation Hub](docs/README.md) - Index of project docs
- [Architecture Documentation](docs/ARCHITECTURE.md) - System design and component interactions
- [Protocol Specification](docs/SPECIFICATION.md) - Wire protocol and message formats
- [Functional Tests](test/functional/README.md) - Runner, categories, test-only RPCs
- [Testing Guide](test/QUICK_REFERENCE.md) - Running tests and test coverage
- [Deployment Guide](deploy/README.md) - Docker and Ansible deployment
- [Binary Releases](https://github.com/sakuyama2024/unicity-pow/releases)

## Bitcoin Core-Inspired Architecture

Unicity adopts proven architectural patterns from Bitcoin Core for P2P networking and chain state management, adapted for a headers-only blockchain.

**Bitcoin Core Patterns Implemented:**
- P2P networking protocol (version messages, ping/pong, addr relay)
- Chain state management (CBlockIndex, block tree, best chain selection)
- Header validation and chain selection (heaviest work chain)
- Peer management and DoS protection
- Network message format and serialization

**Unicity-Specific Design:**
- **Proof-of-work**: RandomX (ASIC-resistant) instead of SHA256d
- **Difficulty adjustment**: ASERT per-block instead of 2016-block retargeting
- **Block headers**: 100 bytes (includes miner address + RandomX hash)
- **Target spacing**: 2.4 hours instead of 10 minutes
- **No transaction layer**: No mempool, UTXO set, or transaction processing

## Project Structure

```
unicity-pow/
├── src/                 # C++ source code (~12,000 lines)
│   ├── chain/           # Blockchain core (validation, PoW, block index)
│   ├── network/         # P2P networking and peer management
│   └── util/            # Utilities (logging, serialization, crypto)
├── include/             # C++ headers (~3,600 lines)
│   ├── chain/           # Chain-related interfaces
│   ├── network/         # Network protocol definitions
│   └── util/            # Utility headers
├── test/                # Comprehensive test suite
│   ├── unit/            # Unit tests (Catch2)
│   ├── functional/      # End-to-end Python tests
│   ├── security/        # Security-focused tests
│   ├── chain/           # Chain validation tests
│   ├── network/         # Network protocol tests
│   └── util/            # Utility tests
├── fuzz/                # Fuzzing infrastructure
├── deploy/              # Deployment automation
│   ├── ansible/         # Multi-node deployment
│   └── docker/          # Container configuration
├── docs/                # Documentation
├── scripts/             # Development scripts
├── cmake/               # CMake modules
└── tools/               # Development tools
```

## Building from Source

### Prerequisites

- **Compiler**: C++20 compatible (GCC 10+, Clang 11+)
- **CMake**: 3.20 or newer

All other dependencies (Asio, RandomX, spdlog, fmt, nlohmann/json, miniupnpc) are automatically downloaded via CMake FetchContent.

### Build Steps

```bash
git clone https://github.com/sakuyama2024/unicity-pow.git
cd unicity-pow
cmake -B build
cmake --build build -j$(nproc)
```

The build produces:
- `build/bin/unicityd` - Node daemon
- `build/bin/unicity-cli` - Command-line interface
- `build/bin/unicity_tests` - Test suite

### Running Tests

```bash
# Run all tests
./build/bin/unicity_tests

# Run specific test category
./build/bin/unicity_tests "[network]"
./build/bin/unicity_tests "[chain]"

# Run functional tests (requires Python 3.7+)
cd test/functional
./run_tests.py
```

See [test/QUICK_REFERENCE.md](test/QUICK_REFERENCE.md) for testing documentation.

## Running a Node

### Basic Usage

```bash
# Start with default settings
# Note: mainnet is disabled until TGE
./build/bin/unicityd --testnet

# Specify data directory
./build/bin/unicityd --testnet --datadir=/path/to/data

# Enable debug logging
./build/bin/unicityd --testnet --debug=net --debug=chain

# Start mining (CLI connects to running daemon via Unix socket)
# Note: internal CPU miner is designed for testing and uses a single thread
./build/bin/unicity-cli startmining
```

### Using Docker

For production deployments, Docker is recommended:

```bash
# Quick start
docker run -d --name unicityd \
  -p 9590:9590 \
  -v unicity-data:/data \
  unicitynetwork/unicity-pow

# With resource limits
docker run -d --name unicityd \
  --memory="1g" \
  --cpus="2" \
  -p 9590:9590 \
  -v unicity-data:/data \
  unicitynetwork/unicity-pow
```

For multi-node deployments with Ansible, see [deploy/README.md](deploy/README.md).

### Resource Requirements

- **Memory**: 1GB minimum (256MB for RandomX light mode + overhead)
- **CPU**: 2+ cores recommended
- **Disk**: 1GB for blockchain data and logs
- **Network**: Allow port 9590 (mainnet) or 19590 (testnet) for P2P

## RPC Interface

Unicity uses **Unix domain sockets** for RPC instead of TCP/IP for enhanced security:

- RPC socket: `<datadir>/node.sock`
- No network exposure (local access only)
- No authentication needed (file system permissions)
- Remote access requires SSH to server

### Basic RPC Commands

```bash
# Show help and available options
./build/bin/unicity-cli --help

# Get blockchain info
./build/bin/unicity-cli getblockchaininfo

# Get block count
./build/bin/unicity-cli getblockcount

# Get best block hash
./build/bin/unicity-cli getbestblockhash

# Get peer info
./build/bin/unicity-cli getpeerinfo

# Get specific block header
./build/bin/unicity-cli getblockheader <hash>

# Specify custom datadir
./build/bin/unicity-cli --datadir=/custom/path getblockcount
```

For remote monitoring, use SSH or deploy a local monitoring agent that exports metrics.

## Network Parameters

### Mainnet
- **Magic Bytes**: 0x554E4944
- **P2P Port**: 9590
- **Target Spacing**: 2.4 hours
- **ASERT Half-life**: ~20 blocks (2 days)
- **Genesis Hash**: `0xb675bea090e27659c91885afe341facf399cf84997918bac927948ee75409ebf`

### Testnet
- **Magic Bytes**: 0xA3F8D412
- **P2P Port**: 19590
- **Target Spacing**: 2.4 hours
- **ASERT Half-life**: ~20 blocks (2 days)
- **Genesis Hash**: `0xcb608755c4b2bee0b929fe5760dec6cc578b48976ee164bb06eb9597c17575f8`
- **Network Expiration**: 1000 blocks (testing feature)

### Regtest
- **P2P Port**: 29590
- **Target Spacing**: 2 minutes
- **Instant mining**: Extremely low difficulty for local testing

## Mining

Unicity uses RandomX proof-of-work (ASIC-resistant, CPU-friendly). The node supports mining using regtest only for testing. Use a separate mining client for production.

## Development

### Code Organization

The implementation follows a modular design with clear separation:

- **Chain Layer** (`src/chain/`, `include/chain/`)
  - Block validation and proof-of-work
  - Chain state management (CBlockIndex, CChainState)
  - Difficulty adjustment (ASERT)
  - RandomX integration

- **Network Layer** (`src/network/`, `include/network/`)
  - P2P protocol implementation
  - Peer lifecycle and connection management
  - Message handling (headers, inv, ping/pong, addr)
  - DoS protection

- **Utility Layer** (`src/util/`, `include/util/`)
  - Logging infrastructure
  - Serialization and hashing
  - Time management
  - Platform abstractions

### Contributing

Contributions are welcome! Please ensure:

1. All changes include appropriate tests
2. Code follows existing style conventions
3. Tests pass: `./build/bin/unicity_tests`
4. Functional tests pass: `cd test/functional && ./run_tests.py`

### Continuous Integration

CI runs on every commit:
- **Platforms**: Linux, macOS
- **Compilers**: GCC 10+, Clang 11+
- **Sanitizers**: AddressSanitizer, ThreadSanitizer, UndefinedBehaviorSanitizer
- **Tests**: Unit tests, functional tests, fuzz tests
- **Coverage**: Code coverage tracking

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md) - Detailed system architecture
- [PROTOCOL_SPECIFICATION.md](PROTOCOL_SPECIFICATION.md) - Wire protocol specification
- [test/QUICK_REFERENCE.md](test/QUICK_REFERENCE.md) - Testing guide
- [deploy/README.md](deploy/README.md) - Deployment guide
- [DOCUMENTATION_INDEX.md](DOCUMENTATION_INDEX.md) - Full documentation index

## Community

- **Issues**: [GitHub Issues](https://github.com/unicity-network/unicity-pow/issues)
- **Discussions**: [GitHub Discussions](https://github.com/unicity-network/unicity-pow/discussions)

## License

Unicity PoW is released under the terms of the MIT license. See https://opensource.org/licenses/MIT for more information.

### Acknowledgments

This project incorporates code and design patterns from several open-source projects:

**Bitcoin Core** \
Portions of this software are derived from Bitcoin Core, including chain state management architecture, block index data structures, median time past calculation, skip list implementation, and P2P networking patterns. \
Copyright (c) 2009-2010 Satoshi Nakamoto \
Copyright (c) 2009-2022 The Bitcoin Core developers \
Licensed under the MIT License - https://github.com/bitcoin/bitcoin

**Bitcoin Cash (ASERT)** \
The ASERT difficulty adjustment algorithm is adapted from Bitcoin Cash's aserti3-2d implementation. \
Licensed under the MIT License - https://reference.cash/protocol/forks/2020-11-15-asert

**Scash** \
The RandomX integration was initially adapted from Scash. \
Copyright (c) 2018-2021 The Scash developers \
Licensed under the MIT License - https://github.com/scashnetwork/scash

**RandomX** \
RandomX proof-of-work algorithm by tevador and contributors. \
Licensed under the BSD 3-Clause License - https://github.com/tevador/RandomX
