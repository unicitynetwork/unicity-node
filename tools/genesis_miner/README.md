# Genesis Block Miner

Standalone tool to mine the genesis block for Unicity using RandomX proof-of-work.

## Features

- Multi-threaded RandomX mining
- Real-time hashrate reporting
- Configurable difficulty and timestamp
- Outputs genesis block parameters for `chainparams.cpp`

## Building

```bash
cd tools/genesis_miner
mkdir build
cd build
cmake ..
cmake --build .
```

## Usage

### Basic (default parameters)

```bash
./bin/genesis_miner
```

Defaults:
- Time: `1234567890` (2009-02-13, Bitcoin genesis timestamp)
- Difficulty: `0x1d00ffff` (Bitcoin genesis difficulty)
- Threads: All available CPU cores

### Custom parameters

```bash
# Custom timestamp (current time)
./bin/genesis_miner --time $(date +%s)

# Easier difficulty (for faster testing)
./bin/genesis_miner --bits 0x1e0fffff

# Specific number of threads
./bin/genesis_miner --threads 4

# Combination
./bin/genesis_miner --time 1700000000 --bits 0x1d00ffff --threads 8
```

## Output

When a valid genesis block is found:

```
🎉 FOUND GENESIS BLOCK! 🎉
Nonce: 2083236893
Hash: c465b15aa81050c15c0c6f2c2f47be01cbd1734a8ba79e78e5e3baddbbdc25f0
RandomX Hash: 1234567890abcdef...
Commitment: 000000001234abcd...

=== Code for chainparams.cpp ===
genesis.nVersion = 1;
genesis.nTime = 1234567890;
genesis.nBits = 0x1d00ffff;
genesis.nNonce = 2083236893;
// Block hash: c465b15aa81050c15c0c6f2c2f47be01cbd1734a8ba79e78e5e3baddbbdc25f0
```

Copy the code output directly into your `chainparams.cpp` file.

## Performance Notes

- RandomX is CPU-intensive and ASIC-resistant
- Expected hashrate: 100-1000 H/s per core (depending on CPU)
- Finding a valid block at difficulty `0x1d00ffff` takes ~30 minutes on modern hardware
- Use `--bits 0x1f00ffff` for testing (256x easier, finds in seconds)

## Algorithm

1. Create genesis block header with specified parameters
2. Initialize RandomX VM for current epoch
3. For each nonce:
   - Calculate RandomX hash of block header
   - Calculate commitment = SHA256(SHA256(rx_hash || block_header))
   - Check if commitment <= target
4. Output results when valid block is found

## Integration

The miner is standalone and only depends on:
- Unicity's crypto primitives (SHA256, uint256)
- Unicity's block header structure
- RandomX from Unicity's fork

No other dependencies on the main node code.
