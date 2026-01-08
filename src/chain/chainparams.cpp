// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#include "chain/chainparams.hpp"

#include "network/protocol.hpp"
#include "util/arith_uint256.hpp"

#include <cassert>
#include <stdexcept>

namespace unicity {
namespace chain {

// ============================================================================
// Compile-time constants - validated at compile time, no runtime parsing
// ============================================================================

// Mainnet
static constexpr uint256 MAINNET_GENESIS_HASH{"b675bea090e27659c91885afe341facf399cf84997918bac927948ee75409ebf"};
static constexpr uint256 MAINNET_POW_LIMIT{"000fffff00000000000000000000000000000000000000000000000000000000"};

// Testnet
static constexpr uint256 TESTNET_GENESIS_HASH{"cb608755c4b2bee0b929fe5760dec6cc578b48976ee164bb06eb9597c17575f8"};
static constexpr uint256 TESTNET_POW_LIMIT{"007fffff00000000000000000000000000000000000000000000000000000000"};

// Regtest
static constexpr uint256 REGTEST_GENESIS_HASH{"0233b37bb6942bfb471cfd7fb95caab0e0f7b19cc8767da65fbef59eb49e45bd"};
static constexpr uint256 REGTEST_POW_LIMIT{"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};

// Static instance
std::unique_ptr<ChainParams> GlobalChainParams::instance = nullptr;

CBlockHeader CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion) {
  CBlockHeader genesis;
  genesis.nVersion = nVersion;
  genesis.hashPrevBlock.SetNull();
  genesis.minerAddress.SetNull();
  genesis.nTime = nTime;
  genesis.nBits = nBits;
  genesis.nNonce = nNonce;
  genesis.hashRandomX.SetNull();
  return genesis;
}

std::string ChainParams::GetChainTypeString() const {
  switch (chainType) {
  case ChainType::MAIN:
    return "main";
  case ChainType::TESTNET:
    return "test";
  case ChainType::REGTEST:
    return "regtest";
  }
  return "unknown";
}

uint32_t ChainParams::GetNetworkMagic() const {
  switch (chainType) {
  case ChainType::MAIN:
    return protocol::magic::MAINNET;
  case ChainType::TESTNET:
    return protocol::magic::TESTNET;
  case ChainType::REGTEST:
    return protocol::magic::REGTEST;
  }
  return 0;
}

std::unique_ptr<ChainParams> ChainParams::CreateMainNet() {
  return std::make_unique<CMainParams>();
}

std::unique_ptr<ChainParams> ChainParams::CreateTestNet() {
  return std::make_unique<CTestNetParams>();
}

std::unique_ptr<ChainParams> ChainParams::CreateRegTest() {
  return std::make_unique<CRegTestParams>();
}

// ============================================================================
// MainNet Parameters
// ============================================================================

CMainParams::CMainParams() {
  chainType = ChainType::MAIN;

  // Consensus rules
  consensus.powLimit = MAINNET_POW_LIMIT;
  consensus.nPowTargetSpacing = 144 * 60;              // 2.4 hours (8640 seconds)
  consensus.nRandomXEpochDuration = 7 * 24 * 60 * 60;  // 1 week (70 blocks at 2.4h)
  consensus.nASERTHalfLife = 2 * 24 * 60 * 60;         // 2 days (~20 blocks at 2.4h)

  // ASERT anchor: Use block 1 as the anchor
  // This means block 0 (genesis) and block 1 both use powLimit
  // Block 2 onwards uses ASERT relative to block 1's actual timestamp
  // This eliminates timing issues - block 1 can be mined at any time
  consensus.nASERTAnchorHeight = 1;

  // Minimum chain work
  // Update this value periodically as the chain grows
  // Set to 0 for now since this is a fresh chain with no accumulated work
  // Once mainnet has significant work, update this to ~90% of current chain work
  consensus.nMinimumChainWork = uint256::ZERO;

  // Network configuration
  nDefaultPort = protocol::ports::MAINNET;

  // Genesis block:
  // Mined on: 2025-10-24 19:20:12 UTC
  // Difficulty: 0x1f06a000 (target: ~2.5 minutes at 50 H/s)
  // Block hash: b675bea090e27659c91885afe341facf399cf84997918bac927948ee75409ebf
  genesis = CreateGenesisBlock(1761330012,  // nTime - Oct 24, 2025
                               8497,        // nNonce - found by genesis miner
                               0x1f06a000,  // nBits - initial difficulty
                               1            // nVersion
  );

  consensus.hashGenesisBlock = genesis.GetHash();
  assert(consensus.hashGenesisBlock == MAINNET_GENESIS_HASH);

  // TODO add timebomb to initial mainnet
  consensus.nNetworkExpirationInterval = 0;
  consensus.nNetworkExpirationGracePeriod = 0;

  // Orphan header management
  consensus.nOrphanHeaderExpireTime = 6 * 60 * 60;  // 6 hours (~2.5 block intervals)

  // Reorg protection
  consensus.nSuspiciousReorgDepth = 2;  // 2 blocks (~4.8 hours)

  // DoS protection
  consensus.nAntiDosWorkBufferBlocks = 6;  // 6 blocks (~14.4 hours)

  // Hardcoded seed node addresses
  vFixedSeeds.push_back("178.18.251.16:9590");
  vFixedSeeds.push_back("185.225.233.49:9590");
  vFixedSeeds.push_back("207.244.248.15:9590");
  vFixedSeeds.push_back("194.140.197.98:9590");
  vFixedSeeds.push_back("173.212.251.205:9590");
  vFixedSeeds.push_back("144.126.138.46:9590");
  vFixedSeeds.push_back("194.163.184.29:9590");
}

// ============================================================================
// TestNet Parameters
// ============================================================================

CTestNetParams::CTestNetParams() {
  chainType = ChainType::TESTNET;

  // Easy difficulty for testnet
  consensus.powLimit = TESTNET_POW_LIMIT;
  consensus.nPowTargetSpacing = 144 * 60;              // 2.4 hours (same as mainnet)
  consensus.nRandomXEpochDuration = 7 * 24 * 60 * 60;  // 1 week  (70 blocks at 2.4h)
  consensus.nASERTHalfLife = 2 * 24 * 60 * 60;         // 2 days (~20 blocks at 2.4h)

  // ASERT anchor: Use block 1 (same as mainnet)
  consensus.nASERTAnchorHeight = 1;

  // Minimum chain work (eclipse attack protection)
  // Set to 0 for fresh testnet - update as the network grows
  consensus.nMinimumChainWork = uint256::ZERO;

  // Network expiration enabled for testnet - set to 1000 blocks for testing
  consensus.nNetworkExpirationInterval = 1000;
  consensus.nNetworkExpirationGracePeriod = 24;  // 24 blocks (~2.4 days warning period)

  // Orphan header management
  consensus.nOrphanHeaderExpireTime = 6 * 60 * 60;  // 6 hours (2.5 block intervals, matching mainnet)

  // Reorg protection
  consensus.nSuspiciousReorgDepth = 100;  // 100 blocks (~10 days) - testing flexibility

  // DoS protection
  consensus.nAntiDosWorkBufferBlocks = 144;  // 144 blocks (~14.4 days) - testing flexibility

  // Network configuration
  nDefaultPort = protocol::ports::TESTNET;

  // Testnet genesis - mined at Oct 15, 2025
  // Block hash:
  // cb608755c4b2bee0b929fe5760dec6cc578b48976ee164bb06eb9597c17575f8
  genesis = CreateGenesisBlock(1760549555,  // Oct 15, 2025
                               253,         // Nonce found by genesis miner
                               0x1f7fffff,  // Easy difficulty for fast testing
                               1);

  consensus.hashGenesisBlock = genesis.GetHash();
  assert(consensus.hashGenesisBlock == TESTNET_GENESIS_HASH);

  // Hardcoded seed node addresses (ct20-ct26)
  // These are reliable seed nodes for initial peer discovery
  vFixedSeeds.push_back("178.18.251.16:19590");
  vFixedSeeds.push_back("185.225.233.49:19590");
  vFixedSeeds.push_back("207.244.248.15:19590");
  vFixedSeeds.push_back("194.140.197.98:19590");
  vFixedSeeds.push_back("173.212.251.205:19590");
  vFixedSeeds.push_back("144.126.138.46:19590");
  vFixedSeeds.push_back("194.163.184.29:19590");
}

// ============================================================================
// RegTest Parameters (Local testing)
// ============================================================================

CRegTestParams::CRegTestParams() {
  chainType = ChainType::REGTEST;

  // Very easy difficulty - instant block generation
  consensus.powLimit = REGTEST_POW_LIMIT;
  consensus.nPowTargetSpacing = 2 * 60;
  consensus.nRandomXEpochDuration = 365ULL * 24 * 60 * 60 *
                                    100;  // 100 years (so all regtest blocks stay in same epoch)

  // Minimum chain work - disabled for regtest (generate chains from scratch)
  consensus.nMinimumChainWork = uint256::ZERO;

  // Network expiration disabled for regtest (testing environment)
  consensus.nNetworkExpirationInterval = 0;     // Disabled
  consensus.nNetworkExpirationGracePeriod = 0;  // Disabled

  // Orphan header management
  consensus.nOrphanHeaderExpireTime = 12 * 60;  // 12 minutes

  // Reorg protection
  consensus.nSuspiciousReorgDepth = 100;  // 100 blocks

  // DoS protection
  consensus.nAntiDosWorkBufferBlocks = 144;  // 144 blocks

  // Network configuration
  nDefaultPort = protocol::ports::REGTEST;

  // Regtest genesis - instant mine
  genesis = CreateGenesisBlock(1296688602,  // Just use a fixed time
                               2,           // Easy nonce
                               0x207fffff,  // Very easy difficulty
                               1);

  consensus.hashGenesisBlock = genesis.GetHash();
  assert(consensus.hashGenesisBlock == REGTEST_GENESIS_HASH);

  vFixedSeeds.clear();  // No hardcoded seeds for local testing
}

// ============================================================================
// Global Params Singleton
// ============================================================================

void GlobalChainParams::Select(ChainType chain) {
  switch (chain) {
  case ChainType::MAIN:
    instance = ChainParams::CreateMainNet();
    break;
  case ChainType::TESTNET:
    instance = ChainParams::CreateTestNet();
    break;
  case ChainType::REGTEST:
    instance = ChainParams::CreateRegTest();
    break;
  }
}

const ChainParams& GlobalChainParams::Get() {
  if (!instance) {
    throw std::runtime_error("GlobalChainParams not initialized - call Select() first");
  }
  return *instance;
}

bool GlobalChainParams::IsInitialized() {
  return instance != nullptr;
}

}  // namespace chain
}  // namespace unicity