// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#pragma once

#include "chain/block.hpp"
#include "util/arith_uint256.hpp"
#include "util/uint.hpp"

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace unicity {
namespace chain {

/**
 * Chain type enumeration
 * Simple modern enum class (vs Bitcoin's ChainType)
 */
enum class ChainType {
  MAIN,     // Production mainnet
  TESTNET,  // Public test network
  REGTEST   // Regression test (local testing)
};

/**
 * Consensus parameters
 */
struct ConsensusParams {
  // Proof of Work
  uint256 powLimit;               // Maximum difficulty (easiest target)
  int64_t nPowTargetSpacing;      // Target time between blocks (in seconds)
  int64_t nRandomXEpochDuration;  // RandomX epoch duration (in seconds)

  // ASERT difficulty adjustment
  int64_t nASERTHalfLife;      // ASERT half-life for difficulty adjustment (in seconds)
  int32_t nASERTAnchorHeight;  // ASERT anchor block height

  // Hash of genesis block
  uint256 hashGenesisBlock;

  // Minimum cumulative chain work for IBD completion
  // Set to 0 to disable check (regtest), or to actual chain work (mainnet/testnet)
  uint256 nMinimumChainWork;

  // Network expiration (timebomb) - forces updates
  // Set to 0 to disable expiration
  int32_t nNetworkExpirationInterval;     // Block height where network expires
  int32_t nNetworkExpirationGracePeriod;  // Grace period for warnings (in blocks)

  // Orphan header management
  int64_t nOrphanHeaderExpireTime;  // Time in seconds before orphan headers expire

  // Reorg protection
  int32_t nSuspiciousReorgDepth;  // Reorg depth that triggers warnings/halts

  // DoS protection
  int32_t nAntiDosWorkBufferBlocks;  // Work buffer for accepting chains behind tip
};

/**
 * ChainParams - Chain-specific parameters
 * Simplified version of Bitcoin's CChainParams
 */
class ChainParams {
public:
  ChainParams() = default;
  virtual ~ChainParams() = default;

  // Accessors
  const ConsensusParams& GetConsensus() const { return consensus; }
  uint32_t GetNetworkMagic() const;  // Returns protocol::magic::* constant for this chain
  uint16_t GetDefaultPort() const { return nDefaultPort; }
  const CBlockHeader& GenesisBlock() const { return genesis; }
  ChainType GetChainType() const { return chainType; }
  std::string GetChainTypeString() const;
  const std::vector<std::string>& FixedSeeds() const { return vFixedSeeds; }

  // Mutators (for CLI overrides)
  void SetSuspiciousReorgDepth(int32_t depth) { consensus.nSuspiciousReorgDepth = depth; }

  // Factory methods
  static std::unique_ptr<ChainParams> CreateMainNet();
  static std::unique_ptr<ChainParams> CreateTestNet();
  static std::unique_ptr<ChainParams> CreateRegTest();

protected:
  ConsensusParams consensus;
  uint16_t nDefaultPort{};
  ChainType chainType{ChainType::MAIN};
  CBlockHeader genesis;
  std::vector<std::string> vFixedSeeds;  // Hardcoded seed node addresses (IP:port)
};

/**
 * MainNet parameters
 */
class CMainParams : public ChainParams {
public:
  CMainParams();
};

/**
 * TestNet parameters
 */
class CTestNetParams : public ChainParams {
public:
  CTestNetParams();
};

/**
 * RegTest parameters
 */
class CRegTestParams : public ChainParams {
public:
  CRegTestParams();
};

/**
 * Global chain params singleton
 */
class GlobalChainParams {
public:
  static void Select(ChainType chain);
  static const ChainParams& Get();
  static bool IsInitialized();

private:
  static std::unique_ptr<ChainParams> instance;
};

// Helper to create genesis block
CBlockHeader CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion = 1);

}  // namespace chain
}  // namespace unicity
