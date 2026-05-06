// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#include "chain/chainparams.hpp"

#include "network/protocol.hpp"
#include "util/arith_uint256.hpp"
#include "util/hash.hpp"
#include "util/sha256.hpp"
#include "util/string_parsing.hpp"

#include <cassert>
#include <cstring>
#include <stdexcept>
#include <string_view>

namespace unicity {
namespace chain {

// ============================================================================
// Compile-time constants - validated at compile time, no runtime parsing
// ============================================================================

// Mainnet
static constexpr uint256 MAINNET_GENESIS_HASH{"82855acd89aae2dc78498f7b83ee6d0352890b96e5b55eb7f9ac0c317868f291"};
static constexpr uint256 MAINNET_POW_LIMIT{"000fffff00000000000000000000000000000000000000000000000000000000"};
static constexpr std::string_view MAINNET_GENESIS_UTB_CBOR_HEX = "d998588a010301018383783531365569753248416d357643446a6a6e72416d785a4d3163556e5a3859414c4d45526d6d47394a547833323767594a7266585a58475821038545351911bdc852bf7be2e09084e069cfa67d7ccb95122f9a5598b850bd51170183783531365569753248416d503668477a5341353964696a6a32554c786d46504e5a3657395475587a4b6669695859784d3435796b4e4d585821033ce68ce8ec203e2fef0fc265756283e6fa2ba38a9acf97aadec9e3b9e928cac30183783531365569753248416d553974385846526f576d6255574e55357a56777331734a69387967516f3267537377616d364a745446417a7058210338392a08cdf163173721beed16af98ed09a68fb8ff2dd733af6dcb0c31caba740103f6f6f6a3783531365569753248416d357643446a6a6e72416d785a4d3163556e5a3859414c4d45526d6d47394a547833323767594a7266585a58475841d103b984c7d97f7c24108e618ce119a889eaf1ff9366b2ca6a09088f0031e6e7313650aeb89d510d3c06a874fa90823c642189440d7190ee04dbf9af80c7985f00783531365569753248416d503668477a5341353964696a6a32554c786d46504e5a3657395475587a4b6669695859784d3435796b4e4d585841b65ace77cde184b893b88a7194f4ce707507641f4b48ab5a2afc780617095c233f8012d0c3af0912ee9783be3ac181594c5b424569404aa08d5678197cff613501783531365569753248416d553974385846526f576d6255574e55357a56777331734a69387967516f3267537377616d364a745446417a7058410cbf3f7862be83009fb6bc251c3a24197417dd275e16441468186e7521ff99e02740a7537dc0d7926d7915d4299cc304c5a4e2479ccbee03d2d5e4a3d60984f101";

// Testnet
static constexpr uint256 TESTNET_GENESIS_HASH{"64a83779853d9d40a18cbe2522ec18ee6a783c3429e64071462249ff0786d273"};
static constexpr uint256 TESTNET_POW_LIMIT{"007fffff00000000000000000000000000000000000000000000000000000000"};
static constexpr std::string_view TESTNET_GENESIS_UTB_CBOR_HEX = MAINNET_GENESIS_UTB_CBOR_HEX;

// Regtest
static constexpr uint256 REGTEST_GENESIS_HASH{"64a2b7d866d472b592c02ad99a5aae6222b646405bd570cc6966ffff963e5739"};
static constexpr uint256 REGTEST_POW_LIMIT{"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
static constexpr std::string_view REGTEST_GENESIS_UTB_CBOR_HEX = MAINNET_GENESIS_UTB_CBOR_HEX;

// Static instance
std::unique_ptr<ChainParams> GlobalChainParams::instance = nullptr;

CBlockHeader CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, std::span<const uint8_t> utb_cbor,
                                int32_t nVersion) {
  CBlockHeader genesis;
  genesis.nVersion = nVersion;
  genesis.hashPrevBlock.SetNull();

  // Genesis Payload: [32 bytes rewardTokenIdHash (all zeros)] + [UTB CBOR bytes]
  genesis.vPayload.assign(32, 0);
  genesis.vPayload.insert(genesis.vPayload.end(), utb_cbor.begin(), utb_cbor.end());

  // Compute leaf_1 by hashing the UTB
  const uint256 leaf_1 = SingleHash(utb_cbor);
  genesis.payloadRoot = CBlockHeader::ComputePayloadRoot(uint256::ZERO, leaf_1);

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
  consensus.nASERTAnchorHeight = 1;

  // Minimum chain work
  consensus.nMinimumChainWork = uint256::ZERO;

  // Network configuration
  nDefaultPort = protocol::ports::MAINNET;

  // Genesis block
  genesis = CreateGenesisBlock(1761330012, 28041, 0x1f06a000, util::ParseHex(MAINNET_GENESIS_UTB_CBOR_HEX), 1);
  consensus.hashGenesisBlock = genesis.GetHash();
  assert(consensus.hashGenesisBlock == MAINNET_GENESIS_HASH);

  consensus.nNetworkExpirationInterval = 0;
  consensus.nNetworkExpirationGracePeriod = 0;
  consensus.nSuspiciousReorgDepth = 2;

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

  consensus.powLimit = TESTNET_POW_LIMIT;
  consensus.nPowTargetSpacing = 144 * 60;
  consensus.nRandomXEpochDuration = 7 * 24 * 60 * 60;
  consensus.nASERTHalfLife = 2 * 24 * 60 * 60;
  consensus.nASERTAnchorHeight = 1;
  consensus.nMinimumChainWork = uint256::ZERO;

  nDefaultPort = protocol::ports::TESTNET;

  // Genesis block
  genesis = CreateGenesisBlock(1760549555, 4031, 0x1f7fffff, util::ParseHex(TESTNET_GENESIS_UTB_CBOR_HEX), 1);
  consensus.hashGenesisBlock = genesis.GetHash();
  assert(consensus.hashGenesisBlock == TESTNET_GENESIS_HASH);

  consensus.nNetworkExpirationInterval = 1000;
  consensus.nNetworkExpirationGracePeriod = 24;
  consensus.nSuspiciousReorgDepth = 100;

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

  consensus.powLimit = REGTEST_POW_LIMIT;
  consensus.nPowTargetSpacing = 2 * 60;
  consensus.nRandomXEpochDuration = 365ULL * 24 * 60 * 60 * 100;
  consensus.nMinimumChainWork = uint256::ZERO;

  nDefaultPort = protocol::ports::REGTEST;

  // Genesis block
  genesis = CreateGenesisBlock(1774378227, 0, 0x207fffff, util::ParseHex(REGTEST_GENESIS_UTB_CBOR_HEX), 1);
  consensus.hashGenesisBlock = genesis.GetHash();
  assert(consensus.hashGenesisBlock == REGTEST_GENESIS_HASH);

  consensus.nNetworkExpirationInterval = 0;
  consensus.nNetworkExpirationGracePeriod = 0;
  consensus.nSuspiciousReorgDepth = 100;

  vFixedSeeds.clear();
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
