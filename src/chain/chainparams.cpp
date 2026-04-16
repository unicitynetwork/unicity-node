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
static constexpr uint256 MAINNET_GENESIS_HASH{"cac1359df88f7aa4ba8639b44a4c30c06a3d87fcae07d7ae55abfd24220b2157"};
static constexpr uint256 MAINNET_POW_LIMIT{"000fffff00000000000000000000000000000000000000000000000000000000"};
static constexpr std::string_view MAINNET_GENESIS_UTB_CBOR_HEX = "d998588a010301018383783531365569753248416b776456513347774234586f4b554c624b733174504b7671386e6664385941594450415a395341766d61427663582102d23be5a4932867088fd6fbf12cbc2744ff1393ec1cc7eb47addcec6d908a9e710183783531365569753248416d476b734c324674316d3156506a3774326463484c59343661686a6d726245483655316873486d346e72473268582103411c106956451afa8a596f9d3ef443c073f6d6d40c5d4539fa3e140465301f3e0183783531365569753248416d514d7052575343736b576773486e41507148436355487165396848533353787461337a6941737a37795531685821027f0fe7ba12dc544fe9d4f8bdc8f71de106b97d234e769c87a938cc7c5f9587570103f6f6f6a3783531365569753248416b776456513347774234586f4b554c624b733174504b7671386e6664385941594450415a395341766d614276635841dde5ce121337851277214f4cfdb12e1470115987bab6d66cc754df325a8b1ee21fbc022514dcafd8aa73e1b95a599a684a2d2c2f6b373c66becc7975af84588d00783531365569753248416d476b734c324674316d3156506a3774326463484c59343661686a6d726245483655316873486d346e724732685841027cc807c54a74c6530be68d4797b9d1e1154a34559a0f5c608d402db074ef6b71b26c04e16594ca7f63a82bf26b4253e94b987c2b92ac4ff72667f5b56d0ac601783531365569753248416d514d7052575343736b576773486e41507148436355487165396848533353787461337a6941737a377955316858413ddb9ce2a7f1ee255966b91f06409a791cd101ce865c2c5ff1054ff8ca0dc7db145de2c71a0b5ed7776532a6581e3fe6b685ea5d48568f898a9193bb0444c3ab01";

// Testnet
static constexpr uint256 TESTNET_GENESIS_HASH{"e9351ab26030ff058ef75278e4ee3c2065a87c750e2df4fb8437a65c3bff7f35"};
static constexpr uint256 TESTNET_POW_LIMIT{"007fffff00000000000000000000000000000000000000000000000000000000"};
static constexpr std::string_view TESTNET_GENESIS_UTB_CBOR_HEX = MAINNET_GENESIS_UTB_CBOR_HEX;

// Regtest
static constexpr uint256 REGTEST_GENESIS_HASH{"e970e2f0b5898feca76ff24ec35a17c3ab37e4ef5c4f06ee93752dcad26079a3"};
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
  genesis = CreateGenesisBlock(1761330012, 21006, 0x1f06a000, util::ParseHex(MAINNET_GENESIS_UTB_CBOR_HEX), 1);
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
  genesis = CreateGenesisBlock(1760549555, 160, 0x1f7fffff, util::ParseHex(TESTNET_GENESIS_UTB_CBOR_HEX), 1);
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
  genesis = CreateGenesisBlock(1774378227, 20, 0x207fffff, util::ParseHex(REGTEST_GENESIS_UTB_CBOR_HEX), 1);
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
