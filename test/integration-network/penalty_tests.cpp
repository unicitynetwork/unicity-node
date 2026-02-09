// Misbehavior penalty tests (ported to test2)

#include "catch_amalgamated.hpp"
#include "infra/simulated_network.hpp"
#include "infra/simulated_node.hpp"
#include "infra/node_simulator.hpp"
#include "test_orchestrator.hpp"
#include "util/hash.hpp"
#include "chain/chainparams.hpp"

using namespace unicity;
using namespace unicity::test;

static void SetZeroLatency(SimulatedNetwork& network){ SimulatedNetwork::NetworkConditions c; c.latency_min=c.latency_max=std::chrono::milliseconds(0); c.jitter_max=std::chrono::milliseconds(0); network.SetNetworkConditions(c);} 

TEST_CASE("MisbehaviorTest - InvalidPoWPenalty", "[misbehaviortest][network]") {
    SimulatedNetwork network(12345); SetZeroLatency(network);
    SimulatedNode victim(1,&network); NodeSimulator attacker(2,&network);
    for(int i=0;i<5;i++) victim.MineBlock();
    // Connect first with PoW validation bypassed (default)
attacker.ConnectTo(1);
    TestOrchestrator orch(&network);
    REQUIRE(orch.WaitForConnection(victim, attacker));
    // Now enable strict PoW validation before sending invalid headers
    victim.SetBypassPOWValidation(false);
    attacker.SendInvalidPoWHeaders(1, victim.GetTipHash(), 10);
    REQUIRE(orch.WaitForPeerCount(victim, 0, std::chrono::seconds(3)));
}

TEST_CASE("MisbehaviorTest - OversizedMessagePenalty", "[misbehaviortest][network]") {
    SimulatedNetwork network(12346); SetZeroLatency(network);
    SimulatedNode victim(10,&network); NodeSimulator attacker(20,&network);
    for(int i=0;i<5;i++) victim.MineBlock();
attacker.ConnectTo(10);
    TestOrchestrator orch(&network);
    REQUIRE(orch.WaitForConnection(victim, attacker));
    for(int j=0;j<5;j++){ attacker.SendOversizedHeaders(10,100000);} // >80000 limit
    REQUIRE(orch.WaitForPeerCount(victim, 0, std::chrono::seconds(3)));
}

TEST_CASE("MisbehaviorTest - NonContinuousHeadersPenalty", "[misbehaviortest][network]") {
    SimulatedNetwork network(12347); SetZeroLatency(network);
    SimulatedNode victim(30,&network); NodeSimulator attacker(40,&network);
    for(int i=0;i<5;i++) victim.MineBlock();
attacker.ConnectTo(30);
    TestOrchestrator orch(&network);
    REQUIRE(orch.WaitForConnection(victim, attacker));
    for(int j=0;j<5;j++){ attacker.SendNonContinuousHeaders(30,victim.GetTipHash()); }
    REQUIRE(orch.WaitForPeerCount(victim, 0, std::chrono::seconds(3)));
}

TEST_CASE("MisbehaviorTest - TooManyOrphansPenalty", "[misbehaviortest][network]") {
    SimulatedNetwork network(12348); SetZeroLatency(network);
    SimulatedNode victim(50,&network); NodeSimulator attacker(60,&network);
    for(int i=0;i<5;i++) victim.MineBlock();
    // Connect first with PoW validation bypassed (default)
attacker.ConnectTo(50);
    TestOrchestrator orch(&network);
    REQUIRE(orch.WaitForConnection(victim, attacker));
    // Now enable strict PoW validation before flooding orphans
    victim.SetBypassPOWValidation(false);
    attacker.SendOrphanHeaders(50,1000);
    REQUIRE(orch.WaitForPeerCount(victim, 0, std::chrono::seconds(5)));
}

TEST_CASE("MisbehaviorTest - InstantDisconnect", "[misbehaviortest][network]") {
    // Bitcoin Core (March 2024+): Any misbehavior = instant discourage
    // Non-continuous headers immediately trigger disconnect (no score accumulation)
    SimulatedNetwork network(12349); SetZeroLatency(network);
    SimulatedNode victim(70,&network); NodeSimulator attacker(80,&network);
    for(int i=0;i<5;i++) victim.MineBlock();
attacker.ConnectTo(70);
    TestOrchestrator orch(&network);
    REQUIRE(orch.WaitForConnection(victim, attacker));
    // Single non-continuous headers message triggers instant disconnect
    attacker.SendNonContinuousHeaders(70,victim.GetTipHash());
    REQUIRE(orch.WaitForPeerCount(victim, 0, std::chrono::seconds(3)));
}

TEST_CASE("DuplicateHeaders - Resending same valid header does not penalize or disconnect", "[misbehaviortest][network][duplicates]") {
    SimulatedNetwork network(12350); SetZeroLatency(network);
    SimulatedNode victim(90, &network); NodeSimulator attacker(91, &network);

    // Ensure victim has a known tip to attach to
    for (int i = 0; i < 3; ++i) victim.MineBlock();

    // Connect attacker -> victim
    attacker.ConnectTo(90);
    TestOrchestrator orch(&network);
    REQUIRE(orch.WaitForConnection(victim, attacker));

    // Build a header that connects to victim's tip
    CBlockHeader hdr;
    hdr.nVersion = 1;
    hdr.hashPrevBlock = victim.GetTipHash();
    hdr.nTime = static_cast<uint32_t>(network.GetCurrentTime() / 1000);
    hdr.nBits = unicity::chain::GlobalChainParams::Get().GenesisBlock().nBits;
    hdr.nNonce = 42;
    // PoW bypass is enabled by default in tests; non-null value to pass cheap checks if needed
    hdr.hashRandomX.SetHex("0000000000000000000000000000000000000000000000000000000000000001");

    // Serialize HEADERS with single header
    message::HeadersMessage msg; msg.headers = {hdr};
    auto payload = msg.serialize();
    protocol::MessageHeader mhdr(protocol::magic::REGTEST, protocol::commands::HEADERS, static_cast<uint32_t>(payload.size()));
    uint256 hash = Hash(payload);
    std::memcpy(mhdr.checksum.data(), hash.begin(), 4);
    auto mhdr_bytes = message::serialize_header(mhdr);
    std::vector<uint8_t> full; full.reserve(mhdr_bytes.size() + payload.size());
    full.insert(full.end(), mhdr_bytes.begin(), mhdr_bytes.end());
    full.insert(full.end(), payload.begin(), payload.end());

    // Send first time
    network.SendMessage(attacker.GetId(), victim.GetId(), full);
    for (int i = 0; i < 5; ++i) network.AdvanceTime(200);

    // Capture peer_id and verify not misbehaving
    auto& pm = victim.GetNetworkManager().peer_manager();
    int peer_id = orch.GetPeerId(victim, attacker);
    REQUIRE(peer_id >= 0);
    bool misbehaving_before = pm.IsMisbehaving(peer_id);
    CHECK_FALSE(misbehaving_before);

    // Re-send the exact same header
    network.SendMessage(attacker.GetId(), victim.GetId(), full);
    for (int i = 0; i < 5; ++i) network.AdvanceTime(200);

    // Assert still connected and not misbehaving (duplicate valid header is harmless)
    CHECK(victim.GetPeerCount() == 1);
    bool misbehaving_after = pm.IsMisbehaving(peer_id);
    CHECK_FALSE(misbehaving_after);
    CHECK_FALSE(victim.IsBanned(attacker.GetAddress()));
}

// Custom ChainParams with achievable nMinimumChainWork for testing already_validated_work
class AlreadyValidatedWorkParams : public chain::ChainParams {
public:
    AlreadyValidatedWorkParams() {
        chainType = chain::ChainType::REGTEST;
        consensus.powLimit = uint256S("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetSpacing = 2 * 60;
        consensus.nRandomXEpochDuration = 365ULL * 24 * 60 * 60 * 100;
        consensus.nASERTHalfLife = 60 * 60;
        consensus.nASERTAnchorHeight = 1;
        // Set minimum work equivalent to ~5 blocks at easiest difficulty
        // This is achievable, so we can build a chain that exceeds it,
        // then test that re-requesting early headers doesn't trigger penalty
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000000000000010");
        consensus.nNetworkExpirationInterval = 0;
        consensus.nNetworkExpirationGracePeriod = 0;
        consensus.nSuspiciousReorgDepth = 100;
        nDefaultPort = 29591;
        genesis = chain::CreateGenesisBlock(1296688602, 2, 0x207fffff, 1);
        consensus.hashGenesisBlock = genesis.GetHash();
    }
};

TEST_CASE("AlreadyValidatedWork - Re-requesting headers on active chain skips low-work check", "[misbehaviortest][network][already_validated_work]") {
    // This test verifies the "already_validated_work" logic (Bitcoin Core parity).
    //
    // Setup:
    // - Use custom ChainParams with non-zero nMinimumChainWork
    // - Build victim's chain to height 20 (exceeds minimum work)
    // - Re-send headers from height 1-2 (which ALONE would fail low-work check)
    // - Because they END on active chain, already_validated_work=true
    // - Low-work check is SKIPPED, peer is NOT penalized
    //
    // Without already_validated_work, this would disconnect the peer.

    SimulatedNetwork network(12351); SetZeroLatency(network);

    // Create victim with custom params that have non-zero nMinimumChainWork
    auto params = std::make_unique<AlreadyValidatedWorkParams>();
    SimulatedNode victim(100, &network, params.get());
    victim.SetBypassPOWValidation(true);

    // Build victim's chain to height 20 (well above minimum work)
    std::vector<uint256> block_hashes;
    for (int i = 0; i < 20; ++i) {
        block_hashes.push_back(victim.MineBlock());
    }
    REQUIRE(victim.GetTipHeight() == 20);

    // Connect attacker -> victim
    NodeSimulator attacker(101, &network);
    attacker.SetBypassPOWValidation(true);
    attacker.ConnectTo(100);
    TestOrchestrator orch(&network);
    REQUIRE(orch.WaitForConnection(victim, attacker));

    // Get headers from early in victim's chain (blocks 1-2)
    // These headers ALONE have work < nMinimumChainWork
    // But they END on active chain, so already_validated_work=true
    std::vector<CBlockHeader> headers_to_resend;
    for (int i = 0; i < 2; ++i) {
        const chain::CBlockIndex* pindex = victim.GetChainstate().LookupBlockIndex(block_hashes[i]);
        REQUIRE(pindex != nullptr);
        headers_to_resend.push_back(pindex->GetBlockHeader());
    }

    // Manually construct and send HEADERS message
    message::HeadersMessage msg;
    msg.headers = headers_to_resend;
    auto payload = msg.serialize();
    protocol::MessageHeader mhdr(protocol::magic::REGTEST, protocol::commands::HEADERS, static_cast<uint32_t>(payload.size()));
    uint256 hash = Hash(payload);
    std::memcpy(mhdr.checksum.data(), hash.begin(), 4);
    auto mhdr_bytes = message::serialize_header(mhdr);
    std::vector<uint8_t> full;
    full.reserve(mhdr_bytes.size() + payload.size());
    full.insert(full.end(), mhdr_bytes.begin(), mhdr_bytes.end());
    full.insert(full.end(), payload.begin(), payload.end());

    // Record peer_id before sending
    auto& pm = victim.GetNetworkManager().peer_manager();
    int peer_id = orch.GetPeerId(victim, attacker);
    REQUIRE(peer_id >= 0);
    CHECK_FALSE(pm.IsMisbehaving(peer_id));

    // Send headers that are already on active chain
    INFO("Sending 2 headers from height 1-2 (low work, but on active chain)");
    network.SendMessage(attacker.GetId(), victim.GetId(), full);
    for (int i = 0; i < 20; ++i) network.AdvanceTime(100);

    // Verify: peer should NOT be penalized
    // Because headers end on active chain, already_validated_work=true,
    // and the low-work check is skipped
    CHECK(victim.GetPeerCount() == 1);
    CHECK_FALSE(pm.IsMisbehaving(peer_id));
    CHECK_FALSE(victim.IsBanned(attacker.GetAddress()));
}

