// DoS: Oversized GETHEADERS locator triggers disconnect

#include "catch_amalgamated.hpp"
#include "infra/simulated_network.hpp"
#include "infra/simulated_node.hpp"
#include "test_orchestrator.hpp"
#include "network/message.hpp"
#include "util/hash.hpp"
#include "chain/chainparams.hpp"

using namespace unicity;
using namespace unicity::chain;
using namespace unicity::test;

static struct TestSetup {
    TestSetup() { chain::GlobalChainParams::Select(chain::ChainType::REGTEST); }
} test_setup_getheaders;

TEST_CASE("DoS: Oversized GETHEADERS locator triggers disconnect", "[dos][network][getheaders-oversize]") {
    // VULNERABILITY (historical): No cap on CBlockLocator size => CPU blowup in FindFork()
    // ATTACK: Send GETHEADERS with 1000+ locator hashes
    // EXPECTED: Deserializer caps at MAX_LOCATOR_SZ and disconnects peer

    SimulatedNetwork network(1717);
    TestOrchestrator orchestrator(&network);

    SimulatedNode victim(1, &network);
    SimulatedNode attacker(2, &network);

    REQUIRE(attacker.ConnectTo(1));
    REQUIRE(orchestrator.WaitForConnection(victim, attacker));

    // Build oversized GETHEADERS payload using MessageSerializer
    message::MessageSerializer s;
    s.write_uint32(protocol::PROTOCOL_VERSION);
    const uint64_t LOCATOR_COUNT = 1200; // > MAX_LOCATOR_SZ (101)
    s.write_varint(LOCATOR_COUNT);

    // Write LOCATOR_COUNT dummy hashes (all zeros)
    std::array<uint8_t, 32> zero{};
    for (uint64_t i = 0; i < LOCATOR_COUNT; ++i) {
        s.write_bytes(zero.data(), zero.size());
    }
    // hash_stop = zero
    s.write_bytes(zero.data(), zero.size());

    auto payload = s.data();

    protocol::MessageHeader header(protocol::magic::REGTEST, protocol::commands::GETHEADERS, static_cast<uint32_t>(payload.size()));
    uint256 hash = Hash(payload);
    std::memcpy(header.checksum.data(), hash.begin(), 4);
    auto header_bytes = message::serialize_header(header);

    std::vector<uint8_t> full;
    full.reserve(header_bytes.size() + payload.size());
    full.insert(full.end(), header_bytes.begin(), header_bytes.end());
    full.insert(full.end(), payload.begin(), payload.end());

    network.SendMessage(attacker.GetId(), victim.GetId(), full);

    orchestrator.AdvanceTime(std::chrono::seconds(1));

    REQUIRE(orchestrator.WaitForPeerCount(victim, 0, std::chrono::seconds(2)));
}
