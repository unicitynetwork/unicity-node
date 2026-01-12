// DoS: Reserve guard on huge vector CompactSize

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
} test_setup_reserve;

TEST_CASE("DoS: Huge vector CompactSize triggers disconnect (reserve guard)", "[dos][network][reserve]") {
    // VULNERABILITY (historical): vector.reserve() using unchecked CompactSize could allocate massive memory
    // ATTACK: Send 0xFF + 0xFFFFFFFFFFFFFFFF as the vector size (e.g., INV count)
    // EXPECTED: Parser caps size (MAX_INV_SIZE) and disconnects without OOM

    SimulatedNetwork network(1414);
    TestOrchestrator orchestrator(&network);

    SimulatedNode victim(1, &network);
    SimulatedNode attacker(2, &network);

    REQUIRE(attacker.ConnectTo(1));
    REQUIRE(orchestrator.WaitForConnection(victim, attacker));

    // Malicious INV payload: CompactSize = 0xFF + 0xFFFFFFFFFFFFFFFF (LE)
    std::vector<uint8_t> payload;
    payload.reserve(9);
    payload.push_back(0xFF);
    for (int i = 0; i < 8; ++i) payload.push_back(0xFF);

    protocol::MessageHeader header(protocol::magic::REGTEST, protocol::commands::HEADERS, static_cast<uint32_t>(payload.size()));
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
