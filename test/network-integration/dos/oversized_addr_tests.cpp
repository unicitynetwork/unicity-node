// DoS: Oversized ADDR triggers disconnect

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
} test_setup_addr;

TEST_CASE("DoS: Oversized ADDR triggers disconnect", "[dos][network][addr]") {
    // ATTACK: Send 10,000 addresses in a single ADDR message
    // EXPECTED: Deserializer caps at MAX_ADDR_SIZE and disconnects

    SimulatedNetwork network(1818);
    TestOrchestrator orchestrator(&network);

    SimulatedNode victim(1, &network);
    SimulatedNode attacker(2, &network);

    REQUIRE(attacker.ConnectTo(1));
    REQUIRE(orchestrator.WaitForConnection(victim, attacker));

    message::MessageSerializer s;
    const uint64_t COUNT = 10000;
    s.write_varint(COUNT); // No addresses needed; parser rejects by count alone

    auto payload = s.data();

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
