// DoS: CompactSize overflow triggers disconnect (18 EB allocation attempt)

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
} test_setup_overflow;

TEST_CASE("DoS: CompactSize overflow triggers disconnect (18 EB allocation attempt)", "[dos][network][overflow]") {
    // VULNERABILITY (historical): CompactSize read without MAX_SIZE cap could trigger huge allocations
    // ATTACK: Send varint prefix 0xFF with value 0xFFFFFFFFFFFFFFFF to claim massive count
    // EXPECTED: Our parser rejects (MAX_SIZE cap), peer disconnects without OOM

    SimulatedNetwork network(1313);
    TestOrchestrator orchestrator(&network);

    SimulatedNode victim(1, &network);
    SimulatedNode attacker(2, &network);

    // Connect normally to complete handshake
    REQUIRE(attacker.ConnectTo(1));
    REQUIRE(orchestrator.WaitForConnection(victim, attacker));

    // Build malicious HEADERS payload: CompactSize = 0xFF + 0xFFFFFFFFFFFFFFFF (LE)
    std::vector<uint8_t> payload;
    payload.reserve(9);
    payload.push_back(0xFF);
    for (int i = 0; i < 8; ++i) payload.push_back(0xFF);

    // Create message header (REGTEST magic)
    protocol::MessageHeader header(protocol::magic::REGTEST, protocol::commands::HEADERS, static_cast<uint32_t>(payload.size()));
    uint256 hash = Hash(payload);
    std::memcpy(header.checksum.data(), hash.begin(), 4);
    auto header_bytes = message::serialize_header(header);

    // Compose full message
    std::vector<uint8_t> full;
    full.reserve(header_bytes.size() + payload.size());
    full.insert(full.end(), header_bytes.begin(), header_bytes.end());
    full.insert(full.end(), payload.begin(), payload.end());

    // Inject directly via simulated network (attacker -> victim)
    network.SendMessage(attacker.GetId(), victim.GetId(), full);

    // Advance time to process
    orchestrator.AdvanceTime(std::chrono::seconds(1));

    // Peer should be disconnected due to malformed message
    REQUIRE(orchestrator.WaitForPeerCount(victim, 0, std::chrono::seconds(2)));
}
