// Malformed message tests for P2P layer

#include "test_helper.hpp"
#include "test_orchestrator.hpp"
#include "infra/simulated_network.hpp"
#include "infra/simulated_node.hpp"

#include "network/message.hpp"
#include "util/hash.hpp"
#include "network/protocol.hpp"

using namespace unicity;
using namespace unicity::test;

static std::vector<uint8_t> MakeRawMessage(uint32_t magic, const std::string& command, const std::vector<uint8_t>& payload) {
    protocol::MessageHeader header(magic, command, static_cast<uint32_t>(payload.size()));
        uint256 hash = Hash(payload);
        std::memcpy(header.checksum.data(), hash.begin(), 4);
    auto header_bytes = message::serialize_header(header);
    std::vector<uint8_t> full;
    full.reserve(header_bytes.size() + payload.size());
    full.insert(full.end(), header_bytes.begin(), header_bytes.end());
    full.insert(full.end(), payload.begin(), payload.end());
    return full;
}

TEST_CASE("Malformed: wrong magic disconnects", "[network][malformed]") {
    SimulatedNetwork network(2024);
    TestOrchestrator orch(&network);

    SimulatedNode victim(1, &network);
    SimulatedNode attacker(2, &network);

    // Establish a normal connection first so we can target the existing channel
    REQUIRE(attacker.ConnectTo(1));
    REQUIRE(orch.WaitForConnection(victim, attacker));

    // Craft a valid PING payload but with WRONG magic in header
    message::PingMessage ping(0xABCDEF0123456789ULL);
    auto payload = ping.serialize();
    auto raw = MakeRawMessage(protocol::magic::MAINNET /*wrong for regtest*/, protocol::commands::PING, payload);

    // Inject directly over the bridged transport
    network.SendMessage(attacker.GetId(), victim.GetId(), raw);

    // Disconnect should occur on both ends
    REQUIRE(orch.WaitForPeerCount(victim, 0));
    REQUIRE(orch.WaitForPeerCount(attacker, 0));
}

TEST_CASE("Malformed: checksum mismatch disconnects", "[network][malformed]") {
    SimulatedNetwork network(2025);
    TestOrchestrator orch(&network);

    SimulatedNode victim(1, &network);
    SimulatedNode attacker(2, &network);

    REQUIRE(attacker.ConnectTo(1));
    REQUIRE(orch.WaitForConnection(victim, attacker));

    // Create a valid PING message, then flip a payload byte after header creation
    message::PingMessage ping(0x1122334455667788ULL);
    auto payload = ping.serialize();
    protocol::MessageHeader header(protocol::magic::REGTEST, protocol::commands::PING, static_cast<uint32_t>(payload.size()));
        uint256 hash = Hash(payload);
        std::memcpy(header.checksum.data(), hash.begin(), 4);
    auto header_bytes = message::serialize_header(header);

    // Flip one byte to break checksum
    if (!payload.empty()) payload[0] ^= 0xFF;

    std::vector<uint8_t> raw;
    raw.reserve(header_bytes.size() + payload.size());
    raw.insert(raw.end(), header_bytes.begin(), header_bytes.end());
    raw.insert(raw.end(), payload.begin(), payload.end());

    network.SendMessage(attacker.GetId(), victim.GetId(), raw);

    REQUIRE(orch.WaitForPeerCount(victim, 0));
    REQUIRE(orch.WaitForPeerCount(attacker, 0));
}

TEST_CASE("Malformed: VERACK with payload causes disconnect", "[network][malformed]") {
    SimulatedNetwork network(3030);
    TestOrchestrator orch(&network);

    SimulatedNode victim(1, &network);
    SimulatedNode attacker(2, &network);

    REQUIRE(attacker.ConnectTo(1));
    REQUIRE(orch.WaitForConnection(victim, attacker));

    // VERACK must have empty payload; send 1 byte
    std::vector<uint8_t> bogus_payload = {0x00};
    auto raw = MakeRawMessage(protocol::magic::REGTEST, protocol::commands::VERACK, bogus_payload);

    network.SendMessage(attacker.GetId(), victim.GetId(), raw);

    REQUIRE(orch.WaitForPeerCount(victim, 0));
    REQUIRE(orch.WaitForPeerCount(attacker, 0));
}

TEST_CASE("Malformed: VERSION with oversized user agent rejected", "[network][malformed]") {
    SimulatedNetwork network(4040);
    TestOrchestrator orch(&network);

    SimulatedNode victim(1, &network);
    // No connection setup; we inject a bogus VERSION as the first message

    // Build VERSION payload with an oversized user agent (> MAX_SUBVERSION_LENGTH)
    message::VersionMessage ver;
    ver.version = protocol::PROTOCOL_VERSION;
    ver.services = protocol::NODE_NETWORK;
    ver.timestamp = 0;
    ver.addr_recv = protocol::NetworkAddress();
    ver.addr_from = protocol::NetworkAddress();
    ver.nonce = 0xCAFEBABEULL;
    ver.user_agent = std::string(protocol::MAX_SUBVERSION_LENGTH + 50, 'A');
    ver.start_height = 0;

    auto payload = ver.serialize();
    auto raw = MakeRawMessage(protocol::magic::REGTEST, protocol::commands::VERSION, payload);

    // From a synthetic node id 2 (not fully constructed)
    network.SendMessage(2, victim.GetId(), raw);

    // Victim should have no peers after processing
    REQUIRE(orch.WaitForPeerCount(victim, 0));
}
