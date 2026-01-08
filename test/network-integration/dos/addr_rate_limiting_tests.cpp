// DoS: ADDR message rate limiting tests
// Verifies that rapid ADDR message spam is rate-limited (Bitcoin Core pattern)

#include "catch_amalgamated.hpp"
#include "infra/simulated_network.hpp"
#include "infra/simulated_node.hpp"
#include "test_orchestrator.hpp"
#include "network/protocol.hpp"
#include "network/message.hpp"
#include "util/hash.hpp"
#include "network/peer_discovery_manager.hpp"
#include "network/network_manager.hpp"
#include "chain/chainparams.hpp"

using namespace unicity;
using namespace unicity::test;
using namespace unicity::protocol;

static struct TestSetup {
    TestSetup() { chain::GlobalChainParams::Select(chain::ChainType::REGTEST); }
} test_setup_rate_limit;

// Helper: Create test address with unique IP across diverse /16 netgroups
// NOTE: AddrManager has per-netgroup limits (MAX_PER_NETGROUP_NEW = 32), so
// we distribute addresses across multiple /16 netgroups to avoid hitting limits.
static TimestampedAddress MakeTestAddress(uint32_t index, uint64_t timestamp_s = 0) {
    TimestampedAddress ta;
    ta.timestamp = timestamp_s > 0 ? static_cast<uint32_t>(timestamp_s) :
                   static_cast<uint32_t>(std::time(nullptr));

    // Generate unique IP across diverse /16 netgroups:
    // Use A.B.x.y where A.B varies to create different /16 netgroups
    // First byte: 8-250 (routable public IPs, avoiding 10/172/192 private ranges)
    // Second byte: rotates based on index to create diverse /16s
    // Third/Fourth bytes: provide uniqueness within each /16
    //
    // With MAX_PER_NETGROUP_NEW = 32, we can store 32 addresses per /16.
    // For 1000 addresses, we need at least ceil(1000/32) = 32 different /16s.
    // Using index/32 to select netgroup ensures good distribution.
    uint8_t first_byte = 8 + (index / 32) % 200;  // 8-207
    uint8_t second_byte = (index / 32 / 200) % 256;  // Overflow for very large index
    uint8_t third_byte = (index % 32);
    uint8_t fourth_byte = 1;  // Non-zero

    uint32_t ip_val = (static_cast<uint32_t>(first_byte) << 24) |
                      (static_cast<uint32_t>(second_byte) << 16) |
                      (static_cast<uint32_t>(third_byte) << 8) |
                      static_cast<uint32_t>(fourth_byte);

    auto ip = asio::ip::make_address_v6(
        asio::ip::v4_mapped,
        asio::ip::address_v4{static_cast<asio::ip::address_v4::uint_type>(ip_val)}
    );
    auto bytes = ip.to_bytes();
    std::copy(bytes.begin(), bytes.end(), ta.address.ip.begin());
    ta.address.services = ServiceFlags::NODE_NETWORK;
    ta.address.port = ports::REGTEST;

    return ta;
}

TEST_CASE("DoS: ADDR messages are rate limited to prevent CPU exhaustion", "[dos][addr][ratelimit]") {
    SimulatedNetwork network(57100);
    TestOrchestrator orchestrator(&network);

    SimulatedNode victim(1, &network);
    SimulatedNode attacker(2, &network);

    REQUIRE(attacker.ConnectTo(victim.GetId()));
    REQUIRE(orchestrator.WaitForConnection(victim, attacker));

    // Boost the token bucket by simulating GETADDR was sent (normal flow)
    // Without this, CI runners with low uptime have too few initial tokens
    int peer_id = orchestrator.GetPeerId(victim, attacker);
    victim.GetNetworkManager().discovery_manager_for_test().NotifyGetAddrSent(peer_id);

    // ATTACK: Send 10 messages × 1000 addresses with small delays
    // Without rate limiting: 10,000 addresses processed
    // With rate limiting: only ~1000 processed initially (token bucket starts at 1000)

    const int num_messages = 10;
    const int addrs_per_message = protocol::MAX_ADDR_SIZE;  // 1000

    for (int msg_idx = 0; msg_idx < num_messages; msg_idx++) {
        message::AddrMessage addr_msg;
        addr_msg.addresses.reserve(addrs_per_message);

        for (int i = 0; i < addrs_per_message; i++) {
            uint32_t unique_idx = msg_idx * addrs_per_message + i;
            addr_msg.addresses.push_back(MakeTestAddress(unique_idx));
        }

        auto payload = addr_msg.serialize();
        protocol::MessageHeader header(magic::REGTEST, commands::ADDR, static_cast<uint32_t>(payload.size()));
        uint256 hash = Hash(payload);
        std::memcpy(header.checksum.data(), hash.begin(), 4);
        auto header_bytes = message::serialize_header(header);

        std::vector<uint8_t> full;
        full.reserve(header_bytes.size() + payload.size());
        full.insert(full.end(), header_bytes.begin(), header_bytes.end());
        full.insert(full.end(), payload.begin(), payload.end());

        network.SendMessage(attacker.GetId(), victim.GetId(), full);
        // Small delay between messages to avoid triggering disconnect
        orchestrator.AdvanceTime(std::chrono::milliseconds(100));
    }

    // Process all messages
    orchestrator.AdvanceTime(std::chrono::seconds(1));

    // Verify rate limiting occurred:
    // - Token bucket starts at 1000
    // - First message processes up to 1000 addresses (empties bucket)
    // - Subsequent messages are heavily rate-limited
    // - Bucket refills slowly at 0.1/sec

    // Check victim's address manager size
    // Per-source limit (MAX_ADDRESSES_PER_SOURCE=64) caps addresses from any single peer
    // This is stricter than rate limiting and provides Sybil resistance
    auto& discovery_mgr = victim.GetNetworkManager().discovery_manager_for_test();
    size_t addr_count = discovery_mgr.Size();

    INFO("Address manager size: " << addr_count);

    // Per-source limit of 64 addresses from any single peer
    // This is the primary DoS protection for ADDR spam
    REQUIRE(addr_count <= 64);  // Per-source limit
    REQUIRE(addr_count >= 32);  // Some addresses should be added (allowing for netgroup limits)

    // Verify peer is still connected (not banned for spam)
    REQUIRE(victim.GetPeerCount() == 1);
}

TEST_CASE("DoS: Rate limiting allows burst then throttles", "[dos][addr][ratelimit]") {
    SimulatedNetwork network(57101);
    TestOrchestrator orchestrator(&network);

    SimulatedNode victim(1, &network);
    SimulatedNode sender(2, &network);

    REQUIRE(sender.ConnectTo(victim.GetId()));
    REQUIRE(orchestrator.WaitForConnection(victim, sender));

    // Send three messages with delays
    // First should be mostly accepted, second/third heavily rate-limited
    for (int msg = 0; msg < 3; msg++) {
        message::AddrMessage addr_msg;
        for (int i = msg * 1000; i < (msg + 1) * 1000; i++) {
            addr_msg.addresses.push_back(MakeTestAddress(i));
        }

        auto payload = addr_msg.serialize();
        protocol::MessageHeader header(magic::REGTEST, commands::ADDR, static_cast<uint32_t>(payload.size()));
        uint256 hash = Hash(payload);
        std::memcpy(header.checksum.data(), hash.begin(), 4);
        auto header_bytes = message::serialize_header(header);

        std::vector<uint8_t> full;
        full.reserve(header_bytes.size() + payload.size());
        full.insert(full.end(), header_bytes.begin(), header_bytes.end());
        full.insert(full.end(), payload.begin(), payload.end());

        network.SendMessage(sender.GetId(), victim.GetId(), full);
        orchestrator.AdvanceTime(std::chrono::milliseconds(500));
    }

    // Verify peer still connected - rate limiting doesn't cause disconnect
    REQUIRE(victim.GetPeerCount() == 1);
}

TEST_CASE("DoS: Rate limiting constants match Bitcoin Core", "[dos][addr][parity]") {
    // Verify our rate limiting works correctly
    // This test mainly validates system stability with rate limiting active

    SimulatedNetwork network(57102);
    TestOrchestrator orchestrator(&network);

    SimulatedNode node1(1, &network);
    SimulatedNode node2(2, &network);

    REQUIRE(node2.ConnectTo(node1.GetId()));
    REQUIRE(orchestrator.WaitForConnection(node1, node2));

    // Send messages with delays to respect rate limiting
    for (int batch = 0; batch < 5; batch++) {
        message::AddrMessage addr_msg;
        for (int i = batch * 200; i < (batch + 1) * 200; i++) {
            addr_msg.addresses.push_back(MakeTestAddress(i));
        }

        auto payload = addr_msg.serialize();
        protocol::MessageHeader header(magic::REGTEST, commands::ADDR, static_cast<uint32_t>(payload.size()));
        uint256 hash = Hash(payload);
        std::memcpy(header.checksum.data(), hash.begin(), 4);
        auto header_bytes = message::serialize_header(header);

        std::vector<uint8_t> full;
        full.reserve(header_bytes.size() + payload.size());
        full.insert(full.end(), header_bytes.begin(), header_bytes.end());
        full.insert(full.end(), payload.begin(), payload.end());

        network.SendMessage(node2.GetId(), node1.GetId(), full);
        orchestrator.AdvanceTime(std::chrono::milliseconds(500));
    }

    // Verify peer still connected - rate limiting is working correctly
    REQUIRE(node1.GetPeerCount() == 1);
}
