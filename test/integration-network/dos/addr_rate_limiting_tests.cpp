// DoS: ADDR message protection tests
// Verifies per-source limits cap addresses from any single peer (Sybil resistance)

#include "catch_amalgamated.hpp"
#include "infra/simulated_network.hpp"
#include "infra/simulated_node.hpp"
#include "test_orchestrator.hpp"
#include "network/protocol.hpp"
#include "network/message.hpp"
#include "util/hash.hpp"
#include "network/addr_relay_manager.hpp"
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

TEST_CASE("DoS: Per-source limit caps ADDR spam from single peer", "[dos][addr][persource]") {
    // Tests MAX_ADDRESSES_PER_SOURCE (64) - the primary Sybil resistance for ADDR spam
    // An attacker controlling a single IP can only contribute 64 addresses to our AddrManager
    // Bitcoin Core achieves similar protection via bucket assignment based on source netgroup

    SimulatedNetwork network(57100);
    // Simulation starts at realistic time (Jan 2024), so timestamps are valid
    TestOrchestrator orchestrator(&network);

    SimulatedNode victim(1, &network);
    SimulatedNode attacker(2, &network);

    REQUIRE(attacker.ConnectTo(victim.GetId()));
    REQUIRE(orchestrator.WaitForConnection(victim, attacker));

    // Boost the token bucket by simulating GETADDR was sent (normal flow)
    int peer_id = orchestrator.GetPeerId(victim, attacker);
    victim.GetDiscoveryManager().NotifyGetAddrSent(peer_id);

    // ATTACK: Send 10 messages × 1000 addresses = 10,000 total addresses
    // Expected: Only 64 are stored (per-source limit)
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
        orchestrator.AdvanceTime(std::chrono::milliseconds(100));
    }

    orchestrator.AdvanceTime(std::chrono::seconds(1));

    // Verify per-source limit enforced
    auto& discovery_mgr = victim.GetDiscoveryManager();
    size_t addr_count = discovery_mgr.Size();

    INFO("Address manager size: " << addr_count << " (expected <= 64 per-source limit)");

    // MAX_ADDRESSES_PER_SOURCE = 64
    REQUIRE(addr_count <= 64);
    REQUIRE(addr_count >= 32);  // Some stored (netgroup limits may reduce further)

    // Peer not banned - per-source limiting is silent protection
    REQUIRE(victim.GetPeerCount() == 1);
}


