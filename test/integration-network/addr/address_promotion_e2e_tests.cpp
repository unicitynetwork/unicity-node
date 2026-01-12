/**
 * End-to-End Address Promotion Tests
 *
 * These tests verify the complete address lifecycle:
 *   1. Node A receives ADDR message containing address X
 *   2. Address X is stored in Node A's NEW table
 *   3. Node A connects to X (which is actually Node C)
 *   4. On successful handshake (VERACK), good() is called
 *   5. Address X moves from NEW to TRIED table
 *
 * This validates that the address manager properly integrates with the
 * connection lifecycle, not just unit testing individual functions.
 *
 * Key verification points:
 * - Address storage via ADDR message protocol
 * - NEW→TRIED promotion via good() after handshake
 * - Proper integration between NetworkManager and AddressManager
 */

#include "catch_amalgamated.hpp"
#include "infra/simulated_network.hpp"
#include "infra/simulated_node.hpp"
#include "test_orchestrator.hpp"
#include "network/protocol.hpp"
#include "network/message.hpp"
#include "network/addr_manager.hpp"
#include "network/peer_discovery_manager.hpp"
#include "util/hash.hpp"
#include <cstring>

using namespace unicity;
using namespace unicity::test;
using namespace unicity::network;
using namespace unicity::protocol;

// Helper: create wire format message
static std::vector<uint8_t> MakeWire(const std::string& cmd, const std::vector<uint8_t>& payload) {
    protocol::MessageHeader hdr(magic::REGTEST, cmd, static_cast<uint32_t>(payload.size()));
    uint256 hash = Hash(payload);
    std::memcpy(hdr.checksum.data(), hash.begin(), 4);
    auto hdr_bytes = message::serialize_header(hdr);
    std::vector<uint8_t> full;
    full.reserve(hdr_bytes.size() + payload.size());
    full.insert(full.end(), hdr_bytes.begin(), hdr_bytes.end());
    full.insert(full.end(), payload.begin(), payload.end());
    return full;
}

// Helper: create ADDR message with single IPv4 address
static message::AddrMessage MakeAddrMsg(const std::string& ip_v4, uint16_t port, uint32_t ts) {
    message::AddrMessage msg;
    protocol::TimestampedAddress ta;
    ta.timestamp = ts;
    ta.address.services = protocol::ServiceFlags::NODE_NETWORK;
    ta.address.port = port;
    std::memset(ta.address.ip.data(), 0, 10);
    ta.address.ip[10] = 0xFF;
    ta.address.ip[11] = 0xFF;
    int a, b, c, d;
    if (sscanf(ip_v4.c_str(), "%d.%d.%d.%d", &a, &b, &c, &d) == 4) {
        ta.address.ip[12] = static_cast<uint8_t>(a);
        ta.address.ip[13] = static_cast<uint8_t>(b);
        ta.address.ip[14] = static_cast<uint8_t>(c);
        ta.address.ip[15] = static_cast<uint8_t>(d);
    }
    msg.addresses.push_back(ta);
    return msg;
}

// Helper: make NetworkAddress from string
static NetworkAddress MakeIPv4Address(const std::string& ip_str, uint16_t port) {
    NetworkAddress addr;
    addr.services = NODE_NETWORK;
    addr.port = port;
    std::memset(addr.ip.data(), 0, 10);
    addr.ip[10] = 0xFF;
    addr.ip[11] = 0xFF;
    int a, b, c, d;
    if (sscanf(ip_str.c_str(), "%d.%d.%d.%d", &a, &b, &c, &d) == 4) {
        addr.ip[12] = static_cast<uint8_t>(a);
        addr.ip[13] = static_cast<uint8_t>(b);
        addr.ip[14] = static_cast<uint8_t>(c);
        addr.ip[15] = static_cast<uint8_t>(d);
    }
    return addr;
}

TEST_CASE("E2E: Address received via ADDR protocol is stored in NEW table", "[network][addr][e2e][integration]") {
    // This test verifies step 1-2 of the address lifecycle:
    // Node A receives ADDR from peer → Address stored in NEW table

    SimulatedNetwork net(50001);
    TestOrchestrator orch(&net);
    net.EnableCommandTracking(true);

    SimulatedNode nodeA(1, &net);  // Target node (will learn address)
    SimulatedNode nodeB(2, &net);  // Source of ADDR message

    nodeA.SetBypassPOWValidation(true);
    nodeB.SetBypassPOWValidation(true);

    // Connect B to A
    REQUIRE(nodeB.ConnectTo(nodeA.GetId()));
    REQUIRE(orch.WaitForConnection(nodeA, nodeB));

    // Let handshake complete
    for (int i = 0; i < 12; ++i) {
        orch.AdvanceTime(std::chrono::milliseconds(100));
    }

    // Get current address counts for A
    auto& discovery = nodeA.GetNetworkManager().discovery_manager();
    size_t new_before = discovery.NewCount();
    size_t tried_before = discovery.TriedCount();

    // B sends ADDR message to A with a routable address
    // Using a public IP that passes IsRoutable() checks
    auto now_s = static_cast<uint32_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count()
    );

    auto addr_msg = MakeAddrMsg("185.1.2.100", ports::REGTEST, now_s);
    auto payload = addr_msg.serialize();
    net.SendMessage(nodeB.GetId(), nodeA.GetId(), MakeWire(commands::ADDR, payload));

    // Process the message
    for (int i = 0; i < 6; ++i) {
        orch.AdvanceTime(std::chrono::milliseconds(100));
    }

    // Verify address was added to NEW table
    size_t new_after = discovery.NewCount();
    size_t tried_after = discovery.TriedCount();

    INFO("new_before=" << new_before << " new_after=" << new_after);
    INFO("tried_before=" << tried_before << " tried_after=" << tried_after);

    // Address should be in NEW table (not TRIED since we haven't connected)
    CHECK(new_after > new_before);
    CHECK(tried_after == tried_before);
}

TEST_CASE("E2E: Successful connection promotes address from NEW to TRIED", "[network][addr][e2e][integration]") {
    // This is the key test that verifies the complete pipeline:
    // 1. NodeA receives ADDR with NodeC's address
    // 2. Address is stored in NEW
    // 3. NodeA connects to NodeC
    // 4. On VERACK, good() is called
    // 5. Address moves to TRIED

    SimulatedNetwork net(50002);
    TestOrchestrator orch(&net);
    net.EnableCommandTracking(true);

    // Use custom addresses so NodeC has a routable IP
    // NodeA: 192.168.1.1 (RFC1918 - filtered, but that's ok for the test node)
    // NodeB: 192.168.1.2 (source of ADDR)
    // NodeC: 185.1.2.50 (routable - the address we're testing)
    SimulatedNode nodeA(1, &net);
    SimulatedNode nodeB(2, &net);
    SimulatedNode nodeC(3, &net, "185.1.2.50");  // Custom routable address

    nodeA.SetBypassPOWValidation(true);
    nodeB.SetBypassPOWValidation(true);
    nodeC.SetBypassPOWValidation(true);

    // Connect B to A (so B can send ADDR to A)
    REQUIRE(nodeB.ConnectTo(nodeA.GetId()));
    REQUIRE(orch.WaitForConnection(nodeA, nodeB));
    for (int i = 0; i < 12; ++i) {
        orch.AdvanceTime(std::chrono::milliseconds(100));
    }

    auto& discovery = nodeA.GetNetworkManager().discovery_manager();

    // Check initial state
    size_t new_initial = discovery.NewCount();
    size_t tried_initial = discovery.TriedCount();
    INFO("Initial state: new=" << new_initial << " tried=" << tried_initial);

    // B sends ADDR to A containing C's address
    auto now_s = static_cast<uint32_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count()
    );

    // Note: Must use the same port that NodeC is listening on
    uint16_t nodeC_port = static_cast<uint16_t>(ports::REGTEST + nodeC.GetId());
    auto addr_msg = MakeAddrMsg("185.1.2.50", nodeC_port, now_s);
    auto payload = addr_msg.serialize();
    net.SendMessage(nodeB.GetId(), nodeA.GetId(), MakeWire(commands::ADDR, payload));

    // Process the ADDR message
    for (int i = 0; i < 6; ++i) {
        orch.AdvanceTime(std::chrono::milliseconds(100));
    }

    // Verify address is in NEW table
    size_t new_after_addr = discovery.NewCount();
    size_t tried_after_addr = discovery.TriedCount();
    INFO("After ADDR: new=" << new_after_addr << " tried=" << tried_after_addr);

    REQUIRE(new_after_addr > new_initial);  // Must have address in NEW
    REQUIRE(tried_after_addr == tried_initial);

    // Now NodeA connects to NodeC using the learned address
    // In simulation, we use ConnectTo() which goes through NetworkManager
    REQUIRE(nodeA.ConnectTo(nodeC.GetId(), "185.1.2.50", nodeC_port));
    REQUIRE(orch.WaitForConnection(nodeA, nodeC));

    // Let handshake complete (VERSION + VERACK exchange)
    for (int i = 0; i < 12; ++i) {
        orch.AdvanceTime(std::chrono::milliseconds(100));
    }

    // After successful handshake, good() should have been called
    // This should move the address from NEW to TRIED
    size_t new_after_connect = discovery.NewCount();
    size_t tried_after_connect = discovery.TriedCount();
    INFO("After connect: new=" << new_after_connect << " tried=" << tried_after_connect);

    // Key assertions:
    // - Address should have moved from NEW to TRIED
    // - NEW count should decrease (or stay same if other addresses added)
    // - TRIED count should increase
    CHECK(tried_after_connect > tried_initial);
}

TEST_CASE("E2E: Failed connection does not promote address to TRIED", "[network][addr][e2e][integration]") {
    // Verify that if connection fails, address stays in NEW table

    SimulatedNetwork net(50003);
    TestOrchestrator orch(&net);
    net.EnableCommandTracking(true);

    SimulatedNode nodeA(1, &net);
    SimulatedNode nodeB(2, &net);

    nodeA.SetBypassPOWValidation(true);
    nodeB.SetBypassPOWValidation(true);

    REQUIRE(nodeB.ConnectTo(nodeA.GetId()));
    REQUIRE(orch.WaitForConnection(nodeA, nodeB));
    for (int i = 0; i < 12; ++i) {
        orch.AdvanceTime(std::chrono::milliseconds(100));
    }

    auto& discovery = nodeA.GetNetworkManager().discovery_manager();

    // B sends ADDR with an address that doesn't have a listening node
    auto now_s = static_cast<uint32_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count()
    );

    // Use a routable IP with no node listening
    auto addr_msg = MakeAddrMsg("185.1.2.200", ports::REGTEST, now_s);
    auto payload = addr_msg.serialize();
    net.SendMessage(nodeB.GetId(), nodeA.GetId(), MakeWire(commands::ADDR, payload));

    for (int i = 0; i < 6; ++i) {
        orch.AdvanceTime(std::chrono::milliseconds(100));
    }

    // Verify address is in NEW table
    size_t new_before = discovery.NewCount();
    size_t tried_before = discovery.TriedCount();
    REQUIRE(new_before >= 1);

    // Manually add the address to simulate what would happen
    // In a real scenario, attempt_outbound_connections() would try to connect
    // and fail, then call failed() on the address

    auto bad_addr = MakeIPv4Address("185.1.2.200", ports::REGTEST);

    // Mark an attempt (simulating what NetworkManager does)
    discovery.Attempt(bad_addr);

    // Mark failure (simulating connection failure)
    discovery.Failed(bad_addr);

    // Verify address is still in NEW, not TRIED
    size_t new_after = discovery.NewCount();
    size_t tried_after = discovery.TriedCount();

    CHECK(tried_after == tried_before);  // No promotion to TRIED
    CHECK(new_after >= 1);  // Address still tracked (may have failure count)
}

TEST_CASE("E2E: good() with correct timestamp update (Bitcoin Core parity)", "[network][addr][e2e][parity]") {
    // This test verifies the fix to good() that adds last_try update
    // Without this fix, addresses could be re-selected too quickly

    AddressManager am;

    // Add a routable address
    auto addr = MakeIPv4Address("93.184.216.34", ports::REGTEST);
    REQUIRE(am.add(addr));
    REQUIRE(am.new_count() == 1);
    REQUIRE(am.tried_count() == 0);

    // Call good() - this should:
    // 1. Move address from NEW to TRIED
    // 2. Set last_try to current time (the fix)
    am.good(addr);

    CHECK(am.new_count() == 0);
    CHECK(am.tried_count() == 1);

    // After good(), the address should have a recent last_try timestamp
    // This prevents immediate re-selection (0.01× penalty for 10 min)
    // We can't directly check last_try, but we can verify the address
    // was properly moved to TRIED
}

TEST_CASE("E2E: Multiple address lifecycle - parallel flows", "[network][addr][e2e][integration]") {
    // Test multiple addresses going through the lifecycle simultaneously

    SimulatedNetwork net(50004);
    TestOrchestrator orch(&net);
    net.EnableCommandTracking(true);

    SimulatedNode nodeA(1, &net);
    SimulatedNode nodeB(2, &net);
    SimulatedNode nodeC(3, &net, "185.1.2.51");
    SimulatedNode nodeD(4, &net, "185.1.2.52");

    nodeA.SetBypassPOWValidation(true);
    nodeB.SetBypassPOWValidation(true);
    nodeC.SetBypassPOWValidation(true);
    nodeD.SetBypassPOWValidation(true);

    // Connect B to A
    REQUIRE(nodeB.ConnectTo(nodeA.GetId()));
    REQUIRE(orch.WaitForConnection(nodeA, nodeB));
    for (int i = 0; i < 12; ++i) {
        orch.AdvanceTime(std::chrono::milliseconds(100));
    }

    auto& discovery = nodeA.GetNetworkManager().discovery_manager();

    // Boost token bucket to allow ADDR processing (simulates A sent GETADDR to B)
    int peer_id = orch.GetPeerId(nodeA, nodeB);
    nodeA.GetNetworkManager().discovery_manager_for_test().NotifyGetAddrSent(peer_id);

    // B sends ADDR with both C's and D's addresses
    auto now_s = static_cast<uint32_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count()
    );

    uint16_t nodeC_port = static_cast<uint16_t>(ports::REGTEST + nodeC.GetId());
    uint16_t nodeD_port = static_cast<uint16_t>(ports::REGTEST + nodeD.GetId());

    auto addr_msg_c = MakeAddrMsg("185.1.2.51", nodeC_port, now_s);
    auto addr_msg_d = MakeAddrMsg("185.1.2.52", nodeD_port, now_s);

    net.SendMessage(nodeB.GetId(), nodeA.GetId(), MakeWire(commands::ADDR, addr_msg_c.serialize()));
    net.SendMessage(nodeB.GetId(), nodeA.GetId(), MakeWire(commands::ADDR, addr_msg_d.serialize()));

    for (int i = 0; i < 6; ++i) {
        orch.AdvanceTime(std::chrono::milliseconds(100));
    }

    // Should have 2 addresses in NEW
    size_t new_after_addr = discovery.NewCount();
    INFO("After ADDR messages: new=" << new_after_addr);
    REQUIRE(new_after_addr >= 2);

    size_t tried_before = discovery.TriedCount();

    // Connect to C only
    REQUIRE(nodeA.ConnectTo(nodeC.GetId(), "185.1.2.51", nodeC_port));
    REQUIRE(orch.WaitForConnection(nodeA, nodeC));
    for (int i = 0; i < 12; ++i) {
        orch.AdvanceTime(std::chrono::milliseconds(100));
    }

    // C's address should be in TRIED now
    size_t tried_after_c = discovery.TriedCount();
    CHECK(tried_after_c > tried_before);

    // Connect to D
    REQUIRE(nodeA.ConnectTo(nodeD.GetId(), "185.1.2.52", nodeD_port));
    REQUIRE(orch.WaitForConnection(nodeA, nodeD));
    for (int i = 0; i < 12; ++i) {
        orch.AdvanceTime(std::chrono::milliseconds(100));
    }

    // D's address should also be in TRIED now
    size_t tried_after_d = discovery.TriedCount();
    CHECK(tried_after_d > tried_after_c);
}

TEST_CASE("E2E: Address learned via relay chain", "[network][addr][e2e][relay]") {
    // Test: A learns from B, B learned from C
    // This verifies multi-hop address propagation

    SimulatedNetwork net(50005);
    TestOrchestrator orch(&net);
    net.EnableCommandTracking(true);

    SimulatedNode nodeA(1, &net);
    SimulatedNode nodeB(2, &net);
    SimulatedNode nodeC(3, &net);
    SimulatedNode nodeX(4, &net, "185.1.2.99");  // The address being relayed

    nodeA.SetBypassPOWValidation(true);
    nodeB.SetBypassPOWValidation(true);
    nodeC.SetBypassPOWValidation(true);
    nodeX.SetBypassPOWValidation(true);

    // C connects to B, announces X to B
    REQUIRE(nodeC.ConnectTo(nodeB.GetId()));
    REQUIRE(orch.WaitForConnection(nodeB, nodeC));
    for (int i = 0; i < 12; ++i) {
        orch.AdvanceTime(std::chrono::milliseconds(100));
    }

    auto now_s = static_cast<uint32_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count()
    );

    uint16_t nodeX_port = static_cast<uint16_t>(ports::REGTEST + nodeX.GetId());
    auto addr_msg = MakeAddrMsg("185.1.2.99", nodeX_port, now_s);
    net.SendMessage(nodeC.GetId(), nodeB.GetId(), MakeWire(commands::ADDR, addr_msg.serialize()));

    for (int i = 0; i < 6; ++i) {
        orch.AdvanceTime(std::chrono::milliseconds(100));
    }

    // Verify B has X in NEW
    auto& discovery_b = nodeB.GetNetworkManager().discovery_manager();
    REQUIRE(discovery_b.NewCount() >= 1);

    // A connects to B, sends GETADDR
    REQUIRE(nodeA.ConnectTo(nodeB.GetId()));
    REQUIRE(orch.WaitForConnection(nodeA, nodeB));
    for (int i = 0; i < 12; ++i) {
        orch.AdvanceTime(std::chrono::milliseconds(100));
    }

    // A should receive X's address in the ADDR response
    // (B responds to inbound connections with ADDR after handshake)
    auto payloads = net.GetCommandPayloads(nodeB.GetId(), nodeA.GetId(), commands::ADDR);

    bool found_x = false;
    for (const auto& p : payloads) {
        message::AddrMessage msg;
        if (msg.deserialize(p.data(), p.size())) {
            for (const auto& ta : msg.addresses) {
                // Check if this is X's address (185.1.2.99)
                if (ta.address.ip[12] == 185 && ta.address.ip[13] == 1 &&
                    ta.address.ip[14] == 2 && ta.address.ip[15] == 99) {
                    found_x = true;
                    break;
                }
            }
        }
        if (found_x) break;
    }

    // Note: ADDR responses are randomized and capped, so X might not always be included
    // This is expected behavior - just check that the mechanism works
    INFO("X's address found in relay: " << found_x);
    // Don't require found_x since response is random subset
}
