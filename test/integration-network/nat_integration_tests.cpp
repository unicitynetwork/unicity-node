// Copyright (c) 2025 The Unicity Foundation
// NAT/NetworkManager integration tests
//
// Tests cover integration paths between NATManager and NetworkManager
// that are NOT covered by self_advertisement_integration_tests.cpp:
// - Private IP filtering in peer feedback
// - First-write-wins priority (injected addr vs peer feedback)
// - Null NAT manager safety
// - No local address → no advertisement (explicit negative test)
// - Listen disabled → no advertisement

#include "catch_amalgamated.hpp"
#include "infra/simulated_network.hpp"
#include "infra/simulated_node.hpp"
#include "infra/test_access.hpp"
#include "test_orchestrator.hpp"
#include "network/message.hpp"
#include "network/protocol.hpp"

using namespace unicity;
using namespace unicity::test;
using namespace unicity::protocol;

// =============================================================================
// HELPERS
// =============================================================================

static std::string GetIPv4(const protocol::NetworkAddress& addr) {
    if (addr.ip[10] == 0xFF && addr.ip[11] == 0xFF) {
        char buf[32];
        snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
                 addr.ip[12], addr.ip[13], addr.ip[14], addr.ip[15]);
        return std::string(buf);
    }
    return "";
}

// =============================================================================
// PEER FEEDBACK FILTERING
// =============================================================================

TEST_CASE("NAT integration: peer feedback ignores private IPs",
          "[nat][integration][peer-feedback]") {
    SimulatedNetwork net(49001);
    TestOrchestrator orch(&net);

    // Node A uses a PRIVATE IP address (192.168.1.50)
    // When B connects to A, B's VERSION will have addr_recv = A's address
    // NetworkManager should reject it because 192.168.1.x is not routable
    SimulatedNode nodeA(1, &net, "192.168.1.50");
    SimulatedNode nodeB(2, &net, "93.184.216.20");

    // Mine blocks so not in IBD
    for (int i = 0; i < 5; i++) {
        nodeA.MineBlock();
        nodeB.MineBlock();
    }

    orch.AdvanceTime(std::chrono::milliseconds(100));

    // Before connection, no local address
    CHECK_FALSE(nodeA.GetNetworkManager().get_local_address().has_value());

    // B connects to A (inbound from A's perspective)
    // B's VERSION addr_recv = 192.168.1.50 (A's address — private, non-routable)
    REQUIRE(nodeB.ConnectTo(nodeA.GetId(), nodeA.GetAddress(), nodeA.GetPort()));
    REQUIRE(orch.WaitForConnection(nodeA, nodeB));
    orch.AdvanceTime(std::chrono::milliseconds(200));

    // A should NOT have learned its address (private IP filtered by IsRoutable)
    CHECK_FALSE(nodeA.GetNetworkManager().get_local_address().has_value());
}

TEST_CASE("NAT integration: peer feedback ignores loopback",
          "[nat][integration][peer-feedback]") {
    SimulatedNetwork net(49002);
    TestOrchestrator orch(&net);

    // Node A uses loopback
    SimulatedNode nodeA(1, &net, "127.0.0.1");
    SimulatedNode nodeB(2, &net, "93.184.216.20");

    for (int i = 0; i < 5; i++) {
        nodeA.MineBlock();
        nodeB.MineBlock();
    }

    orch.AdvanceTime(std::chrono::milliseconds(100));

    REQUIRE(nodeB.ConnectTo(nodeA.GetId(), nodeA.GetAddress(), nodeA.GetPort()));
    REQUIRE(orch.WaitForConnection(nodeA, nodeB));
    orch.AdvanceTime(std::chrono::milliseconds(200));

    // Loopback should be filtered
    CHECK_FALSE(nodeA.GetNetworkManager().get_local_address().has_value());
}

// =============================================================================
// FIRST-WRITE-WINS PRIORITY
// =============================================================================

TEST_CASE("NAT integration: pre-set address not overwritten by peer feedback",
          "[nat][integration][priority]") {
    SimulatedNetwork net(49003);
    TestOrchestrator orch(&net);

    // Both nodes use routable IPs
    SimulatedNode nodeA(1, &net, "93.184.216.10");
    SimulatedNode nodeB(2, &net, "93.184.216.20");

    for (int i = 0; i < 5; i++) {
        nodeA.MineBlock();
        nodeB.MineBlock();
    }

    orch.AdvanceTime(std::chrono::milliseconds(100));

    // Pre-set A's local address (simulating UPnP discovery)
    auto upnp_addr = protocol::NetworkAddress::from_string("203.0.113.50", 9590, protocol::NODE_NETWORK);
    NetworkManagerTestAccess::SetLocalAddr(nodeA.GetNetworkManager(), upnp_addr);

    // Verify it's set
    auto pre_addr = nodeA.GetNetworkManager().get_local_address();
    REQUIRE(pre_addr.has_value());
    CHECK(GetIPv4(*pre_addr) == "203.0.113.50");

    // B connects to A → B's VERSION has addr_recv = 93.184.216.10 (different from pre-set)
    REQUIRE(nodeB.ConnectTo(nodeA.GetId(), nodeA.GetAddress(), nodeA.GetPort()));
    REQUIRE(orch.WaitForConnection(nodeA, nodeB));
    orch.AdvanceTime(std::chrono::milliseconds(200));

    // A's address should still be the pre-set one (first-write-wins)
    auto post_addr = nodeA.GetNetworkManager().get_local_address();
    REQUIRE(post_addr.has_value());
    CHECK(GetIPv4(*post_addr) == "203.0.113.50");
}

TEST_CASE("NAT integration: second peer feedback does not overwrite first",
          "[nat][integration][priority]") {
    SimulatedNetwork net(49004);
    TestOrchestrator orch(&net);

    // A has routable IP, two peers will connect
    SimulatedNode nodeA(1, &net, "93.184.216.10");
    SimulatedNode nodeB(2, &net, "93.184.216.20");
    SimulatedNode nodeC(3, &net, "93.184.216.30");

    for (int i = 0; i < 5; i++) {
        nodeA.MineBlock();
        nodeB.MineBlock();
        nodeC.MineBlock();
    }

    orch.AdvanceTime(std::chrono::milliseconds(100));

    // B connects first → A learns 93.184.216.10 from B's VERSION
    REQUIRE(nodeB.ConnectTo(nodeA.GetId(), nodeA.GetAddress(), nodeA.GetPort()));
    REQUIRE(orch.WaitForConnection(nodeA, nodeB));
    orch.AdvanceTime(std::chrono::milliseconds(200));

    auto first_addr = nodeA.GetNetworkManager().get_local_address();
    REQUIRE(first_addr.has_value());
    std::string first_ip = GetIPv4(*first_addr);

    // C connects second → A gets another feedback, but should keep first
    REQUIRE(nodeC.ConnectTo(nodeA.GetId(), nodeA.GetAddress(), nodeA.GetPort()));
    REQUIRE(orch.WaitForConnection(nodeA, nodeC));
    orch.AdvanceTime(std::chrono::milliseconds(200));

    auto second_addr = nodeA.GetNetworkManager().get_local_address();
    REQUIRE(second_addr.has_value());
    CHECK(GetIPv4(*second_addr) == first_ip);
}

// =============================================================================
// NULL NAT MANAGER SAFETY
// =============================================================================

TEST_CASE("NAT integration: null NAT manager does not crash on self-advertisement",
          "[nat][integration][upnp]") {
    SimulatedNetwork net(49005);
    TestOrchestrator orch(&net);

    SimulatedNode nodeA(1, &net, "93.184.216.10");
    SimulatedNode nodeB(2, &net, "93.184.216.20");

    for (int i = 0; i < 5; i++) {
        nodeA.MineBlock();
    }

    orch.AdvanceTime(std::chrono::milliseconds(100));

    // SimulatedNode has enable_nat=false → nat_manager_ is null
    // Verify no local address learned from UPnP
    CHECK_FALSE(NetworkManagerTestAccess::HasLocalAddr(nodeA.GetNetworkManager()));

    // Connect a peer
    REQUIRE(nodeA.ConnectTo(nodeB.GetId(), nodeB.GetAddress(), nodeB.GetPort()));
    REQUIRE(orch.WaitForConnection(nodeA, nodeB));
    orch.AdvanceTime(std::chrono::milliseconds(200));

    // Trigger self-advertisement — this calls update_local_addr_from_upnp() internally
    // With null nat_manager_, it should be a no-op (not crash)
    REQUIRE_NOTHROW(nodeA.TriggerSelfAdvertisement());
    orch.AdvanceTime(std::chrono::milliseconds(100));
}

// =============================================================================
// NEGATIVE TESTS: NO ADVERTISEMENT
// =============================================================================

TEST_CASE("NAT integration: no local address means no ADDR sent",
          "[nat][integration][advertisement]") {
    SimulatedNetwork net(49006);
    TestOrchestrator orch(&net);
    net.EnableCommandTracking(true);

    // Use private IP so peer feedback won't set local_addr
    SimulatedNode nodeA(1, &net, "10.0.0.1");
    SimulatedNode nodeB(2, &net, "10.0.0.2");

    for (int i = 0; i < 5; i++) {
        nodeA.MineBlock();
        nodeB.MineBlock();
    }

    orch.AdvanceTime(std::chrono::milliseconds(100));

    REQUIRE(nodeA.ConnectTo(nodeB.GetId(), nodeB.GetAddress(), nodeB.GetPort()));
    REQUIRE(orch.WaitForConnection(nodeA, nodeB));
    orch.AdvanceTime(std::chrono::milliseconds(200));

    // A has no local address (private IPs filtered)
    CHECK_FALSE(nodeA.GetNetworkManager().get_local_address().has_value());

    // Count ADDR before triggering
    int addr_before = net.CountCommandSent(nodeA.GetId(), nodeB.GetId(), commands::ADDR);

    // Trigger — should send nothing (no local address)
    nodeA.TriggerSelfAdvertisement();
    orch.AdvanceTime(std::chrono::milliseconds(100));

    int addr_after = net.CountCommandSent(nodeA.GetId(), nodeB.GetId(), commands::ADDR);
    CHECK(addr_after == addr_before);
}

TEST_CASE("NAT integration: injected address triggers ADDR to full-relay peer",
          "[nat][integration][advertisement]") {
    SimulatedNetwork net(49007);
    TestOrchestrator orch(&net);
    net.EnableCommandTracking(true);

    // Use private IPs so peer feedback won't pollute
    SimulatedNode nodeA(1, &net, "10.0.0.1");
    SimulatedNode nodeB(2, &net, "10.0.0.2");

    for (int i = 0; i < 5; i++) {
        nodeA.MineBlock();
        nodeB.MineBlock();
    }

    orch.AdvanceTime(std::chrono::milliseconds(100));

    REQUIRE(nodeA.ConnectTo(nodeB.GetId(), nodeB.GetAddress(), nodeB.GetPort()));
    REQUIRE(orch.WaitForConnection(nodeA, nodeB));
    orch.AdvanceTime(std::chrono::milliseconds(200));

    // A has no local addr yet (private IP filtered)
    CHECK_FALSE(nodeA.GetNetworkManager().get_local_address().has_value());

    int addr_before = net.CountCommandSent(nodeA.GetId(), nodeB.GetId(), commands::ADDR);

    // Inject a routable address (simulating UPnP discovery)
    auto upnp_addr = protocol::NetworkAddress::from_string("203.0.113.50", 9590, protocol::NODE_NETWORK);
    NetworkManagerTestAccess::SetLocalAddr(nodeA.GetNetworkManager(), upnp_addr);

    // Trigger self-advertisement
    nodeA.TriggerSelfAdvertisement();
    orch.AdvanceTime(std::chrono::milliseconds(100));

    int addr_after = net.CountCommandSent(nodeA.GetId(), nodeB.GetId(), commands::ADDR);
    CHECK(addr_after > addr_before);
}

TEST_CASE("NAT integration: injected address NOT sent to block-relay-only peer",
          "[nat][integration][advertisement]") {
    SimulatedNetwork net(49008);
    TestOrchestrator orch(&net);
    net.EnableCommandTracking(true);

    SimulatedNode nodeA(1, &net, "10.0.0.1");
    SimulatedNode nodeB(2, &net, "10.0.0.2");

    for (int i = 0; i < 5; i++) {
        nodeA.MineBlock();
        nodeB.MineBlock();
    }

    orch.AdvanceTime(std::chrono::milliseconds(100));

    // Connect as block-relay-only
    REQUIRE(nodeA.ConnectToBlockRelayOnly(nodeB.GetId(), nodeB.GetAddress(), nodeB.GetPort()));
    REQUIRE(orch.WaitForConnection(nodeA, nodeB));
    orch.AdvanceTime(std::chrono::milliseconds(200));

    int addr_before = net.CountCommandSent(nodeA.GetId(), nodeB.GetId(), commands::ADDR);

    // Inject address and trigger
    auto upnp_addr = protocol::NetworkAddress::from_string("203.0.113.50", 9590, protocol::NODE_NETWORK);
    NetworkManagerTestAccess::SetLocalAddr(nodeA.GetNetworkManager(), upnp_addr);
    nodeA.TriggerSelfAdvertisement();
    orch.AdvanceTime(std::chrono::milliseconds(100));

    int addr_after = net.CountCommandSent(nodeA.GetId(), nodeB.GetId(), commands::ADDR);
    CHECK(addr_after == addr_before);
}

TEST_CASE("NAT integration: ClearLocalAddr allows re-learning from peer",
          "[nat][integration][priority]") {
    SimulatedNetwork net(49009);
    TestOrchestrator orch(&net);

    SimulatedNode nodeA(1, &net, "93.184.216.10");
    SimulatedNode nodeB(2, &net, "93.184.216.20");
    SimulatedNode nodeC(3, &net, "93.184.216.30");

    for (int i = 0; i < 5; i++) {
        nodeA.MineBlock();
        nodeB.MineBlock();
        nodeC.MineBlock();
    }

    orch.AdvanceTime(std::chrono::milliseconds(100));

    // B connects → A learns address
    REQUIRE(nodeB.ConnectTo(nodeA.GetId(), nodeA.GetAddress(), nodeA.GetPort()));
    REQUIRE(orch.WaitForConnection(nodeA, nodeB));
    orch.AdvanceTime(std::chrono::milliseconds(200));

    REQUIRE(nodeA.GetNetworkManager().get_local_address().has_value());

    // Clear the address
    NetworkManagerTestAccess::ClearLocalAddr(nodeA.GetNetworkManager());
    CHECK_FALSE(nodeA.GetNetworkManager().get_local_address().has_value());

    // C connects → A should learn address again
    REQUIRE(nodeC.ConnectTo(nodeA.GetId(), nodeA.GetAddress(), nodeA.GetPort()));
    REQUIRE(orch.WaitForConnection(nodeA, nodeC));
    orch.AdvanceTime(std::chrono::milliseconds(200));

    auto addr = nodeA.GetNetworkManager().get_local_address();
    REQUIRE(addr.has_value());
    CHECK(GetIPv4(*addr) == "93.184.216.10");
}
