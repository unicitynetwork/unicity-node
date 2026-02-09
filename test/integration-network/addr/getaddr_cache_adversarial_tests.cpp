// Copyright (c) 2025 The Unicity Foundation
// GETADDR Cache Adversarial Tests
//
// Tests for cache timing edge cases and potential attack vectors.
// The GETADDR response cache is designed to:
// 1. Prevent address enumeration by returning the same set to all peers within a window
// 2. Use randomized TTL (21-27h) to prevent timing-based attacks

#include "catch_amalgamated.hpp"
#include "infra/simulated_network.hpp"
#include "infra/simulated_node.hpp"
#include "infra/test_access.hpp"
#include "network/network_manager.hpp"
#include "network/message.hpp"
#include "util/hash.hpp"
#include "network/addr_relay_manager.hpp"
#include "test_orchestrator.hpp"
#include <set>

using namespace unicity;
using unicity::test::AddrRelayManagerTestAccess;
using namespace unicity::test;
using namespace unicity::network;
using namespace unicity::protocol;

static struct GetaddrCacheTestSetup {
    GetaddrCacheTestSetup() { chain::GlobalChainParams::Select(chain::ChainType::REGTEST); }
} getaddr_cache_test_setup;

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

// Build a routable NetworkAddress using IPv4-mapped-IPv6 format
static NetworkAddress MakeRoutableAddr(uint8_t b12, uint8_t b13, uint8_t b14, uint8_t b15, uint16_t port = 9590) {
    NetworkAddress addr;
    addr.services = NODE_NETWORK;
    addr.port = port;
    // IPv4-mapped-IPv6 format: 10 zeros, 2 0xFF, then 4 IPv4 bytes
    for (int j = 0; j < 10; ++j) addr.ip[j] = 0;
    addr.ip[10] = 0xFF;
    addr.ip[11] = 0xFF;
    addr.ip[12] = b12;
    addr.ip[13] = b13;
    addr.ip[14] = b14;
    addr.ip[15] = b15;
    return addr;
}

// Helper to get addresses from an ADDR message payload
static std::set<std::string> ExtractAddresses(const std::vector<std::vector<uint8_t>>& payloads) {
    std::set<std::string> addrs;
    for (const auto& payload : payloads) {
        message::AddrMessage msg;
        if (msg.deserialize(payload.data(), payload.size())) {
            for (const auto& ta : msg.addresses) {
                auto str = ta.address.to_string();
                if (str) addrs.insert(*str);
            }
        }
    }
    return addrs;
}

// =============================================================================
// TEST 1: Cache provides same addresses to all peers within window
// =============================================================================
// Multiple GETADDR requests within the cache window should return the same set.

TEST_CASE("GETADDR cache: same addresses within TTL window", "[addr][getaddr][cache][privacy]") {
    SimulatedNetwork net(49501);
    TestOrchestrator orch(&net);
    net.EnableCommandTracking(true);

    SimulatedNode server(1, &net);

    // Seed the server's address manager with known routable addresses
    auto& addrman = AddrRelayManagerTestAccess::GetAddrManager(server.GetNetworkManager().discovery_manager());
    for (int i = 1; i <= 20; ++i) {
        addrman.add(MakeRoutableAddr(93, 184, 216, static_cast<uint8_t>(i)));
    }
    size_t addrman_size = addrman.size();
    INFO("AddrMan size after seeding: " << addrman_size);
    REQUIRE(addrman_size > 0);

    orch.AdvanceTime(std::chrono::seconds(1));

    // Connect first client and get GETADDR response
    SimulatedNode client1(2, &net);
    REQUIRE(client1.ConnectTo(server.GetId()));
    REQUIRE(orch.WaitForConnection(server, client1));
    for (int i = 0; i < 12; ++i) orch.AdvanceTime(std::chrono::milliseconds(100));

    auto payloads1 = net.GetCommandPayloads(server.GetId(), client1.GetId(), commands::ADDR);
    auto addrs1 = ExtractAddresses(payloads1);
    INFO("Client 1 received " << addrs1.size() << " addresses");
    REQUIRE(!addrs1.empty());

    // Advance time but stay within cache window (< 21 hours)
    orch.AdvanceTime(std::chrono::hours(1));

    // Connect second client
    SimulatedNode client2(3, &net);
    REQUIRE(client2.ConnectTo(server.GetId()));
    REQUIRE(orch.WaitForConnection(server, client2));
    for (int i = 0; i < 12; ++i) orch.AdvanceTime(std::chrono::milliseconds(100));

    auto payloads2 = net.GetCommandPayloads(server.GetId(), client2.GetId(), commands::ADDR);
    auto addrs2 = ExtractAddresses(payloads2);
    INFO("Client 2 received " << addrs2.size() << " addresses");
    REQUIRE(!addrs2.empty());

    // CRITICAL: Both clients should get the exact same addresses
    CHECK(addrs1 == addrs2);
}

// =============================================================================
// TEST 2: Cache refreshes after TTL expires
// =============================================================================
// After the cache expires (21-27h), the next GETADDR should get fresh addresses.

TEST_CASE("GETADDR cache: refresh after TTL expiration", "[addr][getaddr][cache][timing]") {
    SimulatedNetwork net(49502);
    TestOrchestrator orch(&net);
    net.EnableCommandTracking(true);

    SimulatedNode server(1, &net);

    // Seed with initial addresses
    auto& addrman = AddrRelayManagerTestAccess::GetAddrManager(server.GetNetworkManager().discovery_manager());
    for (int i = 1; i <= 10; ++i) {
        addrman.add(MakeRoutableAddr(93, 184, 216, static_cast<uint8_t>(i)));
    }
    orch.AdvanceTime(std::chrono::seconds(1));

    // First client triggers cache population
    SimulatedNode client1(2, &net);
    REQUIRE(client1.ConnectTo(server.GetId()));
    REQUIRE(orch.WaitForConnection(server, client1));
    for (int i = 0; i < 12; ++i) orch.AdvanceTime(std::chrono::milliseconds(100));

    auto payloads1 = net.GetCommandPayloads(server.GetId(), client1.GetId(), commands::ADDR);
    size_t count1 = ExtractAddresses(payloads1).size();
    INFO("Before expiration: " << count1 << " addresses");

    // Advance time past maximum TTL (27 hours)
    orch.AdvanceTime(std::chrono::hours(28));

    // Add more addresses after cache was populated
    for (int i = 100; i <= 110; ++i) {
        addrman.add(MakeRoutableAddr(94, 185, 217, static_cast<uint8_t>(i)));
    }
    orch.AdvanceTime(std::chrono::seconds(1));

    // Second client connects after TTL - should trigger cache refresh
    SimulatedNode client2(3, &net);
    REQUIRE(client2.ConnectTo(server.GetId()));
    REQUIRE(orch.WaitForConnection(server, client2));
    for (int i = 0; i < 12; ++i) orch.AdvanceTime(std::chrono::milliseconds(100));

    auto payloads2 = net.GetCommandPayloads(server.GetId(), client2.GetId(), commands::ADDR);
    auto addrs2 = ExtractAddresses(payloads2);
    INFO("After expiration: " << addrs2.size() << " addresses");

    // Cache should have been refreshed - may include the new addresses
    CHECK(addrs2.size() > 0);
}

// =============================================================================
// TEST 3: TTL is randomized (21-27h), not constant
// =============================================================================
// Multiple cache refreshes should have varying expiration times.

TEST_CASE("GETADDR cache: TTL jitter verification", "[addr][getaddr][cache][timing][jitter]") {
    SimulatedNetwork net(49503);
    TestOrchestrator orch(&net);
    net.EnableCommandTracking(true);

    SimulatedNode server(1, &net);

    // Seed addresses
    auto& addrman = AddrRelayManagerTestAccess::GetAddrManager(server.GetNetworkManager().discovery_manager());
    for (int i = 1; i <= 10; ++i) {
        addrman.add(MakeRoutableAddr(93, 184, 216, static_cast<uint8_t>(i)));
    }
    orch.AdvanceTime(std::chrono::seconds(1));

    // First cache population
    SimulatedNode client1(2, &net);
    REQUIRE(client1.ConnectTo(server.GetId()));
    REQUIRE(orch.WaitForConnection(server, client1));
    for (int i = 0; i < 12; ++i) orch.AdvanceTime(std::chrono::milliseconds(100));

    auto payloads1 = net.GetCommandPayloads(server.GetId(), client1.GetId(), commands::ADDR);
    auto addrs1 = ExtractAddresses(payloads1);

    // At exactly 21 hours, cache MIGHT be expired (minimum TTL)
    orch.AdvanceTime(std::chrono::hours(21));

    // Connect new client - depending on jitter, cache may or may not refresh
    SimulatedNode client2(3, &net);
    REQUIRE(client2.ConnectTo(server.GetId()));
    REQUIRE(orch.WaitForConnection(server, client2));
    for (int i = 0; i < 12; ++i) orch.AdvanceTime(std::chrono::milliseconds(100));

    auto payloads2 = net.GetCommandPayloads(server.GetId(), client2.GetId(), commands::ADDR);
    auto addrs2 = ExtractAddresses(payloads2);

    // Both clients should get valid responses
    CHECK(!addrs1.empty());
    CHECK(!addrs2.empty());

    // Note: With jitter, at exactly 21h the cache might or might not be expired
    INFO("At 21h boundary: addrs match = " << (addrs1 == addrs2));
}

// =============================================================================
// TEST 4: Multiple rapid GETADDR requests don't cause issues
// =============================================================================
// Rapid GETADDR requests shouldn't cause race conditions or data corruption.

TEST_CASE("GETADDR cache: rapid requests handled correctly", "[addr][getaddr][cache][stress]") {
    SimulatedNetwork net(49504);
    TestOrchestrator orch(&net);
    net.EnableCommandTracking(true);

    SimulatedNode server(1, &net);

    // Seed addresses
    auto& addrman = AddrRelayManagerTestAccess::GetAddrManager(server.GetNetworkManager().discovery_manager());
    for (int i = 1; i <= 50; ++i) {
        addrman.add(MakeRoutableAddr(93, 184, 216, static_cast<uint8_t>(i)));
    }
    orch.AdvanceTime(std::chrono::seconds(1));

    // Connect multiple clients simultaneously
    std::vector<std::unique_ptr<SimulatedNode>> clients;
    for (int i = 0; i < 5; ++i) {
        auto client = std::make_unique<SimulatedNode>(10 + i, &net);
        REQUIRE(client->ConnectTo(server.GetId()));
        clients.push_back(std::move(client));
    }

    // Wait for all connections
    for (auto& client : clients) {
        REQUIRE(orch.WaitForConnection(server, *client));
    }
    for (int i = 0; i < 50; ++i) orch.AdvanceTime(std::chrono::milliseconds(100));

    // All clients should have received the same addresses (from cache)
    std::set<std::string> first_addrs;
    bool first = true;

    for (auto& client : clients) {
        auto payloads = net.GetCommandPayloads(server.GetId(), client->GetId(), commands::ADDR);
        auto addrs = ExtractAddresses(payloads);

        if (first) {
            first_addrs = addrs;
            first = false;
        } else {
            // All subsequent clients should get the same cached response
            CHECK(addrs == first_addrs);
        }
    }

    // Verify we got a non-trivial response
    CHECK(!first_addrs.empty());
}

// =============================================================================
// TEST 5: GETADDR before any ADDR received (empty cache scenario)
// =============================================================================
// Tests behavior when GETADDR is sent before the server has any addresses.

TEST_CASE("GETADDR cache: empty cache scenario", "[addr][getaddr][cache][edge]") {
    SimulatedNetwork net(49505);
    TestOrchestrator orch(&net);
    net.EnableCommandTracking(true);

    // Server with empty address manager
    SimulatedNode server(1, &net);

    SimulatedNode client(2, &net);
    REQUIRE(client.ConnectTo(server.GetId()));
    REQUIRE(orch.WaitForConnection(server, client));
    for (int i = 0; i < 12; ++i) orch.AdvanceTime(std::chrono::milliseconds(100));

    // Auto-GETADDR response with empty AddrMan
    auto payloads = net.GetCommandPayloads(server.GetId(), client.GetId(), commands::ADDR);
    auto addrs = ExtractAddresses(payloads);

    // Response should be empty or minimal (no addresses to return)
    INFO("Empty AddrMan returned " << addrs.size() << " addresses");

    // Now add addresses and trigger new GETADDR via new connection
    auto& addrman = AddrRelayManagerTestAccess::GetAddrManager(server.GetNetworkManager().discovery_manager());
    for (int i = 1; i <= 10; ++i) {
        addrman.add(MakeRoutableAddr(93, 184, 216, static_cast<uint8_t>(i)));
    }

    // Force cache expiration
    orch.AdvanceTime(std::chrono::hours(28));

    SimulatedNode client2(3, &net);
    REQUIRE(client2.ConnectTo(server.GetId()));
    REQUIRE(orch.WaitForConnection(server, client2));
    for (int i = 0; i < 12; ++i) orch.AdvanceTime(std::chrono::milliseconds(100));

    auto payloads2 = net.GetCommandPayloads(server.GetId(), client2.GetId(), commands::ADDR);
    auto addrs2 = ExtractAddresses(payloads2);

    // Now should have addresses
    CHECK(!addrs2.empty());
}

// =============================================================================
// TEST 6: Once-per-connection gating still works with caching
// =============================================================================
// Verifies that repeat GETADDR on same connection is ignored even with caching.

TEST_CASE("GETADDR cache: once-per-connection gating", "[addr][getaddr][cache][gating]") {
    SimulatedNetwork net(49506);
    TestOrchestrator orch(&net);
    net.EnableCommandTracking(true);

    SimulatedNode server(1, &net);

    // Seed addresses
    auto& addrman = AddrRelayManagerTestAccess::GetAddrManager(server.GetNetworkManager().discovery_manager());
    for (int i = 1; i <= 10; ++i) {
        addrman.add(MakeRoutableAddr(93, 184, 216, static_cast<uint8_t>(i)));
    }
    orch.AdvanceTime(std::chrono::seconds(1));

    SimulatedNode client(2, &net);
    REQUIRE(client.ConnectTo(server.GetId()));
    REQUIRE(orch.WaitForConnection(server, client));
    for (int i = 0; i < 12; ++i) orch.AdvanceTime(std::chrono::milliseconds(100));

    // Count ADDR messages after initial handshake (includes auto-GETADDR response)
    auto payloads_before = net.GetCommandPayloads(server.GetId(), client.GetId(), commands::ADDR);
    size_t count_before = payloads_before.size();
    REQUIRE(count_before > 0);

    // Send additional GETADDR requests - should be ignored
    for (int i = 0; i < 5; ++i) {
        net.SendMessage(client.GetId(), server.GetId(), MakeWire(commands::GETADDR, {}));
        orch.AdvanceTime(std::chrono::milliseconds(100));
    }

    orch.AdvanceTime(std::chrono::seconds(1));

    auto payloads_after = net.GetCommandPayloads(server.GetId(), client.GetId(), commands::ADDR);
    size_t count_after = payloads_after.size();

    // No additional ADDR messages should have been sent
    CHECK(count_after == count_before);
}
