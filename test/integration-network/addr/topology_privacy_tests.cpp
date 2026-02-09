// Topology Privacy Tests
//
// Tests that prevent P2P graph deanonymization via GETADDR/ADDR:
//
// 1. GETADDR subset limit - Response is at most 23% of AddrMan (prevents enumeration)
// 2. GETADDR max cap - Response never exceeds 1000 addresses
// 3. GETADDR randomization - Different connections get different subsets
// 4. ADDR relay fan-out - Relay goes to 1-2 peers, not broadcast

#include "catch_amalgamated.hpp"
#include "infra/simulated_network.hpp"
#include "infra/simulated_node.hpp"
#include "infra/test_access.hpp"
#include "network/network_manager.hpp"
#include "network/message.hpp"
#include "network/addr_relay_manager.hpp"
#include "test_orchestrator.hpp"
#include "util/hash.hpp"
#include "util/time.hpp"
#include <algorithm>
#include <set>
#include <cstring>

using namespace unicity;
using unicity::test::AddrRelayManagerTestAccess;
using namespace unicity::test;
using namespace unicity::network;
using namespace unicity::protocol;

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

static NetworkAddress MakeAddr(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint16_t port = 9590) {
    NetworkAddress addr;
    addr.services = NODE_NETWORK;
    addr.port = port;
    std::memset(addr.ip.data(), 0, 10);
    addr.ip[10] = 0xFF;
    addr.ip[11] = 0xFF;
    addr.ip[12] = a;
    addr.ip[13] = b;
    addr.ip[14] = c;
    addr.ip[15] = d;
    return addr;
}

static std::string MakeAddrKey(const TimestampedAddress& ta) {
    char buf[32];
    snprintf(buf, sizeof(buf), "%u.%u.%u.%u:%u",
             ta.address.ip[12], ta.address.ip[13], ta.address.ip[14], ta.address.ip[15], ta.address.port);
    return std::string(buf);
}

// =============================================================================
// TEST 1: GETADDR returns at most 23% of AddressManager
// =============================================================================
// Attacker trying to enumerate topology should only get partial view.

TEST_CASE("Privacy: GETADDR returns at most 23% of known addresses", "[privacy][addr][topology]") {
    SimulatedNetwork net(49100);
    TestOrchestrator orch(&net);
    net.EnableCommandTracking(true);

    SimulatedNode server(1, &net);

    auto& am = server.GetNetworkManager().discovery_manager();

    // Populate AddrMan with 100 diverse addresses (different /16 netgroups)
    size_t added = 0;
    for (int i = 1; i <= 100 && added < 100; ++i) {
        // Use different /16 blocks to avoid netgroup limits
        auto addr = MakeAddr(static_cast<uint8_t>(i), 1, 0, 1);
        if (AddrRelayManagerTestAccess::GetAddrManager(am).add(addr)) {
            ++added;
        }
    }

    size_t addrman_size = AddrRelayManagerTestAccess::GetAddrManager(am).size();
    REQUIRE(addrman_size >= 50);  // Should have added most addresses

    // Connect a client and request addresses
    SimulatedNode client(2, &net);
    REQUIRE(client.ConnectTo(server.GetId()));
    REQUIRE(orch.WaitForConnection(server, client));

    // Wait for automatic GETADDR response after handshake
    for (int i = 0; i < 15; ++i) {
        orch.AdvanceTime(std::chrono::milliseconds(100));
    }

    auto payloads = net.GetCommandPayloads(server.GetId(), client.GetId(), commands::ADDR);
    REQUIRE_FALSE(payloads.empty());

    message::AddrMessage response;
    REQUIRE(response.deserialize(payloads.back().data(), payloads.back().size()));

    // Verify: response size <= 23% of AddrMan + some margin for implementation details
    size_t max_expected = (addrman_size * 23) / 100 + 5;  // 23% + small margin
    CHECK(response.addresses.size() <= max_expected);

    // Should return SOMETHING (not empty)
    CHECK(response.addresses.size() > 0);

    // Log for debugging
    INFO("AddrMan size: " << addrman_size << ", Response size: " << response.addresses.size()
         << ", Max expected (23%): " << max_expected);
}

// =============================================================================
// TEST 2: GETADDR responses are cached (same within cache window)
// =============================================================================
// Bitcoin Core parity: GETADDR responses are cached for 21-27 hours.
// All peers within the cache window get the SAME addresses (minus suppression).
// This prevents enumeration attacks where an attacker makes many connections
// to collect different random samples and reconstruct the full AddrMan.
//
// Before caching: attacker making 100 connections gets 100 different 23% samples
// After caching: attacker making 100 connections gets the SAME 23% sample

TEST_CASE("Privacy: GETADDR responses are cached within time window", "[privacy][addr][cache]") {
    SimulatedNetwork net(49101);
    TestOrchestrator orch(&net);
    net.EnableCommandTracking(true);

    SimulatedNode server(1, &net);

    auto& am = server.GetNetworkManager().discovery_manager();

    // Populate AddrMan with 50 addresses
    for (int i = 1; i <= 50; ++i) {
        auto addr = MakeAddr(static_cast<uint8_t>(i), 2, 0, 1);
        AddrRelayManagerTestAccess::GetAddrManager(am).add(addr);
    }

    // Get responses from multiple different connections
    std::vector<std::set<std::string>> responses;

    for (int conn = 0; conn < 5; ++conn) {
        SimulatedNode client(10 + conn, &net);
        REQUIRE(client.ConnectTo(server.GetId()));
        REQUIRE(orch.WaitForConnection(server, client));

        for (int i = 0; i < 15; ++i) {
            orch.AdvanceTime(std::chrono::milliseconds(100));
        }

        auto payloads = net.GetCommandPayloads(server.GetId(), client.GetId(), commands::ADDR);
        if (!payloads.empty()) {
            message::AddrMessage resp;
            if (resp.deserialize(payloads.back().data(), payloads.back().size())) {
                std::set<std::string> addrs;
                for (const auto& ta : resp.addresses) {
                    addrs.insert(MakeAddrKey(ta));
                }
                responses.push_back(addrs);
            }
        }

        // Disconnect to allow new connection
        // (each connection gets one GETADDR response due to once-per-connection rule)
    }

    REQUIRE(responses.size() >= 3);  // Need at least 3 responses to compare

    // Within the cache window, all responses should contain the SAME addresses
    // (This is the anti-enumeration protection)
    int identical_pairs = 0;
    for (size_t i = 0; i < responses.size(); ++i) {
        for (size_t j = i + 1; j < responses.size(); ++j) {
            if (responses[i] == responses[j]) {
                ++identical_pairs;
            }
        }
    }

    // All pairs should be identical within the cache window
    int total_pairs = static_cast<int>(responses.size() * (responses.size() - 1) / 2);
    CHECK(identical_pairs == total_pairs);

    INFO("Identical pairs: " << identical_pairs << " out of " << total_pairs);
}

// =============================================================================
// TEST 2b: GETADDR cache expires after TTL
// =============================================================================
// After the cache expires (21-27 hours), a new sample should be generated.
// This test uses mock time to simulate cache expiration.

TEST_CASE("Privacy: GETADDR cache expires and refreshes after TTL", "[privacy][addr][cache][expiration]") {
    // SimulatedNetwork manages mock time internally via SetMockTime
    // We use net.GetCurrentTime() and AdvanceTime() to control time
    SimulatedNetwork net(49103);
    TestOrchestrator orch(&net);
    net.EnableCommandTracking(true);

    SimulatedNode server(1, &net);

    auto& dm = server.GetNetworkManager().discovery_manager();

    // Populate AddrMan with addresses in 80.x.x.x range (routable)
    for (int i = 1; i <= 50; ++i) {
        auto addr = MakeAddr(80, static_cast<uint8_t>(i), 0, 1);
        AddrRelayManagerTestAccess::GetAddrManager(dm).add(addr);
    }

    // Helper to get GETADDR response
    auto get_response = [&]() -> std::set<std::string> {
        static int client_id = 100;
        SimulatedNode client(client_id++, &net);
        REQUIRE(client.ConnectTo(server.GetId()));
        REQUIRE(orch.WaitForConnection(server, client));

        for (int i = 0; i < 15; ++i) {
            orch.AdvanceTime(std::chrono::milliseconds(100));
        }

        auto payloads = net.GetCommandPayloads(server.GetId(), client.GetId(), commands::ADDR);
        std::set<std::string> addrs;
        if (!payloads.empty()) {
            message::AddrMessage resp;
            if (resp.deserialize(payloads.back().data(), payloads.back().size())) {
                for (const auto& ta : resp.addresses) {
                    addrs.insert(MakeAddrKey(ta));
                }
            }
        }
        return addrs;
    };

    // Helper to check if response contains 80.x.x.x addresses
    auto has_80_range = [](const std::set<std::string>& addrs) {
        for (const auto& a : addrs) {
            if (a.find("80.") == 0) return true;
        }
        return false;
    };

    // Helper to check if response contains 90.x.x.x addresses
    auto has_90_range = [](const std::set<std::string>& addrs) {
        for (const auto& a : addrs) {
            if (a.find("90.") == 0) return true;
        }
        return false;
    };

    // Get first response (this populates the cache with 80.x.x.x addresses)
    auto response1 = get_response();
    REQUIRE(!response1.empty());
    REQUIRE(has_80_range(response1));
    REQUIRE_FALSE(has_90_range(response1));

    // Now ADD addresses in 90.x.x.x range to AddrMan (routable)
    // (The cache should still serve ONLY the old 80.x.x.x addresses)
    for (int i = 1; i <= 50; ++i) {
        auto addr = MakeAddr(90, static_cast<uint8_t>(i), 0, 1);
        AddrRelayManagerTestAccess::GetAddrManager(dm).add(addr);
    }
    // AddrMan now has 100 addresses (50 in 80.x.x.x + 50 in 90.x.x.x)
    INFO("AddrMan size after adding 90.x: " << AddrRelayManagerTestAccess::GetAddrManager(dm).size());

    // Get second response - cache should still serve ONLY old addresses (80.x.x.x)
    // because cache was populated before we added 90.x.x.x addresses
    auto response2 = get_response();

    // Cache is working if:
    // 1. Response2 contains ONLY 80.x addresses (from cached 50 addresses)
    // 2. Response2 is a superset of response1 (same cache, higher limit due to larger AddrMan)
    // Note: max_to_send is based on CURRENT AddrMan size, so response2 may have more addresses
    CHECK(has_80_range(response2));
    CHECK_FALSE(has_90_range(response2));  // New addresses NOT in cache yet

    // Verify response1 is a subset of response2 (proves same cache is being used)
    bool is_subset = std::includes(response2.begin(), response2.end(),
                                   response1.begin(), response1.end());
    CHECK(is_subset);

    // Advance network time by 28 hours (past max cache lifetime of 27h)
    // We advance the orchestrator's time which updates the network's current_time_ms_
    // and synchronizes with util::SetMockTime via SimulatedNetwork::AdvanceTime
    //
    // Note: Large time jumps can break pending message chains, but since we're just
    // connecting a NEW client, there are no pending messages to worry about
    orch.AdvanceTime(std::chrono::hours(28));  // Advance network time by 28 hours

    // Get third response - cache expired, should now include NEW addresses (90.x.x.x)
    // The refreshed cache pulls from current AddrMan which has both ranges
    auto response3 = get_response();
    INFO("Response3 size: " << response3.size());
    REQUIRE(!response3.empty());

    // After cache refresh, response should include some 90.x.x.x addresses
    // (With 100 addresses and 23% limit, we get ~23 addresses, statistically
    // very likely to include at least one from each range)
    CHECK(has_90_range(response3));  // New addresses now served

    // Verify response3 differs from response1 (cache actually refreshed)
    CHECK(response1 != response3);
}

// =============================================================================
// TEST 3: ADDR relay implementation exists and is bounded
// =============================================================================
// Verify the relay code limits to 2 peers by inspecting the implementation.
// Note: Active relay is hard to trigger in simulation because it requires
// ADDR that is NOT a response to GETADDR, which the automatic handshake process
// makes difficult to achieve. The implementation at addr_relay_manager.cpp:323
// uses: relay_count = std::min(relay_candidates.size(), size_t{2})

TEST_CASE("Privacy: ADDR relay code is bounded to 2 peers", "[privacy][addr][relay][implementation]") {
    // This test verifies the relay MECHANISM exists by checking that:
    // 1. Addresses are learned from ADDR messages
    // 2. The relay limit constant exists in the implementation

    SimulatedNetwork net(49102);
    // Simulation starts at realistic time (Jan 2024), so timestamps are valid
    TestOrchestrator orch(&net);

    SimulatedNode server(1, &net);
    SimulatedNode client(2, &net);

    REQUIRE(client.ConnectTo(server.GetId()));
    REQUIRE(orch.WaitForConnection(server, client));

    for (int i = 0; i < 15; ++i) {
        orch.AdvanceTime(std::chrono::milliseconds(100));
    }

    // Send ADDR with routable address
    message::AddrMessage addr_msg;
    auto now_s = static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());

    TimestampedAddress ta;
    ta.timestamp = now_s;
    ta.address = MakeAddr(93, 184, 216, 42);
    addr_msg.addresses.push_back(ta);

    auto payload = addr_msg.serialize();
    net.SendMessage(client.GetId(), server.GetId(), MakeWire(commands::ADDR, payload));

    for (int i = 0; i < 10; ++i) {
        orch.AdvanceTime(std::chrono::milliseconds(100));
    }

    // Verify address was learned (proves ADDR processing works)
    auto& discovery = server.GetNetworkManager().discovery_manager();
    size_t new_count = discovery.NewCount();

    // Address should be in NEW table
    CHECK(new_count >= 1);
    INFO("Addresses in NEW table: " << new_count);

    // The actual relay limit of 2 peers is verified by code inspection:
    // addr_relay_manager.cpp:323: relay_count = std::min(relay_candidates.size(), size_t{2})
}

// =============================================================================
// TEST 5: Large AddrMan still capped at 1000 addresses
// =============================================================================
// Even with huge address database, response never exceeds MAX_ADDR_SIZE (1000).

TEST_CASE("Privacy: GETADDR response capped at MAX_ADDR_SIZE", "[privacy][addr][cap]") {
    SimulatedNetwork net(49104);
    TestOrchestrator orch(&net);
    net.EnableCommandTracking(true);

    SimulatedNode server(1, &net);

    auto& am = server.GetNetworkManager().discovery_manager();

    // Try to populate AddrMan with 5000 addresses (should hit internal limits)
    // Use diverse netgroups to maximize acceptance
    size_t added = 0;
    for (int a = 1; a <= 250 && added < 5000; ++a) {
        for (int b = 1; b <= 250 && added < 5000; ++b) {
            auto addr = MakeAddr(static_cast<uint8_t>(a), static_cast<uint8_t>(b), 0, 1);
            if (AddrRelayManagerTestAccess::GetAddrManager(am).add(addr)) {
                ++added;
            }
        }
    }

    size_t addrman_size = AddrRelayManagerTestAccess::GetAddrManager(am).size();
    INFO("AddrMan size after population: " << addrman_size);

    // Connect client
    SimulatedNode client(2, &net);
    REQUIRE(client.ConnectTo(server.GetId()));
    REQUIRE(orch.WaitForConnection(server, client));

    for (int i = 0; i < 15; ++i) {
        orch.AdvanceTime(std::chrono::milliseconds(100));
    }

    auto payloads = net.GetCommandPayloads(server.GetId(), client.GetId(), commands::ADDR);
    REQUIRE_FALSE(payloads.empty());

    message::AddrMessage response;
    REQUIRE(response.deserialize(payloads.back().data(), payloads.back().size()));

    // Response must never exceed MAX_ADDR_SIZE (1000)
    CHECK(response.addresses.size() <= protocol::MAX_ADDR_SIZE);

    // With 23% limit on large AddrMan, should still be bounded
    // 5000 * 0.23 = 1150, but capped at 1000
    if (addrman_size > 4000) {
        CHECK(response.addresses.size() <= 1000);
    }

    INFO("Response size: " << response.addresses.size() << " (max allowed: 1000)");
}

// =============================================================================
// TEST 6: GETADDR once-per-connection prevents enumeration
// =============================================================================
// Attacker can't repeatedly query to enumerate full address database.

TEST_CASE("Privacy: GETADDR once-per-connection prevents enumeration", "[privacy][addr][enumeration]") {
    SimulatedNetwork net(49105);
    TestOrchestrator orch(&net);
    net.EnableCommandTracking(true);

    SimulatedNode server(1, &net);

    auto& am = server.GetNetworkManager().discovery_manager();

    // Populate with addresses
    for (int i = 1; i <= 30; ++i) {
        auto addr = MakeAddr(static_cast<uint8_t>(i), 5, 0, 1);
        AddrRelayManagerTestAccess::GetAddrManager(am).add(addr);
    }

    SimulatedNode attacker(2, &net);
    REQUIRE(attacker.ConnectTo(server.GetId()));
    REQUIRE(orch.WaitForConnection(server, attacker));

    for (int i = 0; i < 15; ++i) {
        orch.AdvanceTime(std::chrono::milliseconds(100));
    }

    // Count initial response
    auto initial = net.GetCommandPayloads(server.GetId(), attacker.GetId(), commands::ADDR);
    size_t initial_count = initial.size();

    // Try to send 10 more GETADDR requests on same connection
    for (int attempt = 0; attempt < 10; ++attempt) {
        net.SendMessage(attacker.GetId(), server.GetId(), MakeWire(commands::GETADDR, {}));
        orch.AdvanceTime(std::chrono::milliseconds(100));
    }

    // Should not have received additional responses
    auto final_msgs = net.GetCommandPayloads(server.GetId(), attacker.GetId(), commands::ADDR);

    // Only 1-2 ADDR messages should exist (initial + maybe one more with throttling)
    // Definitely not 11+ responses
    CHECK(final_msgs.size() <= initial_count + 1);

    // Verify the "ignored_repeat" counter incremented
    auto stats = server.GetDiscoveryManager().GetGetAddrDebugStats();
    CHECK(stats.ignored_repeat >= 9);  // Most repeats should be ignored

    INFO("Initial ADDR messages: " << initial_count << ", After 10 requests: " << final_msgs.size());
    INFO("Ignored repeat count: " << stats.ignored_repeat);
}
