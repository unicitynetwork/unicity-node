// ADDR Relay Multi-Source Coordination Attack Tests
//
// Tests that verify defense against Sybil attacks where multiple attacker-controlled
// peers all send the same address to a victim, attempting to amplify relay traffic.
//
// Key defense mechanisms:
// 1. Deterministic relay target selection (same address -> same 2 targets)
// 2. Learned address tracking (targets marked as "knowing" address after first relay)
// 3. Per-source rate limiting (limits each individual attacker)
//
// Attack scenario:
// - Attacker controls N sybil peers connected to victim
// - All N peers send the same malicious address to victim
// - Without protection: victim relays to 2 targets × N sources = 2N relays
// - With protection: victim relays to 2 targets total (deduplication across sources)

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
#include <cstring>
#include <map>
#include <set>
#include <sstream>

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

static std::string AddrToKey(const TimestampedAddress& ta) {
    char buf[32];
    snprintf(buf, sizeof(buf), "%u.%u.%u.%u:%u",
             ta.address.ip[12], ta.address.ip[13], ta.address.ip[14], ta.address.ip[15],
             ta.address.port);
    return std::string(buf);
}

// =============================================================================
// TEST 1: Multiple sybil peers send same address - max 2 relay targets
// =============================================================================
// Attack: N sybil peers all send the SAME address to victim hub
// Defense: Deduplication via learned_addresses ensures only 2 targets receive relay

TEST_CASE("ADDR coordinated: sybil peers sending same address limited to 2 targets", "[addr][relay][sybil][security]") {
    SimulatedNetwork net(49400);
    TestOrchestrator orch(&net);
    net.EnableCommandTracking(true);

    // Hub (victim) that will receive addresses from sybils and relay to targets
    SimulatedNode hub(1, &net);

    // Seed for deterministic behavior
    AddrRelayManagerTestAccess::SeedRng(hub.GetDiscoveryManager(), 12345);
    AddrRelayManagerTestAccess::SeedAddrRelay(hub.GetDiscoveryManager(), 11111, 22222);

    // Create 10 sybil attacker peers (different netgroups)
    constexpr int NUM_SYBILS = 10;
    std::vector<std::unique_ptr<SimulatedNode>> sybils;
    for (int i = 0; i < NUM_SYBILS; ++i) {
        auto sybil = std::make_unique<SimulatedNode>(100 + i, &net);
        // Each sybil connects TO hub (hub sees them as inbound)
        REQUIRE(sybil->ConnectToFullRelay(hub.GetId(), hub.GetAddress()));
        sybils.push_back(std::move(sybil));
    }

    // Create 4 relay target peers
    SimulatedNode target1(200, &net, "10.200.0.1");
    SimulatedNode target2(201, &net, "10.201.0.1");
    SimulatedNode target3(202, &net, "10.202.0.1");
    SimulatedNode target4(203, &net, "10.203.0.1");

    // Hub connects OUT to targets as full-relay
    REQUIRE(hub.ConnectToFullRelay(target1.GetId(), target1.GetAddress()));
    REQUIRE(hub.ConnectToFullRelay(target2.GetId(), target2.GetAddress()));
    REQUIRE(hub.ConnectToFullRelay(target3.GetId(), target3.GetAddress()));
    REQUIRE(hub.ConnectToFullRelay(target4.GetId(), target4.GetAddress()));

    // Wait for all connections
    for (auto& sybil : sybils) {
        REQUIRE(orch.WaitForConnection(hub, *sybil));
    }
    REQUIRE(orch.WaitForConnection(hub, target1));
    REQUIRE(orch.WaitForConnection(hub, target2));
    REQUIRE(orch.WaitForConnection(hub, target3));
    REQUIRE(orch.WaitForConnection(hub, target4));

    // Let handshakes complete
    for (int i = 0; i < 30; ++i) {
        orch.AdvanceTime(std::chrono::milliseconds(100));
    }

    // Verify hub sees all peers and handshakes are complete
    auto hub_peers = hub.GetNetworkManager().peer_manager().get_all_peers();
    INFO("Hub peer count: " << hub_peers.size() << " (expected: " << (NUM_SYBILS + 4) << ")");
    REQUIRE(hub_peers.size() == NUM_SYBILS + 4);  // 10 sybils + 4 targets

    // Verify all peers participate in ADDR relay (handshakes complete)
    int full_relay_count = 0;
    int successfully_connected_count = 0;
    for (const auto& p : hub_peers) {
        if (p->relays_addr()) full_relay_count++;
        if (p->successfully_connected()) successfully_connected_count++;
    }
    INFO("Full-relay peers: " << full_relay_count << ", successfully_connected: " << successfully_connected_count);
    REQUIRE(full_relay_count == NUM_SYBILS + 4);
    REQUIRE(successfully_connected_count == NUM_SYBILS + 4);

    // Record baseline ADDR counts to targets
    std::vector<SimulatedNode*> targets = {&target1, &target2, &target3, &target4};
    std::map<int, size_t> baselines;
    for (auto* t : targets) {
        baselines[t->GetId()] = net.GetCommandPayloads(hub.GetId(), t->GetId(), commands::ADDR).size();
    }

    // Record baseline HandleAddr call count to verify P2P path is used
    uint64_t handleaddr_baseline = AddrRelayManagerTestAccess::GetHandleAddrCallCount(hub.GetDiscoveryManager());

    // The malicious address all sybils will send
    auto now_s = static_cast<uint32_t>(util::GetTime());
    TimestampedAddress malicious_addr;
    malicious_addr.timestamp = now_s;
    malicious_addr.address = MakeAddr(8, 8, 8, 8);  // Well-known IP for testing

    // ATTACK: All 10 sybils send the SAME address to hub
    for (int i = 0; i < NUM_SYBILS; ++i) {
        message::AddrMessage msg;
        msg.addresses.push_back(malicious_addr);
        net.SendMessage(sybils[i]->GetId(), hub.GetId(), MakeWire(commands::ADDR, msg.serialize()));

        // Small delay between sybil sends
        orch.AdvanceTime(std::chrono::milliseconds(50));
    }

    // Check pending relay queue after sending
    size_t pending_after_send = AddrRelayManagerTestAccess::GetPendingAddrRelayCount(hub.GetDiscoveryManager());
    INFO("Pending relay queue after sending: " << pending_after_send);

    // Wait for trickle delays (600 seconds like Bitcoin Core tests)
    for (int i = 0; i < 600; ++i) {
        orch.AdvanceTime(std::chrono::seconds(1));
    }

    size_t pending_after_wait = AddrRelayManagerTestAccess::GetPendingAddrRelayCount(hub.GetDiscoveryManager());
    INFO("Pending relay queue after wait: " << pending_after_wait);

    // Count relays of the malicious address to ALL nodes (sybils + targets)
    // NOTE: SimulatedNetwork uses node IDs, not Peer IDs
    std::string target_key = AddrToKey(malicious_addr);
    int total_relays = 0;
    std::set<int> nodes_that_received;

    // Collect all node IDs we might have relayed to
    std::vector<int> all_node_ids;
    for (int i = 0; i < NUM_SYBILS; ++i) {
        all_node_ids.push_back(100 + i);  // Sybil node IDs
    }
    all_node_ids.push_back(200);  // target1
    all_node_ids.push_back(201);  // target2
    all_node_ids.push_back(202);  // target3
    all_node_ids.push_back(203);  // target4

    std::ostringstream node_debug;
    node_debug << "Checking nodes: ";
    int total_addr_msgs = 0;
    for (int node_id : all_node_ids) {
        auto payloads = net.GetCommandPayloads(hub.GetId(), node_id, commands::ADDR);
        node_debug << node_id << "(" << payloads.size() << ") ";
        total_addr_msgs += payloads.size();

        for (const auto& payload : payloads) {
            message::AddrMessage msg;
            if (msg.deserialize(payload.data(), payload.size())) {
                for (const auto& ta : msg.addresses) {
                    if (AddrToKey(ta) == target_key) {
                        nodes_that_received.insert(node_id);
                        ++total_relays;
                    }
                }
            }
        }
    }
    INFO(node_debug.str());
    INFO("Total ADDR messages from hub: " << total_addr_msgs);

    // VERIFICATION: Confirm HandleAddr was called via real P2P path
    uint64_t handleaddr_after = AddrRelayManagerTestAccess::GetHandleAddrCallCount(hub.GetDiscoveryManager());
    uint64_t handleaddr_calls = handleaddr_after - handleaddr_baseline;
    INFO("HandleAddr called " << handleaddr_calls << " times (expected: " << NUM_SYBILS << ")");
    REQUIRE(handleaddr_calls == NUM_SYBILS);  // Each sybil's ADDR went through real P2P handler

    INFO("Sybil attack: " << NUM_SYBILS << " sybils sent same address, total relays: "
         << total_relays << ", nodes receiving: " << nodes_that_received.size());

    // CRITICAL ASSERTION: Despite 10 sybils sending the same address,
    // deduplication ensures only a small constant number of relays, NOT 10*2=20.
    //
    // Why we might see 2-3 targets instead of exactly 2:
    // - Each sender is excluded from their own relay candidates
    // - Different senders may thus select slightly different target sets
    // - But learned_addresses deduplication prevents re-relaying to same target
    //
    // Security property: total_relays << NUM_SYBILS * 2
    CHECK(nodes_that_received.size() <= 4);  // Small constant, not 10+
    CHECK(total_relays <= 4);                // Small constant, not 20
    CHECK(total_relays < NUM_SYBILS);        // Way less than amplification attack
}

// =============================================================================
// TEST 2: Verify per-source rate limiting doesn't affect cross-source dedup
// =============================================================================
// Rate limiting is per-source (each sybil has its own bucket).
// Relay deduplication is per-target (learned_addresses tracks what targets know).
// This test verifies both mechanisms work together correctly.

TEST_CASE("ADDR coordinated: rate limiting per-source, dedup per-target", "[addr][relay][sybil][rate]") {
    SimulatedNetwork net(49401);
    TestOrchestrator orch(&net);
    net.EnableCommandTracking(true);

    SimulatedNode hub(1, &net);
    AddrRelayManagerTestAccess::SeedRng(hub.GetDiscoveryManager(), 54321);
    AddrRelayManagerTestAccess::SeedAddrRelay(hub.GetDiscoveryManager(), 33333, 44444);

    // 3 sybil sources
    SimulatedNode sybil1(10, &net, "10.10.0.1");
    SimulatedNode sybil2(11, &net, "10.11.0.1");
    SimulatedNode sybil3(12, &net, "10.12.0.1");

    // 4 relay targets
    SimulatedNode target1(200, &net, "10.200.0.1");
    SimulatedNode target2(201, &net, "10.201.0.1");
    SimulatedNode target3(202, &net, "10.202.0.1");
    SimulatedNode target4(203, &net, "10.203.0.1");

    // Sybils connect TO hub (inbound)
    REQUIRE(sybil1.ConnectToFullRelay(hub.GetId(), hub.GetAddress()));
    REQUIRE(sybil2.ConnectToFullRelay(hub.GetId(), hub.GetAddress()));
    REQUIRE(sybil3.ConnectToFullRelay(hub.GetId(), hub.GetAddress()));

    // Hub connects OUT to targets
    REQUIRE(hub.ConnectToFullRelay(target1.GetId(), target1.GetAddress()));
    REQUIRE(hub.ConnectToFullRelay(target2.GetId(), target2.GetAddress()));
    REQUIRE(hub.ConnectToFullRelay(target3.GetId(), target3.GetAddress()));
    REQUIRE(hub.ConnectToFullRelay(target4.GetId(), target4.GetAddress()));

    REQUIRE(orch.WaitForConnection(hub, sybil1));
    REQUIRE(orch.WaitForConnection(hub, sybil2));
    REQUIRE(orch.WaitForConnection(hub, sybil3));
    REQUIRE(orch.WaitForConnection(hub, target1));
    REQUIRE(orch.WaitForConnection(hub, target2));
    REQUIRE(orch.WaitForConnection(hub, target3));
    REQUIRE(orch.WaitForConnection(hub, target4));

    for (int i = 0; i < 30; ++i) {
        orch.AdvanceTime(std::chrono::milliseconds(100));
    }

    std::vector<SimulatedNode*> targets = {&target1, &target2, &target3, &target4};
    std::map<int, size_t> baselines;
    for (auto* t : targets) {
        baselines[t->GetId()] = net.GetCommandPayloads(hub.GetId(), t->GetId(), commands::ADDR).size();
    }

    auto now_s = static_cast<uint32_t>(util::GetTime());

    // Each sybil sends a DIFFERENT address
    // This tests that rate limiting is per-source, not global
    TimestampedAddress addr1, addr2, addr3;
    addr1.timestamp = now_s;
    addr1.address = MakeAddr(1, 1, 1, 1);
    addr2.timestamp = now_s;
    addr2.address = MakeAddr(2, 2, 2, 2);
    addr3.timestamp = now_s;
    addr3.address = MakeAddr(3, 3, 3, 3);

    // All three sybils send their addresses simultaneously
    {
        message::AddrMessage msg;
        msg.addresses.push_back(addr1);
        net.SendMessage(sybil1.GetId(), hub.GetId(), MakeWire(commands::ADDR, msg.serialize()));
    }
    {
        message::AddrMessage msg;
        msg.addresses.push_back(addr2);
        net.SendMessage(sybil2.GetId(), hub.GetId(), MakeWire(commands::ADDR, msg.serialize()));
    }
    {
        message::AddrMessage msg;
        msg.addresses.push_back(addr3);
        net.SendMessage(sybil3.GetId(), hub.GetId(), MakeWire(commands::ADDR, msg.serialize()));
    }

    orch.AdvanceTime(std::chrono::milliseconds(100));

    // Wait for trickle delays
    for (int i = 0; i < 600; ++i) {
        orch.AdvanceTime(std::chrono::seconds(1));
    }

    // Count total unique addresses relayed to ALL nodes (sybils + targets)
    // NOTE: Relay targets include sybils, not just our "target" nodes
    std::set<std::string> unique_addrs_relayed;
    int total_relays = 0;

    // Check all possible relay destinations (sybils 10-12 + targets 200-203)
    std::vector<int> all_node_ids = {10, 11, 12, 200, 201, 202, 203};
    for (int node_id : all_node_ids) {
        auto payloads = net.GetCommandPayloads(hub.GetId(), node_id, commands::ADDR);

        for (const auto& payload : payloads) {
            message::AddrMessage msg;
            if (msg.deserialize(payload.data(), payload.size())) {
                for (const auto& ta : msg.addresses) {
                    unique_addrs_relayed.insert(AddrToKey(ta));
                    ++total_relays;
                }
            }
        }
    }

    INFO("3 sybils sent 3 different addresses, unique relayed: " << unique_addrs_relayed.size()
         << ", total relay entries: " << total_relays);

    // Each of the 3 addresses should be relayed, with approximately 2 targets each
    // Variation due to sender-exclusion affecting deterministic selection
    CHECK(unique_addrs_relayed.size() == 3);
    CHECK(total_relays >= 3);   // At least 1 relay per address
    CHECK(total_relays <= 12);  // Upper bound: worst case all different targets
}

// =============================================================================
// TEST 3: Rapid source churn doesn't bypass deduplication
// =============================================================================
// Attacker disconnects and reconnects (gets new peer_id) to try to bypass dedup.
// Deduplication is on the TARGET side (target's learned_addresses), so this should
// still be blocked as long as the target remains connected.

TEST_CASE("ADDR coordinated: source reconnect doesn't bypass dedup", "[addr][relay][sybil][churn]") {
    SimulatedNetwork net(49402);
    TestOrchestrator orch(&net);
    net.EnableCommandTracking(true);

    SimulatedNode hub(1, &net);
    AddrRelayManagerTestAccess::SeedRng(hub.GetDiscoveryManager(), 99999);
    AddrRelayManagerTestAccess::SeedAddrRelay(hub.GetDiscoveryManager(), 55555, 66666);

    // Attacker node (will disconnect and reconnect)
    SimulatedNode attacker(10, &net, "10.10.0.1");

    // Relay targets (remain connected throughout)
    SimulatedNode target1(200, &net, "10.200.0.1");
    SimulatedNode target2(201, &net, "10.201.0.1");
    SimulatedNode target3(202, &net, "10.202.0.1");
    SimulatedNode target4(203, &net, "10.203.0.1");

    // Initial connections
    REQUIRE(attacker.ConnectToFullRelay(hub.GetId(), hub.GetAddress()));
    REQUIRE(hub.ConnectToFullRelay(target1.GetId(), target1.GetAddress()));
    REQUIRE(hub.ConnectToFullRelay(target2.GetId(), target2.GetAddress()));
    REQUIRE(hub.ConnectToFullRelay(target3.GetId(), target3.GetAddress()));
    REQUIRE(hub.ConnectToFullRelay(target4.GetId(), target4.GetAddress()));

    REQUIRE(orch.WaitForConnection(hub, attacker));
    REQUIRE(orch.WaitForConnection(hub, target1));
    REQUIRE(orch.WaitForConnection(hub, target2));
    REQUIRE(orch.WaitForConnection(hub, target3));
    REQUIRE(orch.WaitForConnection(hub, target4));

    for (int i = 0; i < 30; ++i) {
        orch.AdvanceTime(std::chrono::milliseconds(100));
    }

    std::vector<SimulatedNode*> targets = {&target1, &target2, &target3, &target4};
    std::map<int, size_t> baselines;
    for (auto* t : targets) {
        baselines[t->GetId()] = net.GetCommandPayloads(hub.GetId(), t->GetId(), commands::ADDR).size();
    }

    auto now_s = static_cast<uint32_t>(util::GetTime());
    TimestampedAddress malicious_addr;
    malicious_addr.timestamp = now_s;
    malicious_addr.address = MakeAddr(77, 77, 77, 77);

    // ROUND 1: Attacker sends address
    {
        message::AddrMessage msg;
        msg.addresses.push_back(malicious_addr);
        net.SendMessage(attacker.GetId(), hub.GetId(), MakeWire(commands::ADDR, msg.serialize()));
    }

    // Wait for relay to happen
    for (int i = 0; i < 600; ++i) {
        orch.AdvanceTime(std::chrono::seconds(1));
    }

    // Verify first round relayed to 2 targets
    std::string target_key = AddrToKey(malicious_addr);
    int round1_relays = 0;
    std::set<int> round1_targets;

    for (auto* t : targets) {
        auto payloads = net.GetCommandPayloads(hub.GetId(), t->GetId(), commands::ADDR);
        for (size_t i = baselines[t->GetId()]; i < payloads.size(); ++i) {
            message::AddrMessage msg;
            if (msg.deserialize(payloads[i].data(), payloads[i].size())) {
                for (const auto& ta : msg.addresses) {
                    if (AddrToKey(ta) == target_key) {
                        ++round1_relays;
                        round1_targets.insert(t->GetId());
                    }
                }
            }
        }
        // Update baseline for round 2 comparison
        baselines[t->GetId()] = payloads.size();
    }

    INFO("Round 1: " << round1_relays << " relays to " << round1_targets.size() << " targets");
    CHECK(round1_targets.size() == 2);
    CHECK(round1_relays == 2);

    // ROUND 2: Attacker disconnects and reconnects (simulating churn attack)
    attacker.DisconnectFrom(hub.GetId());
    for (int i = 0; i < 10; ++i) {
        orch.AdvanceTime(std::chrono::milliseconds(100));
    }

    // Reconnect
    REQUIRE(attacker.ConnectToFullRelay(hub.GetId(), hub.GetAddress()));
    REQUIRE(orch.WaitForConnection(hub, attacker));

    for (int i = 0; i < 30; ++i) {
        orch.AdvanceTime(std::chrono::milliseconds(100));
    }

    // Attacker sends the SAME address again after reconnect
    {
        message::AddrMessage msg;
        msg.addresses.push_back(malicious_addr);
        net.SendMessage(attacker.GetId(), hub.GetId(), MakeWire(commands::ADDR, msg.serialize()));
    }

    // Wait for potential relay
    for (int i = 0; i < 600; ++i) {
        orch.AdvanceTime(std::chrono::seconds(1));
    }

    // Count round 2 relays
    int round2_relays = 0;

    for (auto* t : targets) {
        auto payloads = net.GetCommandPayloads(hub.GetId(), t->GetId(), commands::ADDR);
        for (size_t i = baselines[t->GetId()]; i < payloads.size(); ++i) {
            message::AddrMessage msg;
            if (msg.deserialize(payloads[i].data(), payloads[i].size())) {
                for (const auto& ta : msg.addresses) {
                    if (AddrToKey(ta) == target_key) {
                        ++round2_relays;
                    }
                }
            }
        }
    }

    INFO("Round 2 (after reconnect): " << round2_relays << " additional relays");

    // CRITICAL: Round 2 should have 0 additional relays because:
    // - Targets already have the address in their learned_addresses
    // - Attacker reconnecting doesn't clear target state
    CHECK(round2_relays == 0);
}

// =============================================================================
// TEST 4: Multiple sybils with interleaved sends
// =============================================================================
// More realistic attack pattern: sybils send addresses in interleaved bursts
// to try to overwhelm deduplication tracking

TEST_CASE("ADDR coordinated: interleaved sybil sends still deduplicated", "[addr][relay][sybil][stress]") {
    SimulatedNetwork net(49403);
    TestOrchestrator orch(&net);
    net.EnableCommandTracking(true);

    SimulatedNode hub(1, &net);
    AddrRelayManagerTestAccess::SeedRng(hub.GetDiscoveryManager(), 11111);
    AddrRelayManagerTestAccess::SeedAddrRelay(hub.GetDiscoveryManager(), 77777, 88888);

    // 5 sybil sources
    constexpr int NUM_SYBILS = 5;
    std::vector<std::unique_ptr<SimulatedNode>> sybils;
    for (int i = 0; i < NUM_SYBILS; ++i) {
        auto sybil = std::make_unique<SimulatedNode>(100 + i, &net);
        REQUIRE(sybil->ConnectToFullRelay(hub.GetId(), hub.GetAddress()));
        sybils.push_back(std::move(sybil));
    }

    // 4 relay targets
    SimulatedNode target1(200, &net, "10.200.0.1");
    SimulatedNode target2(201, &net, "10.201.0.1");
    SimulatedNode target3(202, &net, "10.202.0.1");
    SimulatedNode target4(203, &net, "10.203.0.1");

    REQUIRE(hub.ConnectToFullRelay(target1.GetId(), target1.GetAddress()));
    REQUIRE(hub.ConnectToFullRelay(target2.GetId(), target2.GetAddress()));
    REQUIRE(hub.ConnectToFullRelay(target3.GetId(), target3.GetAddress()));
    REQUIRE(hub.ConnectToFullRelay(target4.GetId(), target4.GetAddress()));

    for (auto& sybil : sybils) {
        REQUIRE(orch.WaitForConnection(hub, *sybil));
    }
    REQUIRE(orch.WaitForConnection(hub, target1));
    REQUIRE(orch.WaitForConnection(hub, target2));
    REQUIRE(orch.WaitForConnection(hub, target3));
    REQUIRE(orch.WaitForConnection(hub, target4));

    for (int i = 0; i < 30; ++i) {
        orch.AdvanceTime(std::chrono::milliseconds(100));
    }

    std::vector<SimulatedNode*> targets = {&target1, &target2, &target3, &target4};
    std::map<int, size_t> baselines;
    for (auto* t : targets) {
        baselines[t->GetId()] = net.GetCommandPayloads(hub.GetId(), t->GetId(), commands::ADDR).size();
    }

    auto now_s = static_cast<uint32_t>(util::GetTime());

    // Create 3 malicious addresses (use simple IPs like passing tests)
    std::vector<TimestampedAddress> malicious_addrs;
    for (int i = 0; i < 3; ++i) {
        TimestampedAddress ta;
        ta.timestamp = now_s;
        ta.address = MakeAddr(50 + i, 0, 0, i + 1);  // 50.0.0.1, 51.0.0.2, 52.0.0.3
        malicious_addrs.push_back(ta);
    }

    // Check HandleAddr counter before attack
    uint64_t handleaddr_before = AddrRelayManagerTestAccess::GetHandleAddrCallCount(hub.GetDiscoveryManager());

    // ATTACK: Interleaved sends - each sybil sends all 3 addresses in round-robin
    // Pattern: S0 sends A0, S1 sends A0, S2 sends A0, ... S0 sends A1, S1 sends A1, ...
    //
    // IMPORTANT: Token bucket rate limiting is 0.1 addr/sec = 1 addr per 10 seconds per source.
    // With 5 sybils, each sybil has 5*2s + 5s = 15 seconds between its consecutive sends.
    // This ensures each sybil's token bucket refills (needs 10s for 1 token).
    for (const auto& addr : malicious_addrs) {
        for (int s = 0; s < NUM_SYBILS; ++s) {
            message::AddrMessage msg;
            msg.addresses.push_back(addr);
            net.SendMessage(sybils[s]->GetId(), hub.GetId(), MakeWire(commands::ADDR, msg.serialize()));
            orch.AdvanceTime(std::chrono::seconds(2));  // 2 seconds between different sybils
        }
        // Gap between addresses rounds - total time per round: 5*2s = 10s + 5s gap = 15s
        orch.AdvanceTime(std::chrono::seconds(5));
    }

    // Verify HandleAddr was called for each ADDR message
    uint64_t handleaddr_after = AddrRelayManagerTestAccess::GetHandleAddrCallCount(hub.GetDiscoveryManager());
    uint64_t expected_handleaddr_calls = NUM_SYBILS * 3;  // 5 sybils × 3 addresses each
    INFO("HandleAddr called " << (handleaddr_after - handleaddr_before) << " times (expected: " << expected_handleaddr_calls << ")");
    REQUIRE((handleaddr_after - handleaddr_before) == expected_handleaddr_calls);

    // Debug: Check pending relay queue before trickle wait
    size_t pending_before_wait = AddrRelayManagerTestAccess::GetPendingAddrRelayCount(hub.GetDiscoveryManager());
    INFO("Pending relay queue before wait: " << pending_before_wait);

    // Wait for trickle delays
    for (int i = 0; i < 600; ++i) {
        orch.AdvanceTime(std::chrono::seconds(1));
    }

    // Debug: Check pending relay queue after wait
    size_t pending_after_wait = AddrRelayManagerTestAccess::GetPendingAddrRelayCount(hub.GetDiscoveryManager());
    INFO("Pending relay queue after wait: " << pending_after_wait);

    // Count relays per address - check ALL possible destinations (sybils + targets)
    std::map<std::string, int> relay_counts;
    std::map<std::string, std::set<int>> targets_per_addr;

    // All possible relay destinations: sybils 100-104 and targets 200-203
    std::vector<int> all_node_ids = {100, 101, 102, 103, 104, 200, 201, 202, 203};

    for (int node_id : all_node_ids) {
        auto payloads = net.GetCommandPayloads(hub.GetId(), node_id, commands::ADDR);

        for (const auto& payload : payloads) {
            message::AddrMessage msg;
            if (msg.deserialize(payload.data(), payload.size())) {
                for (const auto& ta : msg.addresses) {
                    std::string key = AddrToKey(ta);
                    relay_counts[key]++;
                    targets_per_addr[key].insert(node_id);
                }
            }
        }
    }

    INFO("Interleaved attack with " << NUM_SYBILS << " sybils × 3 addresses:");

    // Debug: Print all ADDR payloads from hub to each node
    for (int node_id : all_node_ids) {
        auto payloads = net.GetCommandPayloads(hub.GetId(), node_id, commands::ADDR);
        if (!payloads.empty()) {
            INFO("  Hub -> Node " << node_id << ": " << payloads.size() << " ADDR messages");
        }
    }

    int total_relays = 0;
    for (const auto& addr : malicious_addrs) {
        std::string key = AddrToKey(addr);
        std::string targets_str;
        for (int t : targets_per_addr[key]) {
            targets_str += std::to_string(t) + " ";
        }
        INFO("  " << key << ": " << relay_counts[key] << " relays to targets: [" << targets_str << "]");
        total_relays += relay_counts[key];
        // Each address should go to a small number of targets (2-4 due to sender-exclusion)
        CHECK(targets_per_addr[key].size() >= 1);  // At least 1 relay
        CHECK(targets_per_addr[key].size() <= 4);  // No amplification
    }

    // Total relays bounded, not amplified by sybil count
    // 3 addresses × (2-4 targets each) = 6-12 relays
    // NOT: 3 addresses × 5 sybils × 2 targets = 30 relays
    CHECK(total_relays >= 3);
    CHECK(total_relays <= 12);
}
