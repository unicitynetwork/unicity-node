// ADDR Relay Deduplication Tests
//
// Tests that the same address received from multiple sources is only relayed
// once to each destination peer, preventing bandwidth waste and relay loops.
//
// Bug scenario (without deduplication):
// 1. Hub connected to Source1, Source2, Dest
// 2. Source1 sends addr X to Hub -> Hub queues relay to Dest
// 3. Source2 sends addr X to Hub -> Hub queues DUPLICATE relay to Dest
// 4. Dest receives addr X TWICE (wrong!)
//
// Expected behavior (with deduplication):
// - Hub checks if Dest already knows addr X before queuing relay
// - Second relay from Source2 is skipped
// - Dest receives addr X exactly ONCE

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
// TEST 1: Basic deterministic relay - address goes to exactly 2 peers
// =============================================================================
// Core functionality test: a single address from a single source should be
// relayed to exactly 2 deterministically-selected peers.

TEST_CASE("ADDR dedup: basic deterministic relay to 2 peers", "[addr][relay][dedup]") {
    SimulatedNetwork net(49300);
    TestOrchestrator orch(&net);
    net.EnableCommandTracking(true);

    // Hub node that will receive addresses and relay them
    SimulatedNode hub(1, &net);

    // Seed hub's relay seeds for deterministic behavior
    AddrRelayManagerTestAccess::SeedRng(hub.GetDiscoveryManager(), 11111);
    AddrRelayManagerTestAccess::SeedAddrRelay(hub.GetDiscoveryManager(), 12345, 67890);

    // Single source peer that will send addresses to hub
    SimulatedNode source(2, &net, "10.1.0.1");

    // Multiple potential relay targets - deterministic selection will pick 2
    SimulatedNode peer1(4, &net, "10.3.0.1");
    SimulatedNode peer2(5, &net, "10.4.0.1");
    SimulatedNode peer3(6, &net, "10.5.0.1");
    SimulatedNode peer4(7, &net, "10.6.0.1");

    // Source connects TO hub (hub sees it as INBOUND - can receive ADDR)
    // Hub connects OUT to peers as FULL_RELAY (can relay to them)
    REQUIRE(source.ConnectToFullRelay(hub.GetId(), hub.GetAddress()));
    REQUIRE(hub.ConnectToFullRelay(peer1.GetId(), peer1.GetAddress()));
    REQUIRE(hub.ConnectToFullRelay(peer2.GetId(), peer2.GetAddress()));
    REQUIRE(hub.ConnectToFullRelay(peer3.GetId(), peer3.GetAddress()));
    REQUIRE(hub.ConnectToFullRelay(peer4.GetId(), peer4.GetAddress()));

    REQUIRE(orch.WaitForConnection(hub, source));
    REQUIRE(orch.WaitForConnection(hub, peer1));
    REQUIRE(orch.WaitForConnection(hub, peer2));
    REQUIRE(orch.WaitForConnection(hub, peer3));
    REQUIRE(orch.WaitForConnection(hub, peer4));

    // Let handshakes complete
    for (int i = 0; i < 30; ++i) {
        orch.AdvanceTime(std::chrono::milliseconds(100));
    }

    // Record baseline ADDR messages to all peers
    std::vector<SimulatedNode*> peers = {&peer1, &peer2, &peer3, &peer4};
    std::map<int, size_t> baselines;
    for (auto* p : peers) {
        baselines[p->GetId()] = net.GetCommandPayloads(hub.GetId(), p->GetId(), commands::ADDR).size();
    }

    // Create the address to send
    auto now_s = static_cast<uint32_t>(util::GetTime());
    TimestampedAddress test_addr;
    test_addr.timestamp = now_s;
    test_addr.address = MakeAddr(93, 184, 216, 34);

    // Verify hub has the expected number of peers
    auto hub_peers = hub.GetNetworkManager().peer_manager().get_all_peers();
    INFO("Hub peer count: " << hub_peers.size());
    REQUIRE(hub_peers.size() == 5);  // 1 source + 4 peers

    // Verify all peers participate in ADDR relay
    int full_relay_count = 0;
    for (const auto& p : hub_peers) {
        if (p->relays_addr()) full_relay_count++;
    }
    INFO("Full-relay peers: " << full_relay_count);
    REQUIRE(full_relay_count == 5);

    // Source sends addr X to hub
    {
        message::AddrMessage addr_msg;
        addr_msg.addresses.push_back(test_addr);
        net.SendMessage(source.GetId(), hub.GetId(), MakeWire(commands::ADDR, addr_msg.serialize()));
    }

    // Process and check pending relay queue
    for (int i = 0; i < 10; ++i) {
        orch.AdvanceTime(std::chrono::milliseconds(100));
    }

    size_t pending_count = AddrRelayManagerTestAccess::GetPendingAddrRelayCount(hub.GetDiscoveryManager());
    INFO("Pending relay queue size after ADDR: " << pending_count);

    // Wait for trickle delays - advance 600 seconds like Bitcoin Core tests
    for (int i = 0; i < 600; ++i) {
        orch.AdvanceTime(std::chrono::seconds(1));
    }

    // Count total relay count across all peers
    std::string target_key = AddrToKey(test_addr);
    int total_relays = 0;
    std::set<int> peers_that_received;

    for (auto* p : peers) {
        auto payloads = net.GetCommandPayloads(hub.GetId(), p->GetId(), commands::ADDR);
        int count_for_peer = 0;

        for (size_t i = baselines[p->GetId()]; i < payloads.size(); ++i) {
            message::AddrMessage msg;
            if (msg.deserialize(payloads[i].data(), payloads[i].size())) {
                for (const auto& ta : msg.addresses) {
                    if (AddrToKey(ta) == target_key) {
                        ++count_for_peer;
                    }
                }
            }
        }

        if (count_for_peer > 0) {
            peers_that_received.insert(p->GetId());
            total_relays += count_for_peer;
        }
    }

    INFO("Total relays: " << total_relays << ", Peers receiving: " << peers_that_received.size());

    // CRITICAL: With deterministic selection, address goes to exactly 2 peers
    CHECK(peers_that_received.size() == 2);
    CHECK(total_relays == 2);  // Each selected peer gets it exactly once
}

// =============================================================================
// TEST 2: Different addresses from single source relay to exactly 2 peers each
// =============================================================================
// Verify that different addresses can map to different deterministic targets.
// Single source sends two different addresses - each relays to exactly 2 peers.
// With sender excluded from pool, all 4 other peers are valid targets.

TEST_CASE("ADDR dedup: different addresses from single source all relay", "[addr][relay][dedup]") {
    SimulatedNetwork net(49301);
    TestOrchestrator orch(&net);
    net.EnableCommandTracking(true);

    SimulatedNode hub(1, &net);

    // Seed hub's relay seeds for deterministic behavior
    AddrRelayManagerTestAccess::SeedRng(hub.GetDiscoveryManager(), 11111);
    AddrRelayManagerTestAccess::SeedAddrRelay(hub.GetDiscoveryManager(), 12345, 67890);

    // Single source and 4 relay targets (matching Bitcoin Core test pattern)
    // Source sends addresses, targets receive them
    SimulatedNode source(2, &net, "10.1.0.1");
    SimulatedNode peer1(4, &net, "10.3.0.1");
    SimulatedNode peer2(5, &net, "10.4.0.1");
    SimulatedNode peer3(6, &net, "10.5.0.1");
    SimulatedNode peer4(7, &net, "10.6.0.1");

    // Source connects TO hub (hub sees it as INBOUND)
    // Hub connects OUT to peers as FULL_RELAY
    REQUIRE(source.ConnectToFullRelay(hub.GetId(), hub.GetAddress()));
    REQUIRE(hub.ConnectToFullRelay(peer1.GetId(), peer1.GetAddress()));
    REQUIRE(hub.ConnectToFullRelay(peer2.GetId(), peer2.GetAddress()));
    REQUIRE(hub.ConnectToFullRelay(peer3.GetId(), peer3.GetAddress()));
    REQUIRE(hub.ConnectToFullRelay(peer4.GetId(), peer4.GetAddress()));

    REQUIRE(orch.WaitForConnection(hub, source));
    REQUIRE(orch.WaitForConnection(hub, peer1));
    REQUIRE(orch.WaitForConnection(hub, peer2));
    REQUIRE(orch.WaitForConnection(hub, peer3));
    REQUIRE(orch.WaitForConnection(hub, peer4));

    for (int i = 0; i < 30; ++i) {
        orch.AdvanceTime(std::chrono::milliseconds(100));
    }

    // Track ALL peers except source for relay counting
    // (Source is excluded from selection pool per Bitcoin Core design)
    std::vector<SimulatedNode*> relay_targets = {&peer1, &peer2, &peer3, &peer4};
    std::map<int, size_t> baselines;
    for (auto* p : relay_targets) {
        baselines[p->GetId()] = net.GetCommandPayloads(hub.GetId(), p->GetId(), commands::ADDR).size();
    }

    auto now_s = static_cast<uint32_t>(util::GetTime());

    // Source sends addr A
    TimestampedAddress addr_a;
    addr_a.timestamp = now_s;
    addr_a.address = MakeAddr(93, 184, 216, 100);
    {
        message::AddrMessage msg;
        msg.addresses.push_back(addr_a);
        net.SendMessage(source.GetId(), hub.GetId(), MakeWire(commands::ADDR, msg.serialize()));
    }

    // Allow token bucket to refill (rate: 0.1 tokens/sec, need 1 token = 10 seconds)
    for (int i = 0; i < 15; ++i) {
        orch.AdvanceTime(std::chrono::seconds(1));
    }

    // Source sends DIFFERENT addr B
    TimestampedAddress addr_b;
    addr_b.timestamp = now_s;
    addr_b.address = MakeAddr(93, 184, 216, 200);
    {
        message::AddrMessage msg;
        msg.addresses.push_back(addr_b);
        net.SendMessage(source.GetId(), hub.GetId(), MakeWire(commands::ADDR, msg.serialize()));
    }

    // Wait for trickle delays - advance 600 seconds like Bitcoin Core tests
    for (int i = 0; i < 600; ++i) {
        orch.AdvanceTime(std::chrono::seconds(1));
    }

    // Count relays of each address
    std::string key_a = AddrToKey(addr_a);
    std::string key_b = AddrToKey(addr_b);
    int relays_a = 0, relays_b = 0;
    std::set<int> peers_a, peers_b;

    for (auto* p : relay_targets) {
        auto payloads = net.GetCommandPayloads(hub.GetId(), p->GetId(), commands::ADDR);

        for (size_t i = baselines[p->GetId()]; i < payloads.size(); ++i) {
            message::AddrMessage msg;
            if (msg.deserialize(payloads[i].data(), payloads[i].size())) {
                for (const auto& ta : msg.addresses) {
                    std::string k = AddrToKey(ta);
                    if (k == key_a) { ++relays_a; peers_a.insert(p->GetId()); }
                    if (k == key_b) { ++relays_b; peers_b.insert(p->GetId()); }
                }
            }
        }
    }

    INFO("Addr A relayed to " << peers_a.size() << " peers, Addr B relayed to " << peers_b.size() << " peers");

    // Each address deterministically relays to exactly 2 of the 4 target peers
    CHECK(peers_a.size() == 2);
    CHECK(relays_a == 2);  // Each selected peer gets it once (dedup works)
    CHECK(peers_b.size() == 2);
    CHECK(relays_b == 2);
}

// =============================================================================
// TEST 3: Repeated same address from single source - amplification resistance
// =============================================================================
// Core amplification resistance test: single attacker peer repeatedly sends
// the same address. With deterministic selection, should relay to exactly 2 peers
// total, regardless of how many times it's sent.

TEST_CASE("ADDR dedup: repeated same address from single source", "[addr][relay][dedup][stress]") {
    SimulatedNetwork net(49302);
    TestOrchestrator orch(&net);
    net.EnableCommandTracking(true);

    SimulatedNode hub(1, &net);

    // Seed hub's seeds for deterministic behavior
    AddrRelayManagerTestAccess::SeedRng(hub.GetDiscoveryManager(), 54321);
    AddrRelayManagerTestAccess::SeedAddrRelay(hub.GetDiscoveryManager(), 11111, 22222);

    // Single attacker source
    SimulatedNode attacker(2, &net, "10.1.0.1");

    // Multiple potential relay targets
    SimulatedNode peer1(100, &net, "10.100.0.1");
    SimulatedNode peer2(101, &net, "10.101.0.1");
    SimulatedNode peer3(102, &net, "10.102.0.1");
    SimulatedNode peer4(103, &net, "10.103.0.1");

    // Attacker connects TO hub (hub sees it as INBOUND)
    REQUIRE(attacker.ConnectToFullRelay(hub.GetId(), hub.GetAddress()));
    REQUIRE(orch.WaitForConnection(hub, attacker));

    // Hub connects OUT to peers as full-relay
    REQUIRE(hub.ConnectToFullRelay(peer1.GetId(), peer1.GetAddress()));
    REQUIRE(hub.ConnectToFullRelay(peer2.GetId(), peer2.GetAddress()));
    REQUIRE(hub.ConnectToFullRelay(peer3.GetId(), peer3.GetAddress()));
    REQUIRE(hub.ConnectToFullRelay(peer4.GetId(), peer4.GetAddress()));
    REQUIRE(orch.WaitForConnection(hub, peer1));
    REQUIRE(orch.WaitForConnection(hub, peer2));
    REQUIRE(orch.WaitForConnection(hub, peer3));
    REQUIRE(orch.WaitForConnection(hub, peer4));

    for (int i = 0; i < 30; ++i) {
        orch.AdvanceTime(std::chrono::milliseconds(100));
    }

    std::vector<SimulatedNode*> peers = {&peer1, &peer2, &peer3, &peer4};
    std::map<int, size_t> baselines;
    for (auto* p : peers) {
        baselines[p->GetId()] = net.GetCommandPayloads(hub.GetId(), p->GetId(), commands::ADDR).size();
    }

    // Attacker sends the SAME address 10 times in rapid succession
    auto now_s = static_cast<uint32_t>(util::GetTime());
    TimestampedAddress sybil_addr;
    sybil_addr.timestamp = now_s;
    sybil_addr.address = MakeAddr(93, 184, 216, 77);

    for (int i = 0; i < 10; ++i) {
        message::AddrMessage msg;
        msg.addresses.push_back(sybil_addr);
        net.SendMessage(attacker.GetId(), hub.GetId(), MakeWire(commands::ADDR, msg.serialize()));
        // Small delay between sends
        orch.AdvanceTime(std::chrono::milliseconds(50));
    }

    // Wait for trickle delays - advance 600 seconds like Bitcoin Core tests
    for (int i = 0; i < 600; ++i) {
        orch.AdvanceTime(std::chrono::seconds(1));
    }

    std::string target_key = AddrToKey(sybil_addr);
    int total_relays = 0;
    std::set<int> peers_that_received;

    for (auto* p : peers) {
        auto payloads = net.GetCommandPayloads(hub.GetId(), p->GetId(), commands::ADDR);
        int count = 0;

        for (size_t i = baselines[p->GetId()]; i < payloads.size(); ++i) {
            message::AddrMessage msg;
            if (msg.deserialize(payloads[i].data(), payloads[i].size())) {
                for (const auto& ta : msg.addresses) {
                    if (AddrToKey(ta) == target_key) {
                        ++count;
                    }
                }
            }
        }

        if (count > 0) {
            peers_that_received.insert(p->GetId());
            total_relays += count;
        }
    }

    INFO("Attacker sent same address 10x, total relays: " << total_relays << ", peers: " << peers_that_received.size());

    // AMPLIFICATION RESISTANCE: Even with 10 sends, should only relay to 2 peers, once each
    // Deterministic selection always picks the same 2 peers for the same address
    // Deduplication prevents re-sending to peers who already know the address
    CHECK(peers_that_received.size() == 2);
    CHECK(total_relays == 2);
}

// =============================================================================
// TEST 4: Multiple addresses - each gets exactly 2 peers
// =============================================================================
// Verify that when sending multiple different addresses, each goes to exactly
// 2 deterministic peers (potentially different peers for different addresses).

TEST_CASE("ADDR dedup: multiple addresses each relay to exactly 2 peers", "[addr][relay][dedup]") {
    SimulatedNetwork net(49303);
    TestOrchestrator orch(&net);
    net.EnableCommandTracking(true);

    SimulatedNode hub(1, &net);

    // Seed hub's seeds for deterministic behavior
    AddrRelayManagerTestAccess::SeedRng(hub.GetDiscoveryManager(), 12345);
    AddrRelayManagerTestAccess::SeedAddrRelay(hub.GetDiscoveryManager(), 33333, 44444);

    // Single source and multiple relay targets
    SimulatedNode source(2, &net, "10.1.0.1");
    SimulatedNode peer1(10, &net, "10.10.0.1");
    SimulatedNode peer2(11, &net, "10.11.0.1");
    SimulatedNode peer3(12, &net, "10.12.0.1");
    SimulatedNode peer4(13, &net, "10.13.0.1");

    // Source connects TO hub (hub sees it as INBOUND)
    // Hub connects OUT to peers as FULL_RELAY
    REQUIRE(source.ConnectToFullRelay(hub.GetId(), hub.GetAddress()));
    REQUIRE(hub.ConnectToFullRelay(peer1.GetId(), peer1.GetAddress()));
    REQUIRE(hub.ConnectToFullRelay(peer2.GetId(), peer2.GetAddress()));
    REQUIRE(hub.ConnectToFullRelay(peer3.GetId(), peer3.GetAddress()));
    REQUIRE(hub.ConnectToFullRelay(peer4.GetId(), peer4.GetAddress()));

    REQUIRE(orch.WaitForConnection(hub, source));
    REQUIRE(orch.WaitForConnection(hub, peer1));
    REQUIRE(orch.WaitForConnection(hub, peer2));
    REQUIRE(orch.WaitForConnection(hub, peer3));
    REQUIRE(orch.WaitForConnection(hub, peer4));

    for (int i = 0; i < 30; ++i) {
        orch.AdvanceTime(std::chrono::milliseconds(100));
    }

    // Record baselines
    std::vector<SimulatedNode*> peers = {&peer1, &peer2, &peer3, &peer4};
    std::map<int, size_t> baselines;
    for (auto* p : peers) {
        baselines[p->GetId()] = net.GetCommandPayloads(hub.GetId(), p->GetId(), commands::ADDR).size();
    }

    auto now_s = static_cast<uint32_t>(util::GetTime());

    // Send 5 different addresses
    std::vector<TimestampedAddress> addrs;
    for (int i = 0; i < 5; ++i) {
        TimestampedAddress ta;
        ta.timestamp = now_s;
        ta.address = MakeAddr(93, 184, 216, static_cast<uint8_t>(50 + i));
        addrs.push_back(ta);

        message::AddrMessage msg;
        msg.addresses.push_back(ta);
        net.SendMessage(source.GetId(), hub.GetId(), MakeWire(commands::ADDR, msg.serialize()));
        // Allow token bucket to refill between sends (rate: 0.1 tokens/sec)
        for (int j = 0; j < 15; ++j) {
            orch.AdvanceTime(std::chrono::seconds(1));
        }
    }

    // Wait for trickle delays - advance 600 seconds like Bitcoin Core tests
    for (int i = 0; i < 600; ++i) {
        orch.AdvanceTime(std::chrono::seconds(1));
    }

    // Count relays for each address
    for (size_t addr_idx = 0; addr_idx < addrs.size(); ++addr_idx) {
        std::string target_key = AddrToKey(addrs[addr_idx]);
        int relays = 0;
        std::set<int> recipients;

        for (auto* p : peers) {
            auto payloads = net.GetCommandPayloads(hub.GetId(), p->GetId(), commands::ADDR);
            int count = 0;
            for (size_t i = baselines[p->GetId()]; i < payloads.size(); ++i) {
                message::AddrMessage msg;
                if (msg.deserialize(payloads[i].data(), payloads[i].size())) {
                    for (const auto& ta : msg.addresses) {
                        if (AddrToKey(ta) == target_key) ++count;
                    }
                }
            }
            if (count > 0) {
                recipients.insert(p->GetId());
                relays += count;
            }
            // Each peer should receive each address at most once
            CHECK(count <= 1);
        }

        INFO("Address " << addr_idx << ": relayed to " << recipients.size() << " peers, " << relays << " times");

        // Each address deterministically relays to exactly 2 of the 4 peers
        CHECK(recipients.size() == 2);
        CHECK(relays == 2);
    }
}
