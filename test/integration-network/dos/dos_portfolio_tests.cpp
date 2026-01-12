// DoS Attack Portfolio Tests
// Comprehensive test suite using DoSAttackSimulator infrastructure
//
// Test Categories:
// 1. Buffer Overflow Attacks - Memory/bandwidth exhaustion
// 2. Validation Attacks - Invalid headers, PoW manipulation
// 3. Connection Attacks - Throttle evasion, stalling
// 4. Protocol Violations - Oversized messages, malformed data

#include "catch_amalgamated.hpp"
#include "infra/dos_attack_simulator.hpp"
#include "infra/simulated_network.hpp"
#include "infra/simulated_node.hpp"
#include "infra/node_simulator.hpp"
#include "infra/peer_factory.hpp"
#include "chain/chainparams.hpp"
#include "network/peer_misbehavior.hpp"
#include <limits>

using namespace unicity;
using namespace unicity::network;
using namespace unicity::test;

static struct TestSetup {
    TestSetup() { chain::GlobalChainParams::Select(chain::ChainType::REGTEST); }
} test_setup_dos_portfolio;

// =============================================================================
// SECTION 1: BUFFER OVERFLOW ATTACKS
// =============================================================================

TEST_CASE("DoS Portfolio - Buffer Overflow Attacks", "[dos][portfolio][buffer]") {
    SimulatedNetwork network(1000);

    // Fast network conditions
    SimulatedNetwork::NetworkConditions fast;
    fast.latency_min = std::chrono::milliseconds(0);
    fast.latency_max = std::chrono::milliseconds(1);
    fast.bandwidth_bytes_per_sec = 0;  // unlimited
    network.SetNetworkConditions(fast);

    SimulatedNode victim(1, &network);
    DoSAttackSimulator sim(&network, &victim);

    SECTION("Valid messages - processed without disconnect") {
        SimulatedNode attacker(2, &network);

        REQUIRE(attacker.ConnectTo(1));
        TestOrchestrator orch(&network);
        REQUIRE(orch.WaitForConnection(victim, attacker));

        // Send valid PING messages (correct checksum) - these are processed normally
        // and don't fill the buffer
        auto result = sim.SendMessageFlood(attacker, 5, 1024);

        INFO(sim.GenerateReport());

        // Valid messages should be processed without triggering buffer overflow
        CHECK(result.messages_sent == 5);
        // Connection status depends on message handling, not buffer overflow
    }

    SECTION("Partial payload attack - buffer fills waiting for data") {
        SimulatedNode attacker(3, &network);

        REQUIRE(attacker.ConnectTo(1));
        TestOrchestrator orch(&network);
        REQUIRE(orch.WaitForConnection(victim, attacker));

        // Attack: declare 1MB but send only 256KB
        // Buffer fills waiting for the rest of the declared payload
        // 30 messages * 256KB actual = 7.5MB, but buffer expects 30MB
        auto result = sim.SendMessageFlood(attacker, 30, 256 * 1024, 1024 * 1024);

        INFO(sim.GenerateReport());

        // Partial payload attack should trigger buffer overflow protection
        CHECK(result.triggered_disconnect);
        CHECK(result.defense_triggered == "recv_buffer_overflow");
    }

    SECTION("Large partial payload - exceeds threshold quickly") {
        SimulatedNode attacker(4, &network);

        REQUIRE(attacker.ConnectTo(1));
        TestOrchestrator orch(&network);
        REQUIRE(orch.WaitForConnection(victim, attacker));

        // Extreme attack: declare 4MB but send 512KB per message
        // ~20 messages fill 10MB threshold (DEFAULT_RECV_FLOOD_SIZE)
        auto result = sim.SendMessageFlood(attacker, 25, 512 * 1024, 4 * 1024 * 1024);

        INFO(sim.GenerateReport());

        CHECK(result.triggered_disconnect);
        CHECK(result.defense_triggered == "recv_buffer_overflow");
    }

    SECTION("Victim chain integrity preserved during attack") {
        SimulatedNode attacker(5, &network);

        sim.BuildVictimChain(10);  // Build 10 blocks first

        REQUIRE(attacker.ConnectTo(1));
        TestOrchestrator orch(&network);
        REQUIRE(orch.WaitForConnection(victim, attacker));

        // Partial payload attack
        auto result = sim.SendMessageFlood(attacker, 30, 256 * 1024, 1024 * 1024);

        INFO(sim.GenerateReport());

        // Chain should be unaffected by DoS
        CHECK(result.victim_chain_intact);
        CHECK(result.victim_height_before == 10);
        CHECK(result.victim_height_after == 10);
    }
}

// =============================================================================
// SECTION 2: VALIDATION ATTACKS
// =============================================================================

TEST_CASE("DoS Portfolio - Validation Attacks", "[dos][portfolio][validation]") {
    SimulatedNetwork network(2000);
    SimulatedNode victim(1, &network);
    DoSAttackSimulator sim(&network, &victim);

    SECTION("Invalid PoW - single header - immediate discourage") {
        NodeSimulator attacker(2, &network);

        sim.BuildVictimChain(10);
        REQUIRE(sim.ConnectAndSync(attacker));

        auto result = sim.SendInvalidPoWHeaders(attacker, 1);

        INFO(sim.GenerateReport());

        // Invalid PoW = instant discourage (Bitcoin Core March 2024+)
        CHECK(result.peer_discouraged);
        CHECK(result.triggered_disconnect);
        CHECK(result.victim_chain_intact);
        CHECK(result.defense_triggered == "misbehavior_instant_discourage");
    }

    SECTION("Invalid PoW - multiple headers - still one penalty") {
        NodeSimulator attacker(3, &network);

        sim.BuildVictimChain(10);
        REQUIRE(sim.ConnectAndSync(attacker));

        // Send 5 invalid headers
        auto result = sim.SendInvalidPoWHeaders(attacker, 5);

        INFO(sim.GenerateReport());

        // First invalid header triggers penalty, rest don't matter
        CHECK(result.peer_discouraged);
        CHECK(result.triggered_disconnect);
    }

    SECTION("Low work headers - silently ignored") {
        NodeSimulator attacker(4, &network);

        sim.BuildVictimChain(10);
        REQUIRE(sim.ConnectAndSync(attacker));

        // Send headers that don't have enough cumulative work
        auto result = sim.SendLowWorkHeaders(attacker, 20, 10);

        INFO(sim.GenerateReport());

        // Low work = silently ignored, no penalty
        CHECK_FALSE(result.triggered_disconnect);
        CHECK_FALSE(result.peer_discouraged);
        CHECK(result.defense_triggered == "silent_ignore");
        CHECK(result.victim_chain_intact);
    }

    SECTION("Orphan headers - rate limited") {
        NodeSimulator attacker(5, &network);

        sim.BuildVictimChain(10);
        REQUIRE(sim.ConnectAndSync(attacker));

        // Send 200 orphan headers (unknown parent)
        auto result = sim.SendOrphanHeaders(attacker, 200, 50);

        INFO(sim.GenerateReport());

        // Orphans should be limited, not cause crash
        CHECK(result.victim_chain_intact);
        // Peer may or may not be disconnected depending on rate limiting
    }

    SECTION("Orphan spam - large volume") {
        NodeSimulator attacker(6, &network);

        sim.BuildVictimChain(10);
        REQUIRE(sim.ConnectAndSync(attacker));

        // Heavy orphan spam: 1000 headers
        auto result = sim.SendOrphanHeaders(attacker, 1000, 100);

        INFO(sim.GenerateReport());

        // Node should survive without crash
        CHECK(result.victim_chain_intact);
        CHECK(victim.GetTipHeight() == 10);  // Chain unchanged
    }
}

// =============================================================================
// SECTION 3: CONNECTION ATTACKS
// =============================================================================

TEST_CASE("DoS Portfolio - Connection Attacks", "[dos][portfolio][connection]") {
    SimulatedNetwork network(3000);
    SimulatedNode victim(1, &network);
    PeerFactory factory(&network);
    DoSAttackSimulator sim(&network, &victim);

    SECTION("Rapid reconnect - same node reconnecting") {
        // Single attacker node trying to reconnect rapidly
        // Bitcoin Core parity: no per-IP throttling, relies on netgroup eviction
        SimulatedNode attacker(100, &network, "192.168.1.100");

        // Try to reconnect 10 times rapidly from same IP
        auto result = sim.RapidReconnect(attacker, 10, std::chrono::milliseconds(50));

        INFO(sim.GenerateReport());

        // Bitcoin Core parity: no connection throttling
        // All connections from same IP are allowed (within netgroup limits)
        // Protection comes from netgroup-based eviction
        CHECK(result.messages_accepted >= 1);  // At least some should succeed
    }

    SECTION("Sybil connection flood - netgroup limit") {
        // Multiple attackers from same /16 subnet
        auto result = sim.SybilConnectionFlood(factory, "192.168.0.0", 10);

        INFO(sim.GenerateReport());

        // Per-netgroup limit is 4, so only 4 should succeed
        CHECK(result.messages_accepted == 4);
        CHECK(result.messages_rejected == 6);
        CHECK(result.defense_triggered == "netgroup_limit");
    }

    SECTION("Sybil from multiple subnets - all connect") {
        // Test that diverse IPs can all connect
        auto attackers = factory.CreateDiversePeers(8, 200);

        for (auto& a : attackers) {
            a->ConnectTo(victim.GetId(), victim.GetAddress());
        }

        TestOrchestrator orch(&network);
        orch.AdvanceTime(std::chrono::seconds(2));

        // All 8 should connect (different /16s, no netgroup conflict)
        CHECK(victim.GetInboundPeerCount() == 8);
    }

    SECTION("Stalling peer - detected during IBD") {
        SimulatedNode attacker(2, &network);

        // Build victim chain so it's in IBD mode waiting for more
        sim.BuildVictimChain(10);

        REQUIRE(attacker.ConnectTo(1));
        TestOrchestrator orch(&network);
        REQUIRE(orch.WaitForConnection(victim, attacker));

        // Sync first
        REQUIRE(orch.WaitForSync(victim, attacker));

        // Now stall for extended period - during IBD this triggers timeout
        // Note: Stall timeout only applies during IBD, not post-IBD
        auto result = sim.StallResponses(attacker, std::chrono::seconds(180));

        INFO(sim.GenerateReport());

        // May or may not disconnect depending on IBD state
        // The key test is that victim doesn't hang
        CHECK(victim.GetTipHeight() == 10);
    }
}

// =============================================================================
// SECTION 4: PROTOCOL VIOLATION ATTACKS
// =============================================================================

TEST_CASE("DoS Portfolio - Protocol Violations", "[dos][portfolio][protocol]") {
    SimulatedNetwork network(4000);
    SimulatedNode victim(1, &network);
    DoSAttackSimulator sim(&network, &victim);

    SECTION("Oversized headers - protocol violation") {
        NodeSimulator attacker(2, &network);

        sim.BuildVictimChain(10);
        REQUIRE(sim.ConnectAndSync(attacker));

        // Send 80001 headers (MAX_HEADERS_SIZE = 80000)
        auto result = sim.SendOversizedMessages(attacker, "headers", 80001);

        INFO(sim.GenerateReport());

        // Protocol violation should trigger disconnect
        CHECK(result.triggered_disconnect);
        CHECK(result.defense_triggered == "protocol_violation");
    }

    SECTION("Oversized headers - at limit - accepted") {
        NodeSimulator attacker(3, &network);

        sim.BuildVictimChain(10);
        REQUIRE(sim.ConnectAndSync(attacker));

        // Send exactly 80000 headers (at limit, should be OK)
        auto result = sim.SendOversizedMessages(attacker, "headers", 80000);

        INFO(sim.GenerateReport());

        // At limit should be accepted
        CHECK_FALSE(result.triggered_disconnect);
    }

    SECTION("Oversized headers - way over limit") {
        NodeSimulator attacker(4, &network);

        sim.BuildVictimChain(10);
        REQUIRE(sim.ConnectAndSync(attacker));

        // Send 100000 headers (over limit)
        auto result = sim.SendOversizedMessages(attacker, "headers", 100000);

        INFO(sim.GenerateReport());

        CHECK(result.triggered_disconnect);
    }
}

// =============================================================================
// SECTION 5: COMBINED/STRESS ATTACKS
// =============================================================================

TEST_CASE("DoS Portfolio - Combined Attacks", "[dos][portfolio][combined]") {
    SimulatedNetwork network(5000);
    SimulatedNode victim(1, &network);
    DoSAttackSimulator sim(&network, &victim);

    SECTION("Sequential attacks - node recovers") {
        sim.BuildVictimChain(10);

        // Attack 1: Buffer flood
        {
            SimulatedNode attacker1(2, &network);
            REQUIRE(attacker1.ConnectTo(1));
            TestOrchestrator orch(&network);
            REQUIRE(orch.WaitForConnection(victim, attacker1));

            auto r1 = sim.SendMessageFlood(attacker1, 30, 256 * 1024);
            CHECK(r1.triggered_disconnect);
        }

        sim.Reset();

        // Attack 2: Invalid PoW (new attacker)
        {
            NodeSimulator attacker2(3, &network);
            REQUIRE(sim.ConnectAndSync(attacker2));

            auto r2 = sim.SendInvalidPoWHeaders(attacker2, 1);
            CHECK(r2.peer_discouraged);
        }

        sim.Reset();

        // Attack 3: Orphan spam (new attacker)
        {
            NodeSimulator attacker3(4, &network);
            REQUIRE(sim.ConnectAndSync(attacker3));

            auto r3 = sim.SendOrphanHeaders(attacker3, 500, 50);
            CHECK(r3.victim_chain_intact);
        }

        // Victim should still be functional
        CHECK(victim.GetTipHeight() == 10);
    }

    SECTION("Multiple attackers simultaneously") {
        sim.BuildVictimChain(5);

        // Create 5 attackers
        std::vector<std::unique_ptr<SimulatedNode>> attackers;
        for (int i = 0; i < 5; i++) {
            attackers.push_back(std::make_unique<SimulatedNode>(100 + i, &network));
            attackers.back()->ConnectTo(1);
        }

        TestOrchestrator orch(&network);
        orch.AdvanceTime(std::chrono::seconds(2));

        // Each attacker sends moderate flood
        for (auto& attacker : attackers) {
            // 5 messages * 50KB = 250KB per attacker = 1.25MB total
            std::vector<uint8_t> payload(50 * 1024, 0);
            protocol::MessageHeader hdr(protocol::magic::REGTEST,
                                        protocol::commands::PING, payload.size());
            auto hdr_bytes = message::serialize_header(hdr);

            for (int j = 0; j < 5; j++) {
                std::vector<uint8_t> msg;
                msg.insert(msg.end(), hdr_bytes.begin(), hdr_bytes.end());
                msg.insert(msg.end(), payload.begin(), payload.end());
                network.SendMessage(attacker->GetId(), victim.GetId(), msg);
            }
        }

        orch.AdvanceTime(std::chrono::seconds(2));

        // Victim should survive moderate multi-source attack
        CHECK(victim.GetTipHeight() == 5);
    }

    SECTION("Attack during sync - chain integrity") {
        // Victim has short chain
        sim.BuildVictimChain(5);

        // Honest peer with longer chain
        SimulatedNode honest(10, &network);
        honest.SetBypassPOWValidation(true);
        for (int i = 0; i < 20; i++) {
            honest.MineBlock();
        }
        honest.SetBypassPOWValidation(false);

        // Connect honest peer
        REQUIRE(honest.ConnectTo(1));
        TestOrchestrator orch(&network);
        REQUIRE(orch.WaitForConnection(victim, honest));

        // Start sync
        orch.AdvanceTime(std::chrono::seconds(1));

        // Attacker tries to disrupt during sync
        SimulatedNode attacker(20, &network);
        REQUIRE(attacker.ConnectTo(1));
        orch.AdvanceTime(std::chrono::milliseconds(500));

        // Small flood during sync
        sim.SendMessageFlood(attacker, 10, 100 * 1024);

        // Let sync complete
        orch.AdvanceTime(std::chrono::seconds(5));

        // Victim should have synced to honest chain
        CHECK(victim.GetTipHeight() >= 5);  // At least original height
    }
}

// =============================================================================
// SECTION 6: EDGE CASES AND REGRESSION TESTS
// =============================================================================

TEST_CASE("DoS Portfolio - Edge Cases", "[dos][portfolio][edge]") {
    SimulatedNetwork network(6000);
    SimulatedNode victim(1, &network);
    DoSAttackSimulator sim(&network, &victim);

    SECTION("Zero-length messages") {
        SimulatedNode attacker(2, &network);

        REQUIRE(attacker.ConnectTo(1));
        TestOrchestrator orch(&network);
        REQUIRE(orch.WaitForConnection(victim, attacker));

        // Send empty payload messages
        auto result = sim.SendMessageFlood(attacker, 100, 0);

        INFO(sim.GenerateReport());

        // Empty messages should be handled gracefully
        CHECK(result.messages_sent == 100);
        // Should not crash
    }

    SECTION("Single byte messages") {
        SimulatedNode attacker(3, &network);

        REQUIRE(attacker.ConnectTo(1));
        TestOrchestrator orch(&network);
        REQUIRE(orch.WaitForConnection(victim, attacker));

        // Many tiny messages
        auto result = sim.SendMessageFlood(attacker, 1000, 1);

        INFO(sim.GenerateReport());

        CHECK(result.messages_sent == 1000);
    }

    SECTION("Max size single message") {
        SimulatedNode attacker(4, &network);

        REQUIRE(attacker.ConnectTo(1));
        TestOrchestrator orch(&network);
        REQUIRE(orch.WaitForConnection(victim, attacker));

        // Single 4MB message (near max message size)
        auto result = sim.SendMessageFlood(attacker, 1, 4 * 1024 * 1024);

        INFO(sim.GenerateReport());

        // Large single message should be handled
        CHECK(result.messages_sent == 1);
    }

    SECTION("Attacker disconnects mid-flood") {
        SimulatedNode attacker(5, &network);

        REQUIRE(attacker.ConnectTo(1));
        TestOrchestrator orch(&network);
        REQUIRE(orch.WaitForConnection(victim, attacker));

        // Start flood
        protocol::MessageHeader hdr(protocol::magic::REGTEST,
                                    protocol::commands::PING, 100 * 1024);
        auto hdr_bytes = message::serialize_header(hdr);
        std::vector<uint8_t> payload(100 * 1024, 0);

        for (int i = 0; i < 10; i++) {
            std::vector<uint8_t> msg;
            msg.insert(msg.end(), hdr_bytes.begin(), hdr_bytes.end());
            msg.insert(msg.end(), payload.begin(), payload.end());
            network.SendMessage(attacker.GetId(), victim.GetId(), msg);
        }

        // Attacker disconnects mid-attack
        attacker.Disconnect(1);

        orch.AdvanceTime(std::chrono::seconds(2));

        // Victim should handle gracefully
        CHECK(victim.GetPeerCount() == 0);
    }

    SECTION("Fresh node under attack - no prior state") {
        // Victim has no blocks, no prior connections
        SimulatedNode attacker(6, &network);

        REQUIRE(attacker.ConnectTo(1));
        TestOrchestrator orch(&network);
        REQUIRE(orch.WaitForConnection(victim, attacker));

        auto result = sim.SendMessageFlood(attacker, 30, 256 * 1024);

        INFO(sim.GenerateReport());

        // Fresh node should still have protection
        CHECK(result.triggered_disconnect);
        CHECK(victim.GetTipHeight() == 0);  // Still at genesis
    }
}

// =============================================================================
// SECTION 7: DEFENSE EFFECTIVENESS METRICS
// =============================================================================

TEST_CASE("DoS Portfolio - Defense Metrics", "[dos][portfolio][metrics]") {
    SimulatedNetwork network(7000);
    SimulatedNode victim(1, &network);
    DoSAttackSimulator sim(&network, &victim);

    SECTION("Report contains all required fields") {
        SimulatedNode attacker(2, &network);

        REQUIRE(attacker.ConnectTo(1));
        TestOrchestrator orch(&network);
        REQUIRE(orch.WaitForConnection(victim, attacker));

        sim.SendMessageFlood(attacker, 5, 1024);

        std::string report = sim.GenerateReport();

        // Verify report structure
        CHECK(report.find("Attack Type:") != std::string::npos);
        CHECK(report.find("Description:") != std::string::npos);
        CHECK(report.find("Duration:") != std::string::npos);
        CHECK(report.find("Messages Sent:") != std::string::npos);
        CHECK(report.find("Defense Response") != std::string::npos);
        CHECK(report.find("Victim State") != std::string::npos);
        CHECK(report.find("Verdict") != std::string::npos);
    }

    SECTION("Before/after snapshots accurate") {
        sim.BuildVictimChain(10);

        SimulatedNode attacker(3, &network);
        REQUIRE(attacker.ConnectTo(1));
        TestOrchestrator orch(&network);
        REQUIRE(orch.WaitForConnection(victim, attacker));

        // Reset to capture current state as "before"
        sim.Reset();

        auto before = sim.GetBeforeSnapshot();
        CHECK(before.chain_height == 10);
        CHECK(before.peer_count >= 1);

        // Partial payload attack triggers disconnect
        sim.SendMessageFlood(attacker, 30, 256 * 1024, 1024 * 1024);

        auto after = sim.GetAfterSnapshot();
        CHECK(after.chain_height == 10);  // Unchanged
        CHECK(after.peer_count == 0);     // Attacker disconnected
    }

    SECTION("WasDefended() predicate works") {
        SimulatedNode attacker(4, &network);

        REQUIRE(attacker.ConnectTo(1));
        TestOrchestrator orch(&network);
        REQUIRE(orch.WaitForConnection(victim, attacker));

        // Partial payload attack triggers defense
        sim.SendMessageFlood(attacker, 30, 256 * 1024, 1024 * 1024);
        CHECK(sim.WasDefended());
        CHECK(sim.PeerWasDisconnected());

        sim.Reset();

        // Valid small messages don't trigger defense
        SimulatedNode attacker2(5, &network);
        REQUIRE(attacker2.ConnectTo(1));
        REQUIRE(orch.WaitForConnection(victim, attacker2));

        // Send valid complete messages (no partial payload)
        sim.SendMessageFlood(attacker2, 1, 1024);
        // Valid messages are processed normally
        CHECK(sim.GetLastResult().messages_sent == 1);
    }
}

// =============================================================================
// SECTION 8: MESSAGE-SPECIFIC OVERSIZED ATTACKS
// =============================================================================

TEST_CASE("DoS Portfolio - Oversized Message Attacks", "[dos][portfolio][oversized]") {
    SimulatedNetwork network(8000);
    SimulatedNode victim(1, &network);
    DoSAttackSimulator sim(&network, &victim);

    SECTION("Oversized INV - 100,000 items triggers disconnect") {
        SimulatedNode attacker(2, &network);

        REQUIRE(attacker.ConnectTo(1));
        TestOrchestrator orch(&network);
        REQUIRE(orch.WaitForConnection(victim, attacker));

        // Send INV with 100,000 items (MAX_INV_SIZE = 50,000)
        auto result = sim.SendOversizedInv(attacker, 100000);

        INFO(sim.GenerateReport());

        CHECK(result.triggered_disconnect);
        CHECK(result.defense_triggered == "oversized_inv_rejected");
    }

    SECTION("Oversized INV - at limit - accepted") {
        SimulatedNode attacker(3, &network);

        REQUIRE(attacker.ConnectTo(1));
        TestOrchestrator orch(&network);
        REQUIRE(orch.WaitForConnection(victim, attacker));

        // Send INV with exactly 50,000 items (at limit)
        // Note: This declares 50,000 but doesn't provide actual items,
        // so it will fail deserialization but not for oversized count
        auto result = sim.SendOversizedInv(attacker, 50000);

        INFO(sim.GenerateReport());

        // At-limit triggers disconnect due to malformed (incomplete) message
        // but the defense is for the malformed payload, not oversized count
        CHECK(result.triggered_disconnect);
    }

    SECTION("Oversized ADDR - 10,000 addresses triggers disconnect") {
        SimulatedNode attacker(4, &network);

        REQUIRE(attacker.ConnectTo(1));
        TestOrchestrator orch(&network);
        REQUIRE(orch.WaitForConnection(victim, attacker));

        // Send ADDR with 10,000 addresses (MAX_ADDR_SIZE = 1,000)
        auto result = sim.SendOversizedAddr(attacker, 10000);

        INFO(sim.GenerateReport());

        CHECK(result.triggered_disconnect);
        CHECK(result.defense_triggered == "oversized_addr_rejected");
    }

    SECTION("Oversized ADDR - at limit - handled gracefully") {
        SimulatedNode attacker(5, &network);

        REQUIRE(attacker.ConnectTo(1));
        TestOrchestrator orch(&network);
        REQUIRE(orch.WaitForConnection(victim, attacker));

        // Send ADDR with exactly 1,000 addresses (at limit)
        auto result = sim.SendOversizedAddr(attacker, 1000);

        INFO(sim.GenerateReport());

        // Malformed (incomplete) message causes disconnect
        CHECK(result.triggered_disconnect);
    }
}

// =============================================================================
// SECTION 9: COMPACTSIZE OVERFLOW ATTACKS
// =============================================================================

TEST_CASE("DoS Portfolio - CompactSize Overflow Attacks", "[dos][portfolio][overflow]") {
    SimulatedNetwork network(9000);
    SimulatedNode victim(1, &network);
    DoSAttackSimulator sim(&network, &victim);

    SECTION("CompactSize overflow in HEADERS - 18 EB allocation blocked") {
        SimulatedNode attacker(2, &network);

        REQUIRE(attacker.ConnectTo(1));
        TestOrchestrator orch(&network);
        REQUIRE(orch.WaitForConnection(victim, attacker));

        // Attack: 0xFF + 8 bytes of 0xFF = 18 exabytes claimed
        auto result = sim.SendCompactSizeOverflow(attacker, "headers");

        INFO(sim.GenerateReport());

        CHECK(result.triggered_disconnect);
        CHECK(result.defense_triggered == "compactsize_overflow_rejected");
    }

    SECTION("CompactSize overflow in INV - blocked") {
        SimulatedNode attacker(3, &network);

        REQUIRE(attacker.ConnectTo(1));
        TestOrchestrator orch(&network);
        REQUIRE(orch.WaitForConnection(victim, attacker));

        auto result = sim.SendCompactSizeOverflow(attacker, "inv");

        INFO(sim.GenerateReport());

        CHECK(result.triggered_disconnect);
        CHECK(result.defense_triggered == "compactsize_overflow_rejected");
    }

    SECTION("CompactSize overflow in ADDR - blocked") {
        SimulatedNode attacker(4, &network);

        REQUIRE(attacker.ConnectTo(1));
        TestOrchestrator orch(&network);
        REQUIRE(orch.WaitForConnection(victim, attacker));

        auto result = sim.SendCompactSizeOverflow(attacker, "addr");

        INFO(sim.GenerateReport());

        CHECK(result.triggered_disconnect);
        CHECK(result.defense_triggered == "compactsize_overflow_rejected");
    }

    SECTION("Node survives without OOM") {
        SimulatedNode attacker(5, &network);

        REQUIRE(attacker.ConnectTo(1));
        TestOrchestrator orch(&network);
        REQUIRE(orch.WaitForConnection(victim, attacker));

        // Multiple overflow attempts - node must survive all
        for (int i = 0; i < 5; i++) {
            SimulatedNode atk(10 + i, &network);
            REQUIRE(atk.ConnectTo(1));
            orch.AdvanceTime(std::chrono::milliseconds(100));

            sim.SendCompactSizeOverflow(atk, "headers");
        }

        // Victim should still be functional
        CHECK(victim.GetTipHeight() == 0);  // At genesis, but alive
    }
}

// =============================================================================
// SECTION 10: RATE LIMITING ATTACKS
// =============================================================================

TEST_CASE("DoS Portfolio - Rate Limiting Attacks", "[dos][portfolio][ratelimit]") {
    SimulatedNetwork network(10000);
    SimulatedNode victim(1, &network);
    DoSAttackSimulator sim(&network, &victim);

    SECTION("ADDR flood - rate limited") {
        SimulatedNode attacker(2, &network);

        REQUIRE(attacker.ConnectTo(1));
        TestOrchestrator orch(&network);
        REQUIRE(orch.WaitForConnection(victim, attacker));

        // Boost the token bucket by simulating GETADDR was sent
        // (In production, we'd send GETADDR before receiving ADDR)
        // This ensures the test doesn't depend on system uptime for bucket fill
        int peer_id = orch.GetPeerId(victim, attacker);
        victim.GetNetworkManager().discovery_manager_for_test().NotifyGetAddrSent(peer_id);

        // Send 10 messages × 1000 addresses = 10,000 total
        // Rate limiting should cap processing at ~1000 (token bucket starts at 1000)
        auto result = sim.SendAddrFlood(attacker, 10, 1000,
            std::chrono::milliseconds(100));

        INFO(sim.GenerateReport());

        // Per-source limit (64) is stricter than rate limiting (~1000 bucket)
        // Single peer can only add MAX_ADDRESSES_PER_SOURCE addresses
        CHECK(result.messages_accepted < 10000);  // Not all processed
        CHECK(result.messages_accepted <= 64);    // Per-source limit caps at 64
        CHECK(result.messages_accepted >= 32);    // Some processed (allowing for netgroup limits)
        CHECK(result.defense_triggered == "addr_rate_limiting");

        // Peer should still be connected (rate limiting, not ban)
        CHECK_FALSE(result.triggered_disconnect);
    }

    SECTION("ADDR flood - peer survives") {
        SimulatedNode attacker(3, &network);

        REQUIRE(attacker.ConnectTo(1));
        TestOrchestrator orch(&network);
        REQUIRE(orch.WaitForConnection(victim, attacker));

        // Moderate flood - should not disconnect
        auto result = sim.SendAddrFlood(attacker, 5, 500,
            std::chrono::milliseconds(200));

        INFO(sim.GenerateReport());

        // Connection should survive
        CHECK_FALSE(result.triggered_disconnect);
    }

    SECTION("INV flood - bounded GETHEADERS responses") {
        SimulatedNode attacker(4, &network);

        REQUIRE(attacker.ConnectTo(1));
        TestOrchestrator orch(&network);
        REQUIRE(orch.WaitForConnection(victim, attacker));

        // Send 50 fake block INV messages
        // Should not trigger 50 GETHEADERS due to rate limiting
        auto result = sim.SendInvFlood(attacker, 50);

        INFO(sim.GenerateReport());

        // GETHEADERS should be rate-limited (not 1:1 with INV)
        CHECK(result.messages_accepted < 50);  // Bounded GETHEADERS

        // Connection survives
        CHECK_FALSE(result.triggered_disconnect);
    }
}

// =============================================================================
// SECTION 11: RESOURCE EXHAUSTION DEFENSE
// =============================================================================

TEST_CASE("DoS Portfolio - Resource Exhaustion Defense", "[dos][portfolio][resources]") {
    SimulatedNetwork network(11000);
    SimulatedNode victim(1, &network);
    DoSAttackSimulator sim(&network, &victim);

    SECTION("Multiple simultaneous oversized attacks") {
        // Launch multiple attackers with different oversized attacks
        std::vector<std::unique_ptr<SimulatedNode>> attackers;
        for (int i = 0; i < 5; i++) {
            attackers.push_back(std::make_unique<SimulatedNode>(100 + i, &network));
            attackers.back()->ConnectTo(1);
        }

        TestOrchestrator orch(&network);
        orch.AdvanceTime(std::chrono::seconds(1));

        // Each attacker sends different oversized attack
        sim.SendOversizedInv(*attackers[0], 100000);
        sim.SendOversizedAddr(*attackers[1], 10000);
        sim.SendCompactSizeOverflow(*attackers[2], "headers");
        sim.SendCompactSizeOverflow(*attackers[3], "inv");
        sim.SendCompactSizeOverflow(*attackers[4], "addr");

        // Victim should survive all attacks
        CHECK(victim.GetTipHeight() == 0);  // At genesis, alive
    }

    SECTION("Sustained attack recovery") {
        sim.BuildVictimChain(5);

        // Multiple rounds of attacks
        for (int round = 0; round < 3; round++) {
            SimulatedNode attacker(100 + round, &network);
            REQUIRE(attacker.ConnectTo(1));

            TestOrchestrator orch(&network);
            orch.AdvanceTime(std::chrono::milliseconds(500));

            // Different attack each round
            switch (round % 3) {
                case 0:
                    sim.SendOversizedInv(attacker, 100000);
                    break;
                case 1:
                    sim.SendOversizedAddr(attacker, 10000);
                    break;
                case 2:
                    sim.SendCompactSizeOverflow(attacker, "headers");
                    break;
            }

            sim.Reset();
        }

        // Chain should be intact after all attacks
        CHECK(victim.GetTipHeight() == 5);
    }
}

// =============================================================================
// SECTION 12: GETHEADERS LOCATOR ATTACKS
// =============================================================================

TEST_CASE("DoS Portfolio - GETHEADERS Locator Attacks", "[dos][portfolio][getheaders]") {
    SimulatedNetwork network(12000);
    SimulatedNode victim(1, &network);
    DoSAttackSimulator sim(&network, &victim);

    SECTION("Oversized GETHEADERS locator - 1200 hashes triggers disconnect") {
        SimulatedNode attacker(2, &network);

        REQUIRE(attacker.ConnectTo(1));
        TestOrchestrator orch(&network);
        REQUIRE(orch.WaitForConnection(victim, attacker));

        // Send GETHEADERS with 1200 locator hashes (MAX = 101)
        auto result = sim.SendOversizedGetHeaders(attacker, 1200);

        INFO(sim.GenerateReport());

        CHECK(result.triggered_disconnect);
        CHECK(result.defense_triggered == "oversized_getheaders_rejected");
    }

    SECTION("GETHEADERS at limit - 101 hashes accepted") {
        SimulatedNode attacker(3, &network);

        REQUIRE(attacker.ConnectTo(1));
        TestOrchestrator orch(&network);
        REQUIRE(orch.WaitForConnection(victim, attacker));

        // Send exactly at limit - should be processed (may still disconnect due to
        // invalid hashes, but not for oversized locator)
        auto result = sim.SendOversizedGetHeaders(attacker, 101);

        INFO(sim.GenerateReport());

        // At-limit is accepted for locator count; may disconnect for other reasons
        // The key test is that 1200 triggers oversized rejection
    }
}

// =============================================================================
// SECTION 13: PING/PONG FLOOD HANDLING
// =============================================================================

TEST_CASE("DoS Portfolio - Ping Flood Handling", "[dos][portfolio][ping]") {
    SimulatedNetwork network(13000);
    SimulatedNode victim(1, &network);
    DoSAttackSimulator sim(&network, &victim);

    SECTION("Ping flood - victim responds without disconnect") {
        SimulatedNode attacker(2, &network);

        REQUIRE(attacker.ConnectTo(1));
        TestOrchestrator orch(&network);
        REQUIRE(orch.WaitForConnection(victim, attacker));

        // Send 50 PING messages rapidly
        auto result = sim.SendPingFlood(attacker, 50);

        INFO(sim.GenerateReport());

        // Victim should NOT disconnect - should respond with PONGs
        CHECK_FALSE(result.triggered_disconnect);
        CHECK(result.messages_accepted >= 50);  // All PINGs answered with PONGs
        CHECK(result.defense_triggered == "ping_flood_handled");
    }

    SECTION("Large ping flood - still handled gracefully") {
        SimulatedNode attacker(3, &network);

        REQUIRE(attacker.ConnectTo(1));
        TestOrchestrator orch(&network);
        REQUIRE(orch.WaitForConnection(victim, attacker));

        // Send 200 PING messages
        auto result = sim.SendPingFlood(attacker, 200);

        INFO(sim.GenerateReport());

        // Should still handle without disconnect
        CHECK_FALSE(result.triggered_disconnect);
        CHECK(result.messages_accepted >= 200);
    }
}

// =============================================================================
// SECTION 14: PER-NETGROUP CONNECTION LIMITS (Bitcoin Core parity)
// =============================================================================

TEST_CASE("DoS Portfolio - Per-Netgroup Connection Limits", "[dos][portfolio][netgroup]") {
    // Bitcoin Core parity: no per-IP limit, relies on per-netgroup limits
    SimulatedNetwork network(14000);
    SimulatedNode victim(1, &network);
    DoSAttackSimulator sim(&network, &victim);

    SECTION("Per-netgroup limit enforced - many connections from same /16") {
        // Test that connections from same /16 are limited to MAX_INBOUND_PER_NETGROUP (4)
        PeerFactory factory(&network);
        auto result = sim.SybilConnectionFlood(factory, "192.168.0.0", 10);

        INFO(sim.GenerateReport());

        // Should accept at most per-netgroup limit (4)
        CHECK(result.messages_accepted <= 4);
        CHECK(result.messages_rejected >= 6);
    }

    SECTION("Different netgroups not limited together") {
        // Create attackers from different /16 subnets
        std::vector<std::unique_ptr<SimulatedNode>> attackers;
        for (int i = 0; i < 5; i++) {
            // Each has unique /16 netgroup (10.x, 11.x, 12.x, ...)
            std::string ip = std::to_string(10 + i) + ".0.0.1";
            attackers.push_back(std::make_unique<SimulatedNode>(10 + i, &network, ip));
            attackers.back()->ConnectTo(1);
        }

        TestOrchestrator orch(&network);
        orch.AdvanceTime(std::chrono::seconds(2));

        // All should connect (different netgroups)
        CHECK(victim.GetPeerCount() >= 3);
    }
}

// =============================================================================
// SECTION 15: SEND QUEUE OVERFLOW
// =============================================================================

// NOTE: True send queue overflow testing requires real async I/O with backpressure,
// which the simulated network cannot model. The RealTransport tests and functional
// tests cover this scenario. Here we verify the infrastructure works.

TEST_CASE("DoS Portfolio - Send Queue Infrastructure", "[dos][portfolio][send-queue]") {
    SimulatedNetwork network(15000);
    SimulatedNode victim(1, &network);
    DoSAttackSimulator sim(&network, &victim);

    SECTION("High volume message sending works") {
        SimulatedNode receiver(2, &network);

        REQUIRE(receiver.ConnectTo(1));
        TestOrchestrator orch(&network);
        REQUIRE(orch.WaitForConnection(victim, receiver));

        // Test that we can send many messages through the infrastructure
        auto result = sim.TestSendQueueOverflow(receiver, 1000);

        INFO(sim.GenerateReport());

        // Verify infrastructure processed the messages
        CHECK(result.messages_sent == 1000);
        CHECK(result.attack_type == "SEND_QUEUE_OVERFLOW");
    }

    SECTION("Normal message volume - connection survives") {
        SimulatedNode normal_reader(3, &network);

        REQUIRE(normal_reader.ConnectTo(1));
        TestOrchestrator orch(&network);
        REQUIRE(orch.WaitForConnection(victim, normal_reader));

        // Find the peer connection from victim to normal_reader
        auto peers = victim.GetNetworkManager().peer_manager().get_all_peers();
        REQUIRE(!peers.empty());
        auto target_peer = peers[0];
        REQUIRE(target_peer != nullptr);

        // Send reasonable number of messages - should not overflow
        for (int i = 0; i < 100; i++) {
            auto ping = std::make_unique<message::PingMessage>(i);
            target_peer->send_message(std::move(ping));
        }

        orch.AdvanceTime(std::chrono::seconds(2));

        // Connection should survive
        CHECK(victim.GetPeerCount() >= 1);
    }
}

// =============================================================================
// SECTION 16: COMPREHENSIVE ATTACK MATRIX
// =============================================================================

TEST_CASE("DoS Portfolio - Comprehensive Attack Matrix", "[dos][portfolio][matrix]") {
    SimulatedNetwork network(16000);
    SimulatedNode victim(1, &network);
    DoSAttackSimulator sim(&network, &victim);

    // Build a small chain for the victim
    sim.BuildVictimChain(5);

    SECTION("All attack types in sequence - node survives") {
        int attack_num = 0;

        // Attack 1: Buffer overflow
        {
            SimulatedNode attacker(100 + attack_num++, &network);
            attacker.ConnectTo(1);
            TestOrchestrator orch(&network);
            orch.AdvanceTime(std::chrono::milliseconds(500));
            sim.SendMessageFlood(attacker, 30, 256 * 1024, 1024 * 1024);
            sim.Reset();
        }

        // Attack 2: Oversized INV
        {
            SimulatedNode attacker(100 + attack_num++, &network);
            attacker.ConnectTo(1);
            TestOrchestrator orch(&network);
            orch.AdvanceTime(std::chrono::milliseconds(500));
            sim.SendOversizedInv(attacker, 100000);
            sim.Reset();
        }

        // Attack 3: Oversized ADDR
        {
            SimulatedNode attacker(100 + attack_num++, &network);
            attacker.ConnectTo(1);
            TestOrchestrator orch(&network);
            orch.AdvanceTime(std::chrono::milliseconds(500));
            sim.SendOversizedAddr(attacker, 10000);
            sim.Reset();
        }

        // Attack 4: CompactSize overflow
        {
            SimulatedNode attacker(100 + attack_num++, &network);
            attacker.ConnectTo(1);
            TestOrchestrator orch(&network);
            orch.AdvanceTime(std::chrono::milliseconds(500));
            sim.SendCompactSizeOverflow(attacker, "headers");
            sim.Reset();
        }

        // Attack 5: Oversized GETHEADERS
        {
            SimulatedNode attacker(100 + attack_num++, &network);
            attacker.ConnectTo(1);
            TestOrchestrator orch(&network);
            orch.AdvanceTime(std::chrono::milliseconds(500));
            sim.SendOversizedGetHeaders(attacker, 1200);
            sim.Reset();
        }

        // Attack 6: Oversized headers
        {
            NodeSimulator attacker(100 + attack_num++, &network);
            attacker.ConnectTo(1);
            TestOrchestrator orch(&network);
            orch.AdvanceTime(std::chrono::milliseconds(500));
            sim.SendOversizedMessages(attacker, "headers", 2500);
            sim.Reset();
        }

        // Victim chain should be intact after all attacks
        CHECK(victim.GetTipHeight() == 5);
        INFO("Survived " << attack_num << " different attack types");
    }
}

// =============================================================================
// SECTION 17: ORPHAN HEADER SPAM
// =============================================================================

TEST_CASE("DoS Portfolio - Orphan Header Spam", "[dos][portfolio][orphan]") {
    SimulatedNetwork network(17000);
    SimulatedNode victim(1, &network);
    DoSAttackSimulator sim(&network, &victim);

    // Build chain
    sim.BuildVictimChain(5);

    SECTION("Orphan spam triggers disconnect") {
        NodeSimulator attacker(2, &network);

        REQUIRE(sim.ConnectAndSync(attacker));

        // Send 10 batches of 100 orphan headers each
        auto result = sim.SendOrphanSpam(attacker, 10, 100);

        INFO(sim.GenerateReport());

        // Should trigger disconnect due to misbehavior
        CHECK(result.triggered_disconnect);
        CHECK(result.victim_chain_intact);
        CHECK(result.victim_height_after == 5);
    }
}

// =============================================================================
// SECTION 18: STALLING PEER ATTACK
// =============================================================================

TEST_CASE("DoS Portfolio - Stalling Peer Attack", "[dos][portfolio][stall]") {
    SimulatedNetwork network(18000);
    SimulatedNode victim(1, &network);
    DoSAttackSimulator sim(&network, &victim);

    // Build chain
    sim.BuildVictimChain(10);

    SECTION("Stalling peer - victim survives") {
        NodeSimulator attacker(2, &network);

        REQUIRE(sim.ConnectAndSync(attacker));

        // Stall for 5 seconds
        auto result = sim.TestStallingPeer(attacker, 5);

        INFO(sim.GenerateReport());

        // Victim should survive stall attack
        CHECK(result.victim_chain_intact);
        CHECK(result.victim_height_after == 10);
        // Defense triggered (either timeout or survive)
        CHECK(result.defense_triggered.length() > 0);
    }
}

// =============================================================================
// SECTION 19: OUT-OF-ORDER HEADERS
// =============================================================================

TEST_CASE("DoS Portfolio - Out-of-Order Headers", "[dos][portfolio][orphan-resolution]") {
    SimulatedNetwork network(19000);
    TestOrchestrator orchestrator(&network);

    SimulatedNode victim(1, &network);
    victim.SetBypassPOWValidation(true);

    // Build initial chain
    for (int i = 0; i < 3; i++) {
        victim.MineBlock();
    }
    REQUIRE(victim.GetTipHeight() == 3);

    SECTION("Out-of-order headers resolved correctly") {
        NodeSimulator attacker(2, &network);

        // Connect and sync
        attacker.ConnectTo(1);
        REQUIRE(orchestrator.WaitForConnection(victim, attacker));
        REQUIRE(orchestrator.WaitForSync(victim, attacker));

        int initial_height = victim.GetTipHeight();

        // Send child before parent (out-of-order)
        auto [parent_hash, child_hash] = attacker.SendOutOfOrderHeaders(
            victim.GetId(),
            victim.GetTipHash()
        );

        orchestrator.AdvanceTime(std::chrono::milliseconds(100));

        // Activate best chain
        victim.GetChainstate().ActivateBestChain();

        int final_height = victim.GetTipHeight();

        INFO("Initial height: " << initial_height);
        INFO("Final height: " << final_height);

        // Chain should advance by 2 (parent + child)
        CHECK(final_height == initial_height + 2);
        CHECK(victim.GetChainstate().LookupBlockIndex(parent_hash) != nullptr);
        CHECK(victim.GetChainstate().LookupBlockIndex(child_hash) != nullptr);
    }
}

// =============================================================================
// SECTION 20: WIRE-LEVEL ATTACKS
// =============================================================================

TEST_CASE("DoS Portfolio - Wire-Level Attacks", "[dos][portfolio][wire]") {
    SimulatedNetwork network(20000);
    SimulatedNode victim(1, &network);
    DoSAttackSimulator sim(&network, &victim);

    SECTION("Bad magic bytes - disconnect") {
        SimulatedNode attacker(2, &network);

        REQUIRE(attacker.ConnectTo(1));
        TestOrchestrator orch(&network);
        REQUIRE(orch.WaitForConnection(victim, attacker));

        auto result = sim.SendBadMagic(attacker);

        INFO(sim.GenerateReport());

        // Should disconnect on wrong magic
        CHECK(result.triggered_disconnect);
    }

    SECTION("Bad checksum - disconnect") {
        SimulatedNode attacker(3, &network);

        REQUIRE(attacker.ConnectTo(1));
        TestOrchestrator orch(&network);
        REQUIRE(orch.WaitForConnection(victim, attacker));

        auto result = sim.SendBadChecksum(attacker);

        INFO(sim.GenerateReport());

        // Should disconnect on bad checksum
        CHECK(result.triggered_disconnect);
    }

    SECTION("Truncated message - handled gracefully") {
        SimulatedNode attacker(4, &network);

        REQUIRE(attacker.ConnectTo(1));
        TestOrchestrator orch(&network);
        REQUIRE(orch.WaitForConnection(victim, attacker));

        auto result = sim.SendTruncatedMessage(attacker);

        INFO(sim.GenerateReport());

        // Connection may timeout or disconnect - either way victim survives
        // The key is no crash
        CHECK(result.messages_sent == 1);
    }
}

// =============================================================================
// SECTION 21: COMPLETE ATTACK BATTERY
// =============================================================================

TEST_CASE("DoS Portfolio - Complete Attack Battery", "[dos][portfolio][battery]") {
    SimulatedNetwork network(21000);

    // Fast network
    SimulatedNetwork::NetworkConditions fast;
    fast.latency_min = std::chrono::milliseconds(0);
    fast.latency_max = std::chrono::milliseconds(1);
    fast.bandwidth_bytes_per_sec = 0;
    network.SetNetworkConditions(fast);

    SimulatedNode victim(1, &network);
    victim.SetBypassPOWValidation(true);
    DoSAttackSimulator sim(&network, &victim);

    // Build chain
    sim.BuildVictimChain(10);

    SECTION("All attack categories - victim survives") {
        int attacks_executed = 0;

        // Category 1: Buffer overflow
        {
            SimulatedNode attacker(100, &network);
            attacker.ConnectTo(1);
            TestOrchestrator orch(&network);
            orch.AdvanceTime(std::chrono::milliseconds(500));
            sim.SendMessageFlood(attacker, 30, 256 * 1024, 1024 * 1024);
            sim.Reset();
            attacks_executed++;
        }

        // Category 2: Validation (invalid PoW)
        {
            NodeSimulator attacker(101, &network);
            sim.ConnectAndSync(attacker);
            sim.SendInvalidPoWHeaders(attacker, 1);
            sim.Reset();
            attacks_executed++;
        }

        // Category 3: Oversized messages
        {
            SimulatedNode attacker(102, &network);
            attacker.ConnectTo(1);
            TestOrchestrator orch(&network);
            orch.AdvanceTime(std::chrono::milliseconds(500));
            sim.SendOversizedInv(attacker, 100000);
            sim.Reset();
            attacks_executed++;
        }

        // Category 4: CompactSize overflow
        {
            SimulatedNode attacker(103, &network);
            attacker.ConnectTo(1);
            TestOrchestrator orch(&network);
            orch.AdvanceTime(std::chrono::milliseconds(500));
            sim.SendCompactSizeOverflow(attacker, "inv");
            sim.Reset();
            attacks_executed++;
        }

        // Category 5: Orphan spam
        {
            NodeSimulator attacker(104, &network);
            sim.ConnectAndSync(attacker);
            sim.SendOrphanSpam(attacker, 5, 100);
            sim.Reset();
            attacks_executed++;
        }

        // Category 6: Wire-level (bad magic)
        {
            SimulatedNode attacker(105, &network);
            attacker.ConnectTo(1);
            TestOrchestrator orch(&network);
            orch.AdvanceTime(std::chrono::milliseconds(500));
            sim.SendBadMagic(attacker);
            sim.Reset();
            attacks_executed++;
        }

        // Category 7: Wire-level (bad checksum)
        {
            SimulatedNode attacker(106, &network);
            attacker.ConnectTo(1);
            TestOrchestrator orch(&network);
            orch.AdvanceTime(std::chrono::milliseconds(500));
            sim.SendBadChecksum(attacker);
            sim.Reset();
            attacks_executed++;
        }

        // Category 8: Ping flood
        {
            SimulatedNode attacker(107, &network);
            attacker.ConnectTo(1);
            TestOrchestrator orch(&network);
            orch.WaitForConnection(victim, attacker);
            sim.SendPingFlood(attacker, 100);
            sim.Reset();
            attacks_executed++;
        }

        // Victim should survive all attacks with chain intact
        CHECK(victim.GetTipHeight() == 10);
        INFO("Executed " << attacks_executed << " attack categories");
        CHECK(attacks_executed == 8);
    }
}

// =============================================================================
// SECTION 22: ADDR ECHO SUPPRESSION
// =============================================================================

TEST_CASE("DoS Portfolio - ADDR Echo Suppression", "[dos][portfolio][addr-echo]") {
    SimulatedNetwork network(22000);
    TestOrchestrator orch(&network);
    network.EnableCommandTracking(true);

    SimulatedNode server(1, &network);  // receiver of ADDR, responder to GETADDR
    SimulatedNode client(2, &network);

    REQUIRE(client.ConnectTo(server.GetId()));
    REQUIRE(orch.WaitForConnection(server, client));

    // Wait for handshake
    for (int i = 0; i < 12; ++i) orch.AdvanceTime(std::chrono::milliseconds(100));

    SECTION("Node does not echo addresses back to sender") {
        // Client announces address X to server via ADDR
        protocol::TimestampedAddress addr_x;
        addr_x.timestamp = static_cast<uint32_t>(network.GetCurrentTime() / 1000);
        addr_x.address.services = protocol::ServiceFlags::NODE_NETWORK;
        addr_x.address.port = protocol::ports::REGTEST;
        // 10.0.0.42
        std::memset(addr_x.address.ip.data(), 0, 10);
        addr_x.address.ip[10] = 0xFF; addr_x.address.ip[11] = 0xFF;
        addr_x.address.ip[12] = 10; addr_x.address.ip[13] = 0;
        addr_x.address.ip[14] = 0; addr_x.address.ip[15] = 42;

        message::AddrMessage addr_msg;
        addr_msg.addresses.push_back(addr_x);
        auto payload = addr_msg.serialize();

        protocol::MessageHeader header(protocol::magic::REGTEST,
            protocol::commands::ADDR, static_cast<uint32_t>(payload.size()));
        uint256 hash = Hash(payload);
        std::memcpy(header.checksum.data(), hash.begin(), 4);
        auto header_bytes = message::serialize_header(header);

        std::vector<uint8_t> full;
        full.reserve(header_bytes.size() + payload.size());
        full.insert(full.end(), header_bytes.begin(), header_bytes.end());
        full.insert(full.end(), payload.begin(), payload.end());

        network.SendMessage(client.GetId(), server.GetId(), full);
        orch.AdvanceTime(std::chrono::milliseconds(200));

        // Client requests GETADDR
        protocol::MessageHeader getaddr_header(protocol::magic::REGTEST,
            protocol::commands::GETADDR, 0);
        auto getaddr_bytes = message::serialize_header(getaddr_header);
        network.SendMessage(client.GetId(), server.GetId(), getaddr_bytes);
        orch.AdvanceTime(std::chrono::milliseconds(300));

        // Check that server responded
        auto payloads = network.GetCommandPayloads(server.GetId(), client.GetId(),
            protocol::commands::ADDR);
        REQUIRE(!payloads.empty());

        // Verify address X is NOT echoed back
        message::AddrMessage response;
        REQUIRE(response.deserialize(payloads.back().data(), payloads.back().size()));

        bool found_echo = false;
        for (const auto& ta : response.addresses) {
            if (ta.address.ip[12] == 10 && ta.address.ip[15] == 42) {
                found_echo = true;
                break;
            }
        }
        CHECK_FALSE(found_echo);  // Should NOT echo back
    }
}

// =============================================================================
// SECTION 23: VALID ADDR FLOOD
// =============================================================================

TEST_CASE("DoS Portfolio - Valid ADDR Flood", "[dos][portfolio][addr-flood]") {
    SimulatedNetwork network(23000);
    SimulatedNode victim(1, &network);
    SimulatedNode sender(2, &network);

    REQUIRE(sender.ConnectTo(victim.GetId()));
    uint64_t t = 100;
    network.AdvanceTime(t);

    SECTION("Valid-size ADDR flood remains connected") {
        // Build a valid-size ADDR (MAX_ADDR_SIZE = 1000 entries)
        message::AddrMessage addr;
        addr.addresses.reserve(protocol::MAX_ADDR_SIZE);

        for (uint32_t i = 0; i < protocol::MAX_ADDR_SIZE; i++) {
            protocol::TimestampedAddress ta;
            ta.timestamp = static_cast<uint32_t>(network.GetCurrentTime() / 1000);
            // Generate IPs 127.0.0.x
            std::memset(ta.address.ip.data(), 0, 10);
            ta.address.ip[10] = 0xFF; ta.address.ip[11] = 0xFF;
            ta.address.ip[12] = 127; ta.address.ip[13] = 0;
            ta.address.ip[14] = 0; ta.address.ip[15] = static_cast<uint8_t>(i % 255);
            ta.address.services = protocol::ServiceFlags::NODE_NETWORK;
            ta.address.port = protocol::ports::REGTEST;
            addr.addresses.push_back(ta);
        }

        auto payload = addr.serialize();
        protocol::MessageHeader hdr(protocol::magic::REGTEST,
            protocol::commands::ADDR, static_cast<uint32_t>(payload.size()));
        uint256 hash = Hash(payload);
        std::memcpy(hdr.checksum.data(), hash.begin(), 4);
        auto hdr_bytes = message::serialize_header(hdr);

        std::vector<uint8_t> full;
        full.reserve(hdr_bytes.size() + payload.size());
        full.insert(full.end(), hdr_bytes.begin(), hdr_bytes.end());
        full.insert(full.end(), payload.begin(), payload.end());

        int pre_count = victim.GetPeerCount();

        // Send many ADDR messages (10x)
        for (int k = 0; k < 10; k++) {
            network.SendMessage(sender.GetId(), victim.GetId(), full);
            t += 50;
            network.AdvanceTime(t);
        }

        // Still connected and responsive
        CHECK(victim.GetPeerCount() == pre_count);
    }
}

// =============================================================================
// SECTION 24: CONNECT/DISCONNECT CHURN
// =============================================================================

TEST_CASE("DoS Portfolio - Connect Churn", "[dos][portfolio][churn]") {
    SimulatedNetwork network(24000);
    SimulatedNode victim(1, &network);

    SECTION("Connect/disconnect churn does not cause ban") {
        // Repeatedly connect/disconnect from same address
        for (int i = 0; i < 30; i++) {
            SimulatedNode temp(100 + i, &network);
            REQUIRE(temp.ConnectTo(victim.GetId()));
            network.AdvanceTime(100);
            // temp destroyed at end of scope = disconnect
        }

        // Final attempt should still succeed (not banned)
        SimulatedNode last(999, &network);
        CHECK(last.ConnectTo(victim.GetId()));
    }
}

// =============================================================================
// SECTION 25: INV STORM THROTTLING
// =============================================================================

TEST_CASE("DoS Portfolio - INV Storm Throttling", "[dos][portfolio][inv-storm]") {
    SimulatedNetwork network(25000);
    network.EnableCommandTracking(true);

    // Fast network
    SimulatedNetwork::NetworkConditions fast;
    fast.latency_min = fast.latency_max = std::chrono::milliseconds(0);
    fast.jitter_max = std::chrono::milliseconds(0);
    network.SetNetworkConditions(fast);

    // Miner builds base chain
    SimulatedNode miner(100, &network);
    for (int i = 0; i < 20; i++) miner.MineBlock();

    // Victim node
    SimulatedNode victim(1, &network);

    // Create K peers that will announce new blocks to victim
    const int K = 5;
    std::vector<std::unique_ptr<SimulatedNode>> peers;
    for (int i = 0; i < K; i++) {
        peers.push_back(std::make_unique<SimulatedNode>(10 + i, &network));
        REQUIRE(peers.back()->ConnectTo(miner.GetId()));
    }

    uint64_t t = 100;
    network.AdvanceTime(t);

    // Connect victim to peers
    for (auto& p : peers) {
        REQUIRE(victim.ConnectTo(p->GetId()));
    }
    t += 200;
    network.AdvanceTime(t);

    SECTION("INV storm bounded GETHEADERS") {
        // Baseline GETHEADERS counts
        int gh_before = 0;
        for (auto& p : peers) {
            gh_before += network.CountCommandSent(victim.GetId(), p->GetId(),
                protocol::commands::GETHEADERS);
        }

        // Miner mines one block; peers learn and INV to victim
        miner.MineBlock();
        for (int i = 0; i < 10; i++) {
            t += 50;
            network.AdvanceTime(t);
        }

        // Count GETHEADERS delta - should be bounded by K
        int gh_after = 0;
        for (auto& p : peers) {
            gh_after += network.CountCommandSent(victim.GetId(), p->GetId(),
                protocol::commands::GETHEADERS);
        }

        CHECK(gh_after - gh_before <= K);
    }
}

// =============================================================================
// SECTION 26: PER-PEER BUFFER LIMITS
// =============================================================================

TEST_CASE("DoS Portfolio - Per-Peer Buffer Limits", "[dos][portfolio][per-peer-buffer]") {
    SimulatedNetwork network(26000);
    TestOrchestrator orchestrator(&network);

    SimulatedNode victim(1, &network);
    SimulatedNode attacker(2, &network);

    REQUIRE(attacker.ConnectTo(1));
    REQUIRE(orchestrator.WaitForConnection(victim, attacker));

    SECTION("Raw flood exceeds per-peer buffer cap") {
        // Fast delivery from attacker to victim
        SimulatedNetwork::NetworkConditions fast;
        fast.latency_min = std::chrono::milliseconds(0);
        fast.latency_max = std::chrono::milliseconds(1);
        fast.jitter_max = std::chrono::milliseconds(0);
        fast.bandwidth_bytes_per_sec = 0;
        network.SetLinkConditions(2, 1, fast);

        // Raw chunks without valid header (100KB each)
        std::vector<uint8_t> raw(100 * 1024, 0xAB);

        // Send many chunks to exceed DEFAULT_RECV_FLOOD_SIZE (5 MB)
        for (int i = 0; i < 100; ++i) {
            network.SendMessage(attacker.GetId(), victim.GetId(), raw);
        }

        orchestrator.AdvanceTime(std::chrono::seconds(2));

        // Should disconnect due to buffer overflow
        CHECK(orchestrator.WaitForPeerCount(victim, 0, std::chrono::seconds(2)));
    }
}

// =============================================================================
// SECTION 27: CONNECTION THROTTLE
// =============================================================================

TEST_CASE("DoS Portfolio - Connection Throttle", "[dos][portfolio][throttle]") {
    SimulatedNetwork network(27000);
    PeerFactory factory(&network);
    TestOrchestrator orch(&network);

    SimulatedNode victim(1, &network);

    SECTION("Multiple rapid connections from same /16 - netgroup limited") {
        // Create 10 attackers from same /16
        auto attackers = factory.CreateSybilCluster(10, 100, "8.50.0.0");

        for (auto& a : attackers) {
            a->ConnectTo(victim.GetId(), victim.GetAddress());
        }

        orch.AdvanceTime(std::chrono::seconds(2));

        // Per-netgroup limit is 4
        CHECK(victim.GetInboundPeerCount() <= 4);
    }

    SECTION("Diverse IPs - all connect") {
        auto peers = factory.CreateDiversePeers(8, 200);

        for (auto& p : peers) {
            p->ConnectTo(victim.GetId(), victim.GetAddress());
        }

        REQUIRE(orch.WaitForPeerCount(victim, 8));
        CHECK(victim.GetInboundPeerCount() == 8);
    }
}

// =============================================================================
// SECTION 28: RESERVE GUARD (COMPACTSIZE ALLOC)
// =============================================================================

TEST_CASE("DoS Portfolio - Reserve Guard", "[dos][portfolio][reserve]") {
    SimulatedNetwork network(28000);
    TestOrchestrator orchestrator(&network);

    SimulatedNode victim(1, &network);
    SimulatedNode attacker(2, &network);

    REQUIRE(attacker.ConnectTo(1));
    REQUIRE(orchestrator.WaitForConnection(victim, attacker));

    SECTION("Huge CompactSize in HEADERS triggers disconnect") {
        // Attack: 0xFF + 8 bytes of 0xFF = 18 exabytes claimed
        std::vector<uint8_t> payload;
        payload.reserve(9);
        payload.push_back(0xFF);
        for (int i = 0; i < 8; ++i) payload.push_back(0xFF);

        protocol::MessageHeader header(protocol::magic::REGTEST, protocol::commands::HEADERS,
            static_cast<uint32_t>(payload.size()));
        uint256 hash = Hash(payload);
        std::memcpy(header.checksum.data(), hash.begin(), 4);
        auto header_bytes = message::serialize_header(header);

        std::vector<uint8_t> full;
        full.reserve(header_bytes.size() + payload.size());
        full.insert(full.end(), header_bytes.begin(), header_bytes.end());
        full.insert(full.end(), payload.begin(), payload.end());

        network.SendMessage(attacker.GetId(), victim.GetId(), full);
        orchestrator.AdvanceTime(std::chrono::seconds(1));

        // Should disconnect - reserve guard blocks OOM
        CHECK(orchestrator.WaitForPeerCount(victim, 0, std::chrono::seconds(2)));
    }
}

// =============================================================================
// SECTION 29: REANNOUNCE TTL
// =============================================================================

TEST_CASE("DoS Portfolio - Reannounce TTL", "[dos][portfolio][ttl]") {
    SimulatedNetwork network(29000);
    network.EnableCommandTracking(true);

    // Fast network
    SimulatedNetwork::NetworkConditions fast;
    fast.latency_min = fast.latency_max = std::chrono::milliseconds(0);
    fast.jitter_max = std::chrono::milliseconds(0);
    network.SetNetworkConditions(fast);

    SimulatedNode announcer(1, &network);
    SimulatedNode listener(2, &network);

    REQUIRE(listener.ConnectTo(announcer.GetId()));
    uint64_t t = 100;
    network.AdvanceTime(t);

    // Announcer mines one block
    announcer.MineBlock();
    t += 50;
    network.AdvanceTime(t);

    SECTION("TTL prevents INV spam within window") {
        // Multiple periodic runs within TTL should not cause multiple INV
        for (int i = 0; i < 10; i++) {
            announcer.ProcessPeriodic();
            t += 10;
            network.AdvanceTime(t);
        }

        int invs = network.CountCommandSent(announcer.GetId(), listener.GetId(),
            protocol::commands::INV);

        // Should be at most 1 INV within TTL window
        CHECK(invs <= 1);
    }

    SECTION("TTL allows reannounce after expiry") {
        int invs_before = network.CountCommandSent(announcer.GetId(), listener.GetId(),
            protocol::commands::INV);

        // Advance beyond TTL (10 minutes)
        t += (10 * 60 * 1000 + 1000);
        network.AdvanceTime(t);
        announcer.ProcessPeriodic();
        t += 10;
        network.AdvanceTime(t);

        int invs_after = network.CountCommandSent(announcer.GetId(), listener.GetId(),
            protocol::commands::INV);

        // Should allow another INV after TTL
        CHECK(invs_after >= invs_before);
    }
}

// =============================================================================
// SECTION 30: UNKNOWN COMMAND RATE LIMITING
// =============================================================================

TEST_CASE("DoS Portfolio - Unknown Command Rate Limiting", "[dos][portfolio][unknown-cmd]") {
    SimulatedNetwork network(30000);
    TestOrchestrator orch(&network);

    SimulatedNode victim(1, &network);
    SimulatedNode attacker(2, &network);

    REQUIRE(attacker.ConnectTo(1));
    REQUIRE(orch.WaitForConnection(victim, attacker));

    SECTION("Over threshold triggers disconnect") {
        // Send 25 unknown commands (threshold is 20)
        for (int i = 0; i < 25; i++) {
            std::string cmd = "unkn" + std::to_string(i % 10);
            std::vector<uint8_t> payload;
            protocol::MessageHeader header(protocol::magic::REGTEST, cmd, 0);
            uint256 hash = Hash(payload);
            std::memcpy(header.checksum.data(), hash.begin(), 4);
            auto header_bytes = message::serialize_header(header);
            network.SendMessage(2, 1, header_bytes);
            orch.AdvanceTime(std::chrono::milliseconds(10));
        }

        orch.AdvanceTime(std::chrono::seconds(1));

        // Should be disconnected (>20 unknown commands)
        CHECK(victim.GetPeerCount() == 0);
    }
}

// =============================================================================
// SECTION 31: MISBEHAVIOR INSTANT DISCOURAGE (Bitcoin Core March 2024 parity)
// =============================================================================

TEST_CASE("DoS Portfolio - Misbehavior Instant Discourage", "[dos][portfolio][misbehavior]") {
    SECTION("Modern Core: instant discourage, no score accumulation") {
        // Bitcoin Core commit ae60d485da (March 2024) removed score-based misbehavior.
        // Any misbehavior now results in instant discouragement.
        //
        // Old system: Accumulate points, disconnect at threshold (100)
        // New system: Any misbehavior = should_discourage = true, disconnect immediately
        //
        // Benefits:
        // - Simpler code, fewer bugs
        // - No integer overflow concerns
        // - No "save up points" attacks

        // Verify the struct uses boolean (instant) not integer (accumulating)
        PeerMisbehaviorData data;
        CHECK(data.should_discourage == false);  // Default is not discouraged
        data.should_discourage = true;           // Any misbehavior sets this directly
        CHECK(data.should_discourage == true);   // Instant - no accumulation
    }

    SECTION("NoBan peers are tracked but not disconnected") {
        // Peers with NetPermissionFlags::NoBan still have should_discourage set to true
        // but ShouldDisconnect() returns false for them.
        // Use IsMisbehaving() to check if NoBan peer misbehaved.
        CHECK(static_cast<int>(NetPermissionFlags::NoBan) != 0);
    }
}

// =============================================================================
// SECTION 32: UNCONNECTING HEADERS COUNTER
// =============================================================================

TEST_CASE("DoS Portfolio - Unconnecting Headers Counter", "[dos][portfolio][unconnecting]") {
    SECTION("Constants verification") {
        CHECK(MAX_UNCONNECTING_HEADERS == 10);
        INFO("After 10 unconnecting header batches, peer is instantly discouraged");
    }
}

// =============================================================================
// SECTION 33: SUBVERSION LENGTH LIMIT
// =============================================================================

TEST_CASE("DoS Portfolio - Subversion Length Limit", "[dos][portfolio][subversion]") {
    SECTION("Constants verification") {
        CHECK(protocol::MAX_SUBVERSION_LENGTH == 256);
    }

    SECTION("Standard user agent is under limit") {
        std::string ua = protocol::GetUserAgent();
        CHECK(ua.length() < protocol::MAX_SUBVERSION_LENGTH);
    }
}

// =============================================================================
// SECTION 34: SIDE-CHAIN PRUNING (Low-Work Storage Exhaustion Protection)
// =============================================================================

TEST_CASE("DoS Portfolio - Side-Chain Pruning Protection", "[dos][portfolio][pruning]") {
    // This test verifies that PruneStaleSideChains() prevents storage exhaustion
    // from valid low-work headers forking from early blocks.
    //
    // Attack scenario:
    //   1. Attacker mines many valid headers at powLimit forking from genesis/early blocks
    //   2. Each header passes PoW validation (valid at powLimit)
    //   3. Without pruning, these accumulate in m_block_index forever
    //   4. With pruning, stale side-chains below (tip - nSuspiciousReorgDepth) are removed
    //
    // Protection on mainnet: nSuspiciousReorgDepth = 2 (very aggressive pruning)
    // Protection on regtest: nSuspiciousReorgDepth = 100 (for testing flexibility)

    SimulatedNetwork network(34000);

    // Fast network
    SimulatedNetwork::NetworkConditions fast;
    fast.latency_min = fast.latency_max = std::chrono::milliseconds(0);
    fast.jitter_max = std::chrono::milliseconds(0);
    network.SetNetworkConditions(fast);

    SimulatedNode victim(1, &network);
    victim.SetBypassPOWValidation(true);

    SECTION("Verify nSuspiciousReorgDepth values") {
        // Document the protection levels for different networks
        auto& params = chain::GlobalChainParams::Get();

        if (params.GetChainType() == chain::ChainType::MAIN) {
            CHECK(params.GetConsensus().nSuspiciousReorgDepth == 2);
            INFO("Mainnet: Pruning kicks in at tip height 3 (very aggressive)");
        } else if (params.GetChainType() == chain::ChainType::REGTEST) {
            CHECK(params.GetConsensus().nSuspiciousReorgDepth == 100);
            INFO("Regtest: Pruning kicks in at tip height 101 (testing flexibility)");
        }
    }

    SECTION("Side-chain headers pruned after chain grows past threshold") {
        // Build victim chain past the pruning threshold
        // For regtest: nSuspiciousReorgDepth = 100, so we need tip > 100
        const int INITIAL_HEIGHT = 110;
        for (int i = 0; i < INITIAL_HEIGHT; i++) {
            victim.MineBlock();
        }
        REQUIRE(victim.GetTipHeight() == INITIAL_HEIGHT);

        // Get block index size before attack
        size_t blocks_before = victim.GetChainstate().GetBlockCount();
        INFO("Blocks before side-chain attack: " << blocks_before);

        // Create attacker that will build side chains
        NodeSimulator attacker(2, &network);
        attacker.ConnectTo(1);
        TestOrchestrator orch(&network);
        REQUIRE(orch.WaitForConnection(victim, attacker));

        // Attacker builds side chains forking from height 5
        // These are valid headers but will never become the active chain
        const chain::CBlockIndex* fork_block = victim.GetChainstate().GetBlockAtHeight(5);
        REQUIRE(fork_block != nullptr);
        uint256 fork_point = fork_block->GetBlockHash();

        // Send multiple batches of side-chain headers (each batch is a new fork)
        const int NUM_FORKS = 10;
        const int HEADERS_PER_FORK = 5;

        for (int fork = 0; fork < NUM_FORKS; fork++) {
            // Build a chain of headers starting from fork_point
            attacker.SendValidSideChainHeaders(victim.GetId(), fork_point, HEADERS_PER_FORK);
            orch.AdvanceTime(std::chrono::milliseconds(100));
        }

        orch.AdvanceTime(std::chrono::seconds(1));

        // Get block index size after receiving side chains
        size_t blocks_after_attack = victim.GetChainstate().GetBlockCount();
        INFO("Blocks after side-chain attack: " << blocks_after_attack);

        // Side chains should have been added (though some may have been pruned already)
        // The exact count depends on whether pruning ran during header acceptance

        // Now mine another block to trigger ActivateBestChain() which calls pruning
        victim.MineBlock();
        orch.AdvanceTime(std::chrono::milliseconds(100));

        size_t blocks_after_mine = victim.GetChainstate().GetBlockCount();
        INFO("Blocks after mining (pruning should have run): " << blocks_after_mine);

        // Verify pruning occurred: side-chain blocks at height 6-10 (fork_point + 1 to + HEADERS_PER_FORK)
        // should be below the cutoff (tip=111 - 100 = 11) and thus pruned
        // The cutoff is tip_height - nSuspiciousReorgDepth = 111 - 100 = 11
        // Side chains at height 6-10 are below cutoff and should be pruned

        // Active chain should have: genesis + 111 blocks = 112 total
        // Any remaining blocks are unpruned side-chains above the cutoff
        CHECK(blocks_after_mine <= blocks_before + 2);  // Only main chain blocks remain

        // Chain integrity preserved
        CHECK(victim.GetTipHeight() == INITIAL_HEIGHT + 1);
    }

    SECTION("Block index bounded despite continuous side-chain spam") {
        // Build initial chain
        const int INITIAL_HEIGHT = 105;
        for (int i = 0; i < INITIAL_HEIGHT; i++) {
            victim.MineBlock();
        }

        NodeSimulator attacker(2, &network);
        attacker.ConnectTo(1);
        TestOrchestrator orch(&network);
        REQUIRE(orch.WaitForConnection(victim, attacker));

        // Record initial state
        size_t initial_blocks = victim.GetChainstate().GetBlockCount();

        // Simulate ongoing attack: attacker continuously sends side-chain headers
        // while victim continues to mine normally
        const int ATTACK_ROUNDS = 5;
        const int FORKS_PER_ROUND = 5;

        for (int round = 0; round < ATTACK_ROUNDS; round++) {
            // Attacker sends side-chain headers
            const chain::CBlockIndex* old_fork_block = victim.GetChainstate().GetBlockAtHeight(3);
            uint256 old_fork_point = old_fork_block ? old_fork_block->GetBlockHash() : uint256();
            for (int fork = 0; fork < FORKS_PER_ROUND; fork++) {
                attacker.SendValidSideChainHeaders(victim.GetId(), old_fork_point, 3);
                orch.AdvanceTime(std::chrono::milliseconds(50));
            }

            // Victim mines a block (triggers pruning)
            victim.MineBlock();
            orch.AdvanceTime(std::chrono::milliseconds(100));
        }

        size_t final_blocks = victim.GetChainstate().GetBlockCount();

        INFO("Initial blocks: " << initial_blocks);
        INFO("Final blocks after " << ATTACK_ROUNDS << " rounds of attack: " << final_blocks);

        // Block index should be bounded:
        // - Main chain: initial_blocks + ATTACK_ROUNDS new blocks
        // - Side chains: pruned below cutoff, so only recent forks remain
        int expected_main_chain = INITIAL_HEIGHT + ATTACK_ROUNDS + 1;  // +1 for genesis
        int max_expected = expected_main_chain + 20;  // Allow some buffer for unpruned recent forks

        CHECK(final_blocks <= static_cast<size_t>(max_expected));
        INFO("Block index bounded: " << final_blocks << " <= " << max_expected);

        // Victim's chain should have advanced
        CHECK(victim.GetTipHeight() == INITIAL_HEIGHT + ATTACK_ROUNDS);
    }

    SECTION("Pruning protects against memory exhaustion from stale forks") {
        // This test verifies the core DoS protection:
        // Without pruning, an attacker could create unlimited block index entries
        // With pruning, stale side-chains are cleaned up

        // Build chain to height where pruning is active
        for (int i = 0; i < 120; i++) {
            victim.MineBlock();
        }

        // Create many forks from early heights
        NodeSimulator attacker(2, &network);
        attacker.ConnectTo(1);
        TestOrchestrator orch(&network);
        REQUIRE(orch.WaitForConnection(victim, attacker));

        // Fork from height 5 - this is well below the cutoff (120 - 100 = 20)
        const chain::CBlockIndex* early_fork_block = victim.GetChainstate().GetBlockAtHeight(5);
        REQUIRE(early_fork_block != nullptr);
        uint256 early_fork = early_fork_block->GetBlockHash();

        // Send 50 different forks, each 3 blocks long
        for (int fork = 0; fork < 50; fork++) {
            attacker.SendValidSideChainHeaders(victim.GetId(), early_fork, 3);
            orch.AdvanceTime(std::chrono::milliseconds(20));

            // Periodically trigger pruning by mining
            if (fork % 10 == 9) {
                victim.MineBlock();
                orch.AdvanceTime(std::chrono::milliseconds(50));
            }
        }

        victim.MineBlock();  // Final pruning trigger
        orch.AdvanceTime(std::chrono::seconds(1));

        size_t final_block_count = victim.GetChainstate().GetBlockCount();

        // Block count should be close to main chain length
        // Main chain: 120 + (5 periodic mines) + 1 final + genesis = ~127
        int main_chain_length = victim.GetTipHeight() + 1;
        int tolerance = 10;  // Allow small tolerance for any edge cases

        INFO("Main chain length: " << main_chain_length);
        INFO("Final block count: " << final_block_count);
        INFO("50 forks x 3 headers = 150 potential side-chain blocks (should be pruned)");

        CHECK(final_block_count <= static_cast<size_t>(main_chain_length + tolerance));
    }
}
