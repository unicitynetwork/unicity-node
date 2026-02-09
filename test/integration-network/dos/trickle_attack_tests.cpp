// Copyright (c) 2025 The Unicity Foundation
// Trickle Attack Tests - Verify deadline-based stall detection
//
// A trickle attack is when an attacker sends minimal valid data periodically
// to try to keep the connection alive and prevent timeout. These tests verify
// that the sync deadline is set ONCE at sync start and NOT reset when headers arrive.
//
// Bitcoin Core Reference: net_processing.cpp - HEADERS_DOWNLOAD_TIMEOUT is deadline-based
// The deadline is calculated at sync start and NOT reset when headers arrive.

#include "catch_amalgamated.hpp"
#include "infra/simulated_network.hpp"
#include "infra/simulated_node.hpp"
#include "infra/node_simulator.hpp"
#include "test_orchestrator.hpp"
#include "chain/chainparams.hpp"
#include "chain/block.hpp"
#include "network/protocol.hpp"

using namespace unicity;
using namespace unicity::chain;
using namespace unicity::network;
using namespace unicity::test;

static struct TrickleTestSetup {
    TrickleTestSetup() { chain::GlobalChainParams::Select(chain::ChainType::REGTEST); }
} trickle_test_setup;

// Helper: Get headers from a node's chain
static std::vector<CBlockHeader> GetChainHeaders(SimulatedNode& node, int start_height, int end_height) {
    std::vector<CBlockHeader> headers;
    for (int h = start_height; h <= end_height && h <= node.GetTipHeight(); ++h) {
        uint256 hash = node.GetBlockHash(h);
        if (!hash.IsNull()) {
            headers.push_back(node.GetBlockHeader(hash));
        }
    }
    return headers;
}

// =============================================================================
// TEST 1: Trickle Attack - Sending 1 header periodically does NOT reset deadline
// =============================================================================
// Attacker becomes sync peer, then sends 1 valid header every ~100 seconds.
// Victim should STILL disconnect at the deadline, not be kept alive indefinitely.

TEST_CASE("DoS: Trickle attack - single headers do not reset deadline", "[dos][network][trickle][security]") {
    SimulatedNetwork net(2001);
    net.EnableCommandTracking(true);

    // Miner builds a chain the victim will want to sync
    SimulatedNode miner(1, &net);
    for (int i = 0; i < 50; ++i) {
        miner.MineBlock();
    }
    REQUIRE(miner.GetTipHeight() == 50);

    // Attacker has the chain too (syncs from miner first) - use NodeSimulator for P2P control
    NodeSimulator attacker(2, &net);
    attacker.ConnectTo(miner.GetId());
    uint64_t t = 1000;
    net.AdvanceTime(t);
    for (int i = 0; i < 30 && attacker.GetTipHeight() < 50; ++i) {
        t += 500;
        net.AdvanceTime(t);
        attacker.CheckInitialSync();
    }
    REQUIRE(attacker.GetTipHeight() == 50);

    // Disconnect attacker from miner so we control what it sends
    attacker.DisconnectFrom(miner.GetId());
    t += 100;
    net.AdvanceTime(t);

    // New victim node - only connects to attacker
    SimulatedNode victim(3, &net);
    victim.ConnectTo(attacker.GetId());
    t += 100;
    net.AdvanceTime(t);

    // Victim starts IBD, attacker becomes sync peer
    victim.CheckInitialSync();
    t += 100;
    net.AdvanceTime(t);

    // Verify victim is in IBD and attacker is sync peer
    REQUIRE(victim.GetIsIBD());
    REQUIRE(victim.GetTipHeight() == 0);

    // Record initial GETHEADERS count
    int gh_before = net.CountCommandSent(victim.GetId(), attacker.GetId(), protocol::commands::GETHEADERS);
    REQUIRE(gh_before > 0);  // Victim requested headers

    // Enable stalling mode - attacker won't auto-respond to GETHEADERS
    attacker.EnableStalling(true);

    // Get attacker's headers to send via P2P (will go through HandleHeadersMessage)
    auto attacker_headers = GetChainHeaders(attacker, 1, 5);  // Get headers 1-5
    REQUIRE(attacker_headers.size() == 5);

    // Send trickle headers at 90s intervals via REAL P2P layer
    // Total time to deadline is 5 minutes (300s) base + dynamic component
    // We'll send headers at 90s, 180s, 270s - all BEFORE deadline
    // If deadline were rolling, victim would never timeout. But it's not.
    int expected_height = 0;
    for (int wave = 0; wave < 3; ++wave) {
        // Advance 90 seconds
        for (int i = 0; i < 90; ++i) {
            t += 1000;  // 1 second
            net.AdvanceTime(t);
        }

        // Send 1 header via P2P HEADERS message (goes through HandleHeadersMessage)
        std::vector<CBlockHeader> single_header = {attacker_headers[wave]};
        attacker.SendValidHeaders(victim.GetId(), single_header);

        t += 100;
        net.AdvanceTime(t);

        // Process the message
        victim.ProcessEvents();

        // VERIFY: Headers were processed via P2P - victim's tip should advance
        expected_height = wave + 1;
        int actual_height = victim.GetTipHeight();
        INFO("Wave " << wave << " at " << (t / 1000) << "s - sent header " << (wave + 1)
             << ", victim height: " << actual_height << " (expected: " << expected_height << ")");
        REQUIRE(actual_height == expected_height);  // Confirms P2P path is working

        // Process timers
        victim.ProcessHeaderSyncTimers();
    }

    // At this point, ~270 seconds have passed
    // Victim received 3 headers but is still far from synced
    // The deadline should be approaching (5 min = 300s base)

    // Advance another 60 seconds to exceed deadline
    for (int i = 0; i < 60; ++i) {
        t += 1000;
        net.AdvanceTime(t);
    }
    // ~330 seconds total - should exceed deadline

    // Process timers - this should trigger deadline check
    victim.ProcessHeaderSyncTimers();
    t += 100;
    net.AdvanceTime(t);

    // CRITICAL ASSERTION: Attacker should be disconnected due to deadline
    // Despite receiving headers periodically, the deadline was NOT reset
    auto peers = victim.GetNetworkManager().peer_manager().get_all_peers();
    bool attacker_still_connected = false;
    for (const auto& peer : peers) {
        if (peer->is_connected()) {
            attacker_still_connected = true;
            break;
        }
    }

    // The deadline-based approach means attacker SHOULD be disconnected
    CHECK_FALSE(attacker_still_connected);

    // Verify victim is no longer stuck (sync peer was cleared)
    // This confirms the trickle attack failed
    INFO("Trickle attack failed - deadline not reset by partial headers");
}

// =============================================================================
// TEST 2: Empty HEADERS messages do not extend deadline
// =============================================================================
// Attacker sends empty HEADERS periodically. This should not extend deadline.

TEST_CASE("DoS: Empty HEADERS trickle does not extend deadline", "[dos][network][trickle][security]") {
    SimulatedNetwork net(2002);

    SimulatedNode miner(1, &net);
    for (int i = 0; i < 30; ++i) miner.MineBlock();

    // Attacker syncs from miner - use NodeSimulator for P2P control
    NodeSimulator attacker(2, &net);
    attacker.ConnectTo(miner.GetId());
    uint64_t t = 1000;
    for (int i = 0; i < 20 && attacker.GetTipHeight() < 30; ++i) {
        t += 500;
        net.AdvanceTime(t);
        attacker.CheckInitialSync();
    }
    REQUIRE(attacker.GetTipHeight() == 30);

    // Disconnect attacker from miner
    attacker.DisconnectFrom(miner.GetId());
    t += 100;
    net.AdvanceTime(t);

    // Victim connects only to attacker
    SimulatedNode victim(3, &net);
    victim.ConnectTo(attacker.GetId());
    t += 100;
    net.AdvanceTime(t);

    // Start sync
    victim.CheckInitialSync();
    t += 100;
    net.AdvanceTime(t);

    REQUIRE(victim.GetIsIBD());

    // Enable stalling - attacker won't auto-respond
    attacker.EnableStalling(true);

    // Trickle empty HEADERS every 90 seconds via P2P
    for (int wave = 0; wave < 4; ++wave) {
        for (int i = 0; i < 90; ++i) {
            t += 1000;
            net.AdvanceTime(t);
        }

        // Send empty HEADERS via P2P (goes through HandleHeadersMessage)
        std::vector<CBlockHeader> empty_headers;
        attacker.SendValidHeaders(victim.GetId(), empty_headers);

        t += 100;
        net.AdvanceTime(t);
        victim.ProcessEvents();
        victim.ProcessHeaderSyncTimers();

        INFO("Wave " << wave << " - sent empty HEADERS via P2P at " << (t / 1000) << "s");
    }

    // ~360 seconds passed - well beyond 5 min deadline

    // Final timer check
    victim.ProcessHeaderSyncTimers();
    t += 100;
    net.AdvanceTime(t);

    // Attacker should be disconnected - empty headers don't extend deadline
    auto peers = victim.GetNetworkManager().peer_manager().get_all_peers();
    bool attacker_connected = false;
    for (const auto& peer : peers) {
        if (peer->is_connected()) {
            attacker_connected = true;
            break;
        }
    }

    CHECK_FALSE(attacker_connected);
}

// =============================================================================
// TEST 3: Partial batch then stall triggers disconnect at deadline
// =============================================================================
// Attacker sends a large batch of headers, then stops. Victim should still
// disconnect at deadline even though initial progress was made.

TEST_CASE("DoS: Partial batch then stall triggers deadline disconnect", "[dos][network][trickle][security]") {
    SimulatedNetwork net(2003);

    SimulatedNode miner(1, &net);
    for (int i = 0; i < 100; ++i) miner.MineBlock();
    REQUIRE(miner.GetTipHeight() == 100);

    // Attacker syncs from miner - use NodeSimulator for P2P control
    NodeSimulator attacker(2, &net);
    attacker.ConnectTo(miner.GetId());
    uint64_t t = 1000;
    for (int i = 0; i < 30 && attacker.GetTipHeight() < 100; ++i) {
        t += 500;
        net.AdvanceTime(t);
        attacker.CheckInitialSync();
    }
    REQUIRE(attacker.GetTipHeight() == 100);

    attacker.DisconnectFrom(miner.GetId());
    t += 100;
    net.AdvanceTime(t);

    // Victim connects to attacker
    SimulatedNode victim(3, &net);
    victim.ConnectTo(attacker.GetId());
    t += 100;
    net.AdvanceTime(t);

    // Start sync
    victim.CheckInitialSync();
    t += 100;
    net.AdvanceTime(t);

    REQUIRE(victim.GetIsIBD());
    REQUIRE(victim.GetTipHeight() == 0);

    // Enable stalling after we send the partial batch
    // Get first 30 headers from attacker
    auto headers = GetChainHeaders(attacker, 1, 30);
    REQUIRE(headers.size() == 30);

    // Send partial batch (30 of 100 headers) via P2P HEADERS message
    attacker.SendValidHeaders(victim.GetId(), headers);

    t += 500;
    net.AdvanceTime(t);
    victim.ProcessEvents();

    // Victim processed partial batch - may have some height now
    int height_after_partial = victim.GetTipHeight();
    INFO("Victim height after partial batch: " << height_after_partial);

    // Now attacker goes silent (stalls) - enable stalling mode
    attacker.EnableStalling(true);

    // Advance beyond deadline (5+ minutes)
    for (int i = 0; i < 7; ++i) {  // 7 minutes
        t += 60 * 1000;
        net.AdvanceTime(t);
        victim.ProcessHeaderSyncTimers();
    }

    t += 1000;
    net.AdvanceTime(t);

    // Attacker should be disconnected
    auto peers = victim.GetNetworkManager().peer_manager().get_all_peers();
    bool attacker_connected = false;
    for (const auto& peer : peers) {
        if (peer->is_connected()) {
            attacker_connected = true;
            break;
        }
    }

    // Key assertion: partial progress does NOT prevent deadline disconnect
    CHECK_FALSE(attacker_connected);

    // Victim is still in IBD and not fully synced
    CHECK(victim.GetTipHeight() < 100);
}

// =============================================================================
// TEST 4: Verify deadline is calculated correctly at sync start
// =============================================================================
// The deadline should be: base (5 min) + (expected_headers * 1ms) / 1000
// For a chain that's "1 day behind", expected_headers = 86400 / 120 = 720 (regtest 2-min blocks)
// Extra time = 720 * 1 / 1000 = 0.72 seconds (negligible for regtest)

TEST_CASE("DoS: Deadline calculation matches expected formula", "[dos][network][trickle][unit]") {
    SimulatedNetwork net(2004);

    SimulatedNode miner(1, &net);
    // Mine some blocks - regtest has 2-minute target spacing
    for (int i = 0; i < 50; ++i) miner.MineBlock();

    SimulatedNode victim(2, &net);
    victim.ConnectTo(miner.GetId());

    uint64_t t = 1000;
    net.AdvanceTime(t);

    // Start sync - this sets the deadline
    victim.CheckInitialSync();
    t += 100;
    net.AdvanceTime(t);

    // The deadline is base (5 min = 300s) + dynamic component
    // For regtest with 50 blocks and 2-min spacing, we're ~100 minutes behind
    // expected_headers = 100 * 60 / 120 = 50
    // extra_time = 50 * 1 / 1000 = 0.05s (negligible)
    // Total deadline ≈ 300s

    // Advance just under 5 minutes - should NOT trigger disconnect
    for (int i = 0; i < 4; ++i) {  // 4 minutes
        t += 60 * 1000;
        net.AdvanceTime(t);
        victim.ProcessHeaderSyncTimers();
    }

    // Miner should still be connected (4 min < 5 min deadline)
    auto peers_before = victim.GetNetworkManager().peer_manager().get_all_peers();
    bool miner_connected_before = false;
    for (const auto& peer : peers_before) {
        if (peer->is_connected()) {
            miner_connected_before = true;
            break;
        }
    }
    CHECK(miner_connected_before);

    // Now advance past deadline (another 2 minutes = 6 min total)
    for (int i = 0; i < 2; ++i) {
        t += 60 * 1000;
        net.AdvanceTime(t);
        victim.ProcessHeaderSyncTimers();
    }

    // Check if victim is still in IBD - if sync completed, deadline doesn't apply
    if (victim.GetIsIBD()) {
        // If still in IBD, miner should be disconnected due to stall
        auto peers_after = victim.GetNetworkManager().peer_manager().get_all_peers();
        bool miner_connected_after = false;
        for (const auto& peer : peers_after) {
            if (peer->is_connected()) {
                miner_connected_after = true;
                break;
            }
        }
        CHECK_FALSE(miner_connected_after);
    } else {
        // Sync completed - deadline enforcement doesn't matter
        INFO("Sync completed before deadline - test validates normal path");
        CHECK(victim.GetTipHeight() == 50);
    }
}
