// Copyright (c) 2025 The Unicity Foundation
// Adversarial tests for out-of-order header delivery
// These tests verify that orphan resolution correctly advances chain tip

#include "catch_amalgamated.hpp"
#include "infra/simulated_network.hpp"
#include "infra/simulated_node.hpp"
#include "infra/node_simulator.hpp"
#include "test_orchestrator.hpp"
#include "chain/chainparams.hpp"

using namespace unicity;
using namespace unicity::test;

static struct TestSetup {
    TestSetup() { chain::GlobalChainParams::Select(chain::ChainType::REGTEST); }
} test_setup_out_of_order;

// =============================================================================
// ADVERSARIAL: Out-of-Order Header Delivery
// =============================================================================
// These tests simulate an adversary sending headers in non-chronological order.
// This pattern naturally occurs in P2P networks and can exploit bugs in orphan
// resolution logic.

TEST_CASE("Adversarial: Out-of-order headers are resolved and advance chain tip", "[dos][orphan][adversarial][e2e]") {
    // This test would have caught the orphan resolution bug where resolved
    // orphans were indexed but never added to chain tip candidates.

    SimulatedNetwork network(123);
    TestOrchestrator orchestrator(&network);

    // Victim node
    SimulatedNode victim(1, &network);
    victim.SetBypassPOWValidation(true);

    // Mine some blocks first to establish a chain
    for (int i = 0; i < 3; i++) {
        victim.MineBlock();
    }

    // Attacker node (uses NodeSimulator for crafted messages)
    NodeSimulator attacker(2, &network);

    // Connect attacker to victim and wait for sync
    attacker.ConnectTo(1);
    REQUIRE(orchestrator.WaitForConnection(victim, attacker));
    REQUIRE(orchestrator.WaitForSync(victim, attacker));

    // Record initial chain height (should be 3 now)
    auto& victim_chainstate = victim.GetChainstate();
    int initial_height = victim_chainstate.GetChainHeight();
    INFO("Initial chain height: " << initial_height);
    REQUIRE(initial_height == 3);  // Sanity check

    // Attacker sends headers OUT OF ORDER (child before parent)
    // This triggers orphan creation when child arrives, then resolution when parent arrives
    auto [parent_hash, child_hash] = attacker.SendOutOfOrderHeaders(
        1,  // victim's ID
        victim.GetTipHash()
    );

    // Process messages to handle the parent header and trigger orphan resolution
    orchestrator.AdvanceTime(std::chrono::milliseconds(100));

    // Activate best chain to update tip
    victim_chainstate.ActivateBestChain();

    int final_height = victim_chainstate.GetChainHeight();
    INFO("Final chain height: " << final_height);
    INFO("Expected height: " << (initial_height + 2));

    // THE KEY ASSERTION: Chain height must include BOTH the parent AND the resolved orphan
    // Before the fix, this would fail because orphans were indexed but never became tip candidates
    // initial_height is 3, so we expect 3 + 2 = 5
    REQUIRE(final_height == initial_height + 2);
    REQUIRE(final_height == 5);  // Explicit check

    // Verify both headers are indexed
    REQUIRE(victim_chainstate.LookupBlockIndex(parent_hash) != nullptr);
    REQUIRE(victim_chainstate.LookupBlockIndex(child_hash) != nullptr);

    // Verify the tip is the child (the resolved orphan)
    REQUIRE(victim_chainstate.GetTip()->GetBlockHash() == child_hash);
}

TEST_CASE("Adversarial: Multiple out-of-order header chains are all resolved", "[dos][orphan][adversarial][e2e]") {
    // Test multiple independent orphan chains being resolved

    SimulatedNetwork network(456);
    TestOrchestrator orchestrator(&network);

    SimulatedNode victim(1, &network);
    victim.SetBypassPOWValidation(true);

    // Mine some blocks first
    for (int i = 0; i < 3; i++) {
        victim.MineBlock();
    }

    NodeSimulator attacker(2, &network);

    attacker.ConnectTo(1);
    REQUIRE(orchestrator.WaitForConnection(victim, attacker));
    REQUIRE(orchestrator.WaitForSync(victim, attacker));

    auto& victim_chainstate = victim.GetChainstate();
    int initial_height = victim_chainstate.GetChainHeight();
    REQUIRE(initial_height == 3);

    // Send first out-of-order pair
    auto [parent1, child1] = attacker.SendOutOfOrderHeaders(1, victim.GetTipHash());
    orchestrator.AdvanceTime(std::chrono::milliseconds(100));
    victim_chainstate.ActivateBestChain();

    // First pair should advance chain by 2
    REQUIRE(victim_chainstate.GetChainHeight() == initial_height + 2);
    REQUIRE(victim_chainstate.GetTip()->GetBlockHash() == child1);

    // Send second out-of-order pair (building on the resolved chain)
    auto [parent2, child2] = attacker.SendOutOfOrderHeaders(1, child1);
    orchestrator.AdvanceTime(std::chrono::milliseconds(100));
    victim_chainstate.ActivateBestChain();

    // Second pair should advance chain by 2 more
    REQUIRE(victim_chainstate.GetChainHeight() == initial_height + 4);
    REQUIRE(victim_chainstate.GetTip()->GetBlockHash() == child2);

    // All headers should be indexed
    REQUIRE(victim_chainstate.LookupBlockIndex(parent1) != nullptr);
    REQUIRE(victim_chainstate.LookupBlockIndex(child1) != nullptr);
    REQUIRE(victim_chainstate.LookupBlockIndex(parent2) != nullptr);
    REQUIRE(victim_chainstate.LookupBlockIndex(child2) != nullptr);
}

TEST_CASE("Adversarial: Deep orphan chain resolution", "[dos][orphan][adversarial][e2e]") {
    // Test sending multiple out-of-order pairs sequentially

    SimulatedNetwork network(789);
    TestOrchestrator orchestrator(&network);

    SimulatedNode victim(1, &network);
    victim.SetBypassPOWValidation(true);

    // Mine some blocks first
    for (int i = 0; i < 3; i++) {
        victim.MineBlock();
    }

    NodeSimulator attacker(2, &network);

    attacker.ConnectTo(1);
    REQUIRE(orchestrator.WaitForConnection(victim, attacker));
    REQUIRE(orchestrator.WaitForSync(victim, attacker));

    auto& victim_chainstate = victim.GetChainstate();
    int initial_height = victim_chainstate.GetChainHeight();
    REQUIRE(initial_height == 3);
    uint256 genesis_tip = victim.GetTipHash();

    // Send 4 out-of-order pairs (8 headers total)
    std::vector<uint256> all_hashes;
    uint256 current_base = genesis_tip;

    for (int i = 0; i < 4; i++) {
        auto [parent, child] = attacker.SendOutOfOrderHeaders(1, current_base);
        orchestrator.AdvanceTime(std::chrono::milliseconds(100));
        victim_chainstate.ActivateBestChain();

        all_hashes.push_back(parent);
        all_hashes.push_back(child);
        current_base = child;  // Next pair builds on this child
    }

    // Verify final chain height
    int final_height = victim_chainstate.GetChainHeight();
    INFO("Initial height: " << initial_height);
    INFO("Final height: " << final_height);
    INFO("Expected: " << (initial_height + 8));

    REQUIRE(final_height == initial_height + 8);

    // Verify all headers are indexed
    for (const auto& hash : all_hashes) {
        REQUIRE(victim_chainstate.LookupBlockIndex(hash) != nullptr);
    }

    // Verify tip is the last child
    REQUIRE(victim_chainstate.GetTip()->GetBlockHash() == all_hashes.back());
}

TEST_CASE("Adversarial: Out-of-order headers processed correctly", "[dos][orphan][adversarial][e2e]") {
    // Test that valid out-of-order headers (child before parent) are processed correctly
    // via the orphan header mechanism.
    //
    // NOTE: The previous test "Orphan resolution after DoS limit approached" was removed
    // because SendOrphanHeaders creates non-continuous headers, which with instant
    // discourage (Bitcoin Core March 2024) results in immediate disconnection.
    // Non-continuous headers are a protocol violation, not a valid "approach the limit" scenario.

    SimulatedNetwork network(101112);
    TestOrchestrator orchestrator(&network);

    SimulatedNode victim(1, &network);
    victim.SetBypassPOWValidation(true);

    // Mine some blocks first
    for (int i = 0; i < 3; i++) {
        victim.MineBlock();
    }

    NodeSimulator attacker(2, &network);

    attacker.ConnectTo(1);
    REQUIRE(orchestrator.WaitForConnection(victim, attacker));
    REQUIRE(orchestrator.WaitForSync(victim, attacker));

    auto& victim_chainstate = victim.GetChainstate();
    int initial_height = victim_chainstate.GetChainHeight();
    REQUIRE(initial_height == 3);

    // Send valid out-of-order headers (child before parent)
    auto [parent_hash, child_hash] = attacker.SendOutOfOrderHeaders(1, victim.GetTipHash());
    orchestrator.AdvanceTime(std::chrono::milliseconds(100));
    victim_chainstate.ActivateBestChain();

    // Chain should have advanced by 2 (both headers processed via orphan resolution)
    REQUIRE(victim_chainstate.GetChainHeight() == initial_height + 2);
    REQUIRE(victim_chainstate.GetTip()->GetBlockHash() == child_hash);
}

TEST_CASE("Adversarial: Multiple attackers send independent orphan chains", "[dos][orphan][adversarial][e2e]") {
    // Two attackers each send out-of-order headers to the same victim
    // Both chains should be processed correctly

    SimulatedNetwork network(131415);
    TestOrchestrator orchestrator(&network);

    SimulatedNode victim(1, &network);
    victim.SetBypassPOWValidation(true);

    // Mine initial chain
    for (int i = 0; i < 3; i++) {
        victim.MineBlock();
    }

    // Two independent attackers
    NodeSimulator attacker1(2, &network);
    NodeSimulator attacker2(3, &network);

    attacker1.ConnectTo(1);
    attacker2.ConnectTo(1);
    REQUIRE(orchestrator.WaitForConnection(victim, attacker1));
    REQUIRE(orchestrator.WaitForConnection(victim, attacker2));
    REQUIRE(orchestrator.WaitForSync(victim, attacker1));
    REQUIRE(orchestrator.WaitForSync(victim, attacker2));

    auto& victim_chainstate = victim.GetChainstate();
    int initial_height = victim_chainstate.GetChainHeight();
    REQUIRE(initial_height == 3);

    // Attacker 1 sends out-of-order headers
    auto [parent1, child1] = attacker1.SendOutOfOrderHeaders(1, victim.GetTipHash());
    orchestrator.AdvanceTime(std::chrono::milliseconds(50));

    // Attacker 2 also sends out-of-order headers (building on original tip, creating competing fork)
    auto [parent2, child2] = attacker2.SendOutOfOrderHeaders(1, victim.GetTipHash());
    orchestrator.AdvanceTime(std::chrono::milliseconds(100));

    victim_chainstate.ActivateBestChain();

    // Both chains should be indexed (even if only one is active)
    REQUIRE(victim_chainstate.LookupBlockIndex(parent1) != nullptr);
    REQUIRE(victim_chainstate.LookupBlockIndex(child1) != nullptr);
    REQUIRE(victim_chainstate.LookupBlockIndex(parent2) != nullptr);
    REQUIRE(victim_chainstate.LookupBlockIndex(child2) != nullptr);

    // Chain should have advanced (either fork accepted)
    REQUIRE(victim_chainstate.GetChainHeight() >= initial_height + 2);
}

TEST_CASE("Adversarial: Orphan resolution interleaved with normal mining", "[dos][orphan][adversarial][e2e]") {
    // Attacker sends orphans while victim is mining
    // Ensure mining and orphan resolution don't interfere

    SimulatedNetwork network(161718);
    TestOrchestrator orchestrator(&network);

    SimulatedNode victim(1, &network);
    victim.SetBypassPOWValidation(true);

    // Mine initial chain
    for (int i = 0; i < 3; i++) {
        victim.MineBlock();
    }

    NodeSimulator attacker(2, &network);

    attacker.ConnectTo(1);
    REQUIRE(orchestrator.WaitForConnection(victim, attacker));
    REQUIRE(orchestrator.WaitForSync(victim, attacker));

    auto& victim_chainstate = victim.GetChainstate();
    REQUIRE(victim_chainstate.GetChainHeight() == 3);

    // Victim mines a block
    victim.MineBlock();
    REQUIRE(victim_chainstate.GetChainHeight() == 4);

    // Attacker sends out-of-order headers (building on height 4)
    auto [parent1, child1] = attacker.SendOutOfOrderHeaders(1, victim.GetTipHash());
    orchestrator.AdvanceTime(std::chrono::milliseconds(100));
    victim_chainstate.ActivateBestChain();
    REQUIRE(victim_chainstate.GetChainHeight() == 6);

    // Victim mines another block (on top of resolved orphan)
    victim.MineBlock();
    REQUIRE(victim_chainstate.GetChainHeight() == 7);

    // Attacker sends more out-of-order headers
    auto [parent2, child2] = attacker.SendOutOfOrderHeaders(1, victim.GetTipHash());
    orchestrator.AdvanceTime(std::chrono::milliseconds(100));
    victim_chainstate.ActivateBestChain();
    REQUIRE(victim_chainstate.GetChainHeight() == 9);

    // All headers should be properly linked
    REQUIRE(victim_chainstate.LookupBlockIndex(parent1) != nullptr);
    REQUIRE(victim_chainstate.LookupBlockIndex(child1) != nullptr);
    REQUIRE(victim_chainstate.LookupBlockIndex(parent2) != nullptr);
    REQUIRE(victim_chainstate.LookupBlockIndex(child2) != nullptr);
}

TEST_CASE("Adversarial: Orphan spam then disconnect - verify cleanup", "[dos][orphan][adversarial][e2e]") {
    // Attacker sends orphan spam then disconnects
    // Verify orphans are handled and node remains functional

    SimulatedNetwork network(192021);
    TestOrchestrator orchestrator(&network);

    SimulatedNode victim(1, &network);
    victim.SetBypassPOWValidation(true);

    for (int i = 0; i < 3; i++) {
        victim.MineBlock();
    }

    NodeSimulator attacker(2, &network);

    attacker.ConnectTo(1);
    REQUIRE(orchestrator.WaitForConnection(victim, attacker));
    REQUIRE(orchestrator.WaitForSync(victim, attacker));

    auto& victim_chainstate = victim.GetChainstate();
    int initial_height = victim_chainstate.GetChainHeight();

    // Send a burst of orphan spam
    for (int batch = 0; batch < 5; batch++) {
        attacker.SendOrphanHeaders(1, 20);
        orchestrator.AdvanceTime(std::chrono::milliseconds(50));
    }

    // Disconnect the attacker
    victim.DisconnectFrom(2);
    orchestrator.AdvanceTime(std::chrono::milliseconds(100));

    // Chain should be unaffected (orphans had random parents)
    REQUIRE(victim_chainstate.GetChainHeight() == initial_height);

    // Connect a new honest node and mine
    SimulatedNode honest(3, &network);
    honest.SetBypassPOWValidation(true);
    honest.ConnectTo(1);
    REQUIRE(orchestrator.WaitForConnection(victim, honest));
    REQUIRE(orchestrator.WaitForSync(victim, honest));

    // Victim should still be able to accept valid headers
    victim.MineBlock();
    REQUIRE(victim_chainstate.GetChainHeight() == initial_height + 1);
}

TEST_CASE("Adversarial: Rapid-fire out-of-order headers", "[dos][orphan][adversarial][e2e]") {
    // Send many out-of-order header pairs in rapid succession
    // Tests that orphan resolution handles high throughput

    SimulatedNetwork network(222324);
    TestOrchestrator orchestrator(&network);

    SimulatedNode victim(1, &network);
    victim.SetBypassPOWValidation(true);

    for (int i = 0; i < 3; i++) {
        victim.MineBlock();
    }

    NodeSimulator attacker(2, &network);

    attacker.ConnectTo(1);
    REQUIRE(orchestrator.WaitForConnection(victim, attacker));
    REQUIRE(orchestrator.WaitForSync(victim, attacker));

    auto& victim_chainstate = victim.GetChainstate();
    REQUIRE(victim_chainstate.GetChainHeight() == 3);

    // Send 10 out-of-order pairs rapidly, each building on the previous
    uint256 current_tip = victim.GetTipHash();
    std::vector<uint256> all_hashes;

    for (int i = 0; i < 10; i++) {
        auto [parent, child] = attacker.SendOutOfOrderHeaders(1, current_tip);
        // Minimal time between sends
        orchestrator.AdvanceTime(std::chrono::milliseconds(10));
        victim_chainstate.ActivateBestChain();

        all_hashes.push_back(parent);
        all_hashes.push_back(child);
        current_tip = child;
    }

    // Process remaining messages
    orchestrator.AdvanceTime(std::chrono::milliseconds(100));
    victim_chainstate.ActivateBestChain();

    // All 20 headers should be indexed (10 pairs)
    int indexed_count = 0;
    for (const auto& hash : all_hashes) {
        if (victim_chainstate.LookupBlockIndex(hash) != nullptr) {
            indexed_count++;
        }
    }

    INFO("Indexed " << indexed_count << " of " << all_hashes.size() << " headers");
    REQUIRE(indexed_count == 20);

    // Chain should have advanced by 20 (10 pairs × 2 headers each)
    REQUIRE(victim_chainstate.GetChainHeight() == 3 + 20);
}
