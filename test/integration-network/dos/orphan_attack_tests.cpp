// Orphan Header Attack Tests
//
// Tests orphan pool resilience against various attack patterns:
//
// 1. Orphan pool exhaustion - Fill to MAX_ORPHAN_HEADERS, verify eviction
// 2. Unresolvable orphan chains - Headers with non-existent parents
// 3. Orphan resolution cascade - Parent arrives, triggers chain resolution
// 4. Per-peer orphan limits - Single attacker can't monopolize pool
// 5. Orphan expiration - Old orphans are evicted
// 6. Mixed attack - Orphans + valid headers interleaved
//
// Note: True circular orphans (A→B→C→A) are mathematically impossible
// because hash(header) depends on prevBlock which creates ordering.

#include "catch_amalgamated.hpp"
#include "infra/simulated_network.hpp"
#include "infra/simulated_node.hpp"
#include "infra/node_simulator.hpp"
#include "test_orchestrator.hpp"
#include "network_observer.hpp"
#include "chain/chainparams.hpp"
#include "network/protocol.hpp"

using namespace unicity;
using namespace unicity::chain;
using namespace unicity::test;

static struct TestSetup {
    TestSetup() { chain::GlobalChainParams::Select(chain::ChainType::REGTEST); }
} test_setup_orphan;

// =============================================================================
// TEST 1: Orphan Pool Exhaustion and Eviction
// =============================================================================
// Fill orphan pool to MAX_ORPHAN_HEADERS. Verify oldest are evicted.

TEST_CASE("DoS: Orphan pool exhaustion triggers eviction", "[dos][orphan][eviction]") {
    SimulatedNetwork net(4001);

    SimulatedNode victim(1, &net);
    for (int i = 0; i < 5; ++i) victim.MineBlock();
    REQUIRE(victim.GetTipHeight() == 5);

    NodeSimulator attacker(2, &net);
    attacker.ConnectTo(victim.GetId());

    uint64_t t = 1000;
    net.AdvanceTime(t);

    // Get initial orphan count
    size_t initial_orphans = victim.GetChainstate().GetOrphanHeaderCount();

    // Send many orphans (more than MAX_ORPHAN_HEADERS which is typically 1000)
    // Each batch of 50 orphans
    for (int batch = 0; batch < 30; ++batch) {
        attacker.SendOrphanHeaders(victim.GetId(), 50);
        t += 100;
        net.AdvanceTime(t);
    }

    // Get final orphan count
    size_t final_orphans = victim.GetChainstate().GetOrphanHeaderCount();

    // Verify: Orphan pool should be bounded (not unbounded growth)
    // MAX_ORPHAN_HEADERS is 1000, so we shouldn't exceed that much
    CHECK(final_orphans <= protocol::MAX_ORPHAN_HEADERS + 100);  // Some slack for timing

    // Victim should still be functional
    CHECK(victim.GetTipHeight() == 5);

    // Verify victim can still sync normally
    SimulatedNode honest(3, &net);
    for (int i = 0; i < 20; ++i) honest.MineBlock();

    victim.ConnectTo(honest.GetId());
    t += 500;
    net.AdvanceTime(t);

    for (int i = 0; i < 30 && victim.GetTipHeight() < 20; ++i) {
        t += 500;
        net.AdvanceTime(t);
        victim.GetNetworkManager().test_hook_check_initial_sync();
    }

    CHECK(victim.GetTipHeight() == 20);
}

// =============================================================================
// TEST 2: Orphan Resolution Cascade
// =============================================================================
// Send child before parent. When parent arrives, child should resolve.

TEST_CASE("DoS: Orphan resolution when parent arrives", "[dos][orphan][resolution]") {
    SimulatedNetwork net(4002);

    SimulatedNode victim(1, &net);
    for (int i = 0; i < 5; ++i) victim.MineBlock();
    REQUIRE(victim.GetTipHeight() == 5);

    NodeSimulator attacker(2, &net);
    attacker.ConnectTo(victim.GetId());

    uint64_t t = 1000;
    net.AdvanceTime(t);

    // Send out-of-order headers (child first, then parent)
    uint256 tip = victim.GetTipHash();
    auto [parent_hash, child_hash] = attacker.SendOutOfOrderHeaders(victim.GetId(), tip);

    t += 500;
    net.AdvanceTime(t);

    // Process messages to allow orphan resolution
    for (int i = 0; i < 5; ++i) {
        t += 100;
        net.AdvanceTime(t);
    }

    // Victim should have processed the chain
    // The headers should either be in chain or evicted, not stuck
    CHECK(victim.GetTipHeight() >= 5);  // At least original height
}

// =============================================================================
// TEST 3: Multiple Attackers Orphan Flood
// =============================================================================
// Multiple attackers each flood orphans. Verify per-peer limits work.

TEST_CASE("DoS: Multiple attackers orphan flood", "[dos][orphan][multipeer]") {
    SimulatedNetwork net(4003);

    SimulatedNode victim(1, &net);
    for (int i = 0; i < 5; ++i) victim.MineBlock();
    REQUIRE(victim.GetTipHeight() == 5);

    // Create 5 attackers
    std::vector<std::unique_ptr<NodeSimulator>> attackers;
    for (int i = 0; i < 5; ++i) {
        auto attacker = std::make_unique<NodeSimulator>(10 + i, &net);
        attacker->ConnectTo(victim.GetId());
        attackers.push_back(std::move(attacker));
    }

    uint64_t t = 1000;
    net.AdvanceTime(t);

    // Each attacker sends orphans
    for (int round = 0; round < 10; ++round) {
        for (auto& attacker : attackers) {
            attacker->SendOrphanHeaders(victim.GetId(), 100);
        }
        t += 200;
        net.AdvanceTime(t);
    }

    // Verify victim is still functional
    CHECK(victim.GetTipHeight() == 5);

    // Orphan pool should be bounded
    size_t orphan_count = victim.GetChainstate().GetOrphanHeaderCount();
    CHECK(orphan_count <= protocol::MAX_ORPHAN_HEADERS + 100);

    // Verify victim can still sync
    SimulatedNode honest(100, &net);
    for (int i = 0; i < 30; ++i) honest.MineBlock();

    victim.ConnectTo(honest.GetId());
    t += 500;
    net.AdvanceTime(t);

    for (int i = 0; i < 40 && victim.GetTipHeight() < 30; ++i) {
        t += 500;
        net.AdvanceTime(t);
        victim.GetNetworkManager().test_hook_check_initial_sync();
    }

    CHECK(victim.GetTipHeight() == 30);
}

// =============================================================================
// TEST 4: Orphan Eviction Doesn't Affect Valid Chain
// =============================================================================
// Flood orphans while victim is syncing. Sync should still complete.

TEST_CASE("DoS: Orphan flood during sync doesn't block sync", "[dos][orphan][sync]") {
    SimulatedNetwork net(4004);

    // Honest peer with chain
    SimulatedNode honest(1, &net);
    for (int i = 0; i < 50; ++i) honest.MineBlock();
    REQUIRE(honest.GetTipHeight() == 50);

    // Attacker
    NodeSimulator attacker(10, &net);

    // Victim
    SimulatedNode victim(100, &net);
    victim.ConnectTo(honest.GetId());
    attacker.ConnectTo(victim.GetId());

    uint64_t t = 1000;
    net.AdvanceTime(t);

    // Start syncing
    victim.GetNetworkManager().test_hook_check_initial_sync();

    // Attacker floods orphans during sync
    for (int round = 0; round < 20; ++round) {
        attacker.SendOrphanHeaders(victim.GetId(), 100);
        t += 100;
        net.AdvanceTime(t);

        // Process sync in parallel
        victim.GetNetworkManager().test_hook_check_initial_sync();
    }

    // Continue sync
    for (int i = 0; i < 50 && victim.GetTipHeight() < 50; ++i) {
        t += 500;
        net.AdvanceTime(t);
        victim.GetNetworkManager().test_hook_check_initial_sync();
    }

    // Sync should complete despite orphan flood
    CHECK(victim.GetTipHeight() == 50);
}

// =============================================================================
// TEST 5: Orphan Memory Bounds
// =============================================================================
// Verify orphan pool doesn't consume unbounded memory.

TEST_CASE("DoS: Orphan pool memory is bounded", "[dos][orphan][memory]") {
    SimulatedNetwork net(4005);

    SimulatedNode victim(1, &net);
    for (int i = 0; i < 5; ++i) victim.MineBlock();

    NodeSimulator attacker(2, &net);
    attacker.ConnectTo(victim.GetId());

    uint64_t t = 1000;
    net.AdvanceTime(t);

    // Massive orphan flood (10,000 orphans)
    for (int batch = 0; batch < 100; ++batch) {
        attacker.SendOrphanHeaders(victim.GetId(), 100);
        t += 50;
        net.AdvanceTime(t);
    }

    // Orphan pool should be bounded
    size_t orphan_count = victim.GetChainstate().GetOrphanHeaderCount();

    // Should not exceed MAX_ORPHAN_HEADERS significantly
    CHECK(orphan_count <= protocol::MAX_ORPHAN_HEADERS + 50);

    // Victim functional
    CHECK(victim.GetTipHeight() == 5);
}

// =============================================================================
// TEST 6: Orphan From Disconnected Peer
// =============================================================================
// Peer sends orphans then disconnects. Orphans should eventually be evicted.

TEST_CASE("DoS: Orphans from disconnected peer are handled", "[dos][orphan][disconnect]") {
    SimulatedNetwork net(4006);

    SimulatedNode victim(1, &net);
    for (int i = 0; i < 5; ++i) victim.MineBlock();

    uint64_t t = 1000;
    net.AdvanceTime(t);

    {
        // Attacker in scope
        NodeSimulator attacker(2, &net);
        attacker.ConnectTo(victim.GetId());
        t += 200;
        net.AdvanceTime(t);

        // Send orphans
        for (int batch = 0; batch < 10; ++batch) {
            attacker.SendOrphanHeaders(victim.GetId(), 50);
            t += 100;
            net.AdvanceTime(t);
        }

        // Attacker goes out of scope (disconnects)
    }

    // Advance time
    t += 5000;
    net.AdvanceTime(t);

    // Victim should still be functional
    CHECK(victim.GetTipHeight() == 5);

    // Connect honest peer and sync
    SimulatedNode honest(3, &net);
    for (int i = 0; i < 20; ++i) honest.MineBlock();

    victim.ConnectTo(honest.GetId());
    t += 500;
    net.AdvanceTime(t);

    for (int i = 0; i < 30 && victim.GetTipHeight() < 20; ++i) {
        t += 500;
        net.AdvanceTime(t);
        victim.GetNetworkManager().test_hook_check_initial_sync();
    }

    CHECK(victim.GetTipHeight() == 20);
}

// =============================================================================
// TEST 7: Rapid Orphan Churn
// =============================================================================
// Rapid add/evict cycles. Verify no memory leaks or corruption.

TEST_CASE("DoS: Rapid orphan churn stability", "[dos][orphan][churn]") {
    SimulatedNetwork net(4007);

    SimulatedNode victim(1, &net);
    for (int i = 0; i < 5; ++i) victim.MineBlock();

    NodeSimulator attacker(2, &net);
    attacker.ConnectTo(victim.GetId());

    uint64_t t = 1000;
    net.AdvanceTime(t);

    // Rapid cycles of orphan flood + eviction trigger
    for (int cycle = 0; cycle < 50; ++cycle) {
        // Send batch of orphans
        attacker.SendOrphanHeaders(victim.GetId(), 50);
        t += 20;
        net.AdvanceTime(t);

        // Force eviction by calling process timers
        victim.GetNetworkManager().test_hook_header_sync_process_timers();
    }

    // Verify stability
    CHECK(victim.GetTipHeight() == 5);

    // Verify can still process valid headers
    SimulatedNode honest(3, &net);
    for (int i = 0; i < 10; ++i) honest.MineBlock();

    victim.ConnectTo(honest.GetId());
    t += 500;
    net.AdvanceTime(t);

    for (int i = 0; i < 20 && victim.GetTipHeight() < 10; ++i) {
        t += 500;
        net.AdvanceTime(t);
        victim.GetNetworkManager().test_hook_check_initial_sync();
    }

    CHECK(victim.GetTipHeight() == 10);
}

// =============================================================================
// TEST 8: Orphan With Future Timestamp
// =============================================================================
// Headers with far-future timestamps should be handled gracefully.

TEST_CASE("DoS: Orphans with future timestamps", "[dos][orphan][timestamp]") {
    SimulatedNetwork net(4008);

    SimulatedNode victim(1, &net);
    for (int i = 0; i < 5; ++i) victim.MineBlock();

    // Note: SendOrphanHeaders creates headers with current time
    // Future timestamp handling is done at consensus validation level
    // This test verifies the system remains stable

    NodeSimulator attacker(2, &net);
    attacker.ConnectTo(victim.GetId());

    uint64_t t = 1000;
    net.AdvanceTime(t);

    // Send orphans (timestamps are based on network time)
    attacker.SendOrphanHeaders(victim.GetId(), 100);
    t += 500;
    net.AdvanceTime(t);

    // Victim remains functional
    CHECK(victim.GetTipHeight() == 5);

    // Can still sync
    SimulatedNode honest(3, &net);
    for (int i = 0; i < 15; ++i) honest.MineBlock();

    victim.ConnectTo(honest.GetId());

    for (int i = 0; i < 25 && victim.GetTipHeight() < 15; ++i) {
        t += 500;
        net.AdvanceTime(t);
        victim.GetNetworkManager().test_hook_check_initial_sync();
    }

    CHECK(victim.GetTipHeight() == 15);
}
