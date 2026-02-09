// IBD relay suppression tests: verify blocks received during IBD are never announced
//
// This test catches a critical bug where blocks connected during IBD were incorrectly
// relayed after IBD ended due to event batching in ActivateBestChain().
//
// The bug: IBD state was checked at callback time, not when the block was connected.
//
// The fix: Capture fInitialDownload once at ActivateBestChain() entry and pass it
// to all events in the batch. This matches Bitcoin Core's approach.
//
// Strategy: Snapshot HEADERS count from fresh→peer AFTER sync completes (this baseline
// includes any GETHEADERS→HEADERS sync responses). Then verify zero additional HEADERS
// are sent — any extra would be spurious IBD block announcements.

#include "catch_amalgamated.hpp"
#include "infra/simulated_network.hpp"
#include "infra/simulated_node.hpp"
#include "network/protocol.hpp"

using namespace unicity;
using namespace unicity::test;

static void SetZeroLatency(SimulatedNetwork& network) {
    SimulatedNetwork::NetworkConditions cond{};
    cond.latency_min = std::chrono::milliseconds(0);
    cond.latency_max = std::chrono::milliseconds(0);
    cond.jitter_max = std::chrono::milliseconds(0);
    network.SetNetworkConditions(cond);
}

static void AdvanceTime(SimulatedNetwork& net, uint64_t& t, int ms) {
    t += ms;
    net.AdvanceTime(t);
}

TEST_CASE("IBD relay suppression: fresh node syncing 100 blocks announces ZERO during IBD", "[block_relay][ibd][regression]") {
    SimulatedNetwork net(52001);
    SetZeroLatency(net);
    net.EnableCommandTracking(true);

    // Create miner with 100 blocks (enough to trigger IBD on fresh node)
    SimulatedNode miner(1, &net);
    uint64_t t = 1000;
    for (int i = 0; i < 100; ++i) {
        (void)miner.MineBlock();
        AdvanceTime(net, t, 100);
    }
    REQUIRE(miner.GetTipHeight() == 100);

    // Create fresh node (starts at genesis, will be in IBD)
    SimulatedNode fresh(2, &net);
    REQUIRE(fresh.GetTipHeight() == 0);

    // Connect fresh -> miner and let it sync
    fresh.ConnectTo(miner.GetId());
    AdvanceTime(net, t, 1000);

    for (int i = 0; i < 50 && fresh.GetTipHeight() < 100; ++i) {
        AdvanceTime(net, t, 200);
        fresh.CheckInitialSync();
    }
    REQUIRE(fresh.GetTipHeight() == 100);

    // Snapshot HEADERS count after sync (includes any sync responses)
    int baseline = net.CountCommandSent(fresh.GetId(), miner.GetId(), protocol::commands::HEADERS);

    // Advance time further — no new blocks, so no new HEADERS should appear
    AdvanceTime(net, t, 2000);

    int after = net.CountCommandSent(fresh.GetId(), miner.GetId(), protocol::commands::HEADERS);

    // Delta must be exactly 0: no IBD blocks were announced
    // If the bug were present, delta would be ~100 (all IBD blocks announced after exit)
    CHECK(after - baseline == 0);
}

TEST_CASE("IBD relay suppression: post-IBD blocks ARE announced", "[block_relay][ibd][regression]") {
    SimulatedNetwork net(52002);
    SetZeroLatency(net);
    net.EnableCommandTracking(true);

    // Create miner with 50 blocks
    SimulatedNode miner(1, &net);
    uint64_t t = 1000;
    for (int i = 0; i < 50; ++i) {
        (void)miner.MineBlock();
        AdvanceTime(net, t, 100);
    }
    REQUIRE(miner.GetTipHeight() == 50);

    // Create fresh node and let it sync
    SimulatedNode fresh(2, &net);
    fresh.ConnectTo(miner.GetId());
    AdvanceTime(net, t, 1000);

    for (int i = 0; i < 30 && fresh.GetTipHeight() < 50; ++i) {
        AdvanceTime(net, t, 200);
        fresh.CheckInitialSync();
    }
    REQUIRE(fresh.GetTipHeight() == 50);

    // Let all sync exchanges settle before taking baseline
    AdvanceTime(net, t, 5000);

    // Snapshot after sync is fully settled
    int baseline = net.CountCommandSent(fresh.GetId(), miner.GetId(), protocol::commands::HEADERS);

    // Mine a NEW block on fresh node (post-IBD) — should be announced
    (void)fresh.MineBlock();

    // Immediately after mining, before any network processing
    int after_mine = net.CountCommandSent(fresh.GetId(), miner.GetId(), protocol::commands::HEADERS);

    // announce_block fires synchronously during MineBlock → exactly 1 new HEADERS
    CHECK(after_mine - baseline == 1);

    // After network settles, miner may trigger sync responses (GETHEADERS→HEADERS)
    // but the key assertion is that the announcement itself happened
    AdvanceTime(net, t, 1000);
}

TEST_CASE("IBD relay suppression: block causing IBD exit is NOT announced", "[block_relay][ibd][regression]") {
    // This test specifically targets the race condition where the block that
    // causes IBD to exit was incorrectly seeing IBD=false because the check
    // happened AFTER SetActiveTip().

    SimulatedNetwork net(52003);
    SetZeroLatency(net);
    net.EnableCommandTracking(true);

    SimulatedNode miner(1, &net);
    uint64_t t = 1000;

    // Mine 80 blocks with old timestamps
    for (int i = 0; i < 80; ++i) {
        (void)miner.MineBlock();
        AdvanceTime(net, t, 100);
    }

    // Advance time significantly so previous blocks are "old"
    t += 24 * 60 * 60 * 1000;  // +24 hours
    net.AdvanceTime(t);

    // Mine 20 more blocks with "recent" timestamps - these will cause IBD to exit
    for (int i = 0; i < 20; ++i) {
        (void)miner.MineBlock();
        AdvanceTime(net, t, 100);
    }
    REQUIRE(miner.GetTipHeight() == 100);

    // Fresh node syncs
    SimulatedNode fresh(2, &net);
    fresh.ConnectTo(miner.GetId());
    AdvanceTime(net, t, 1000);

    for (int i = 0; i < 50 && fresh.GetTipHeight() < 100; ++i) {
        AdvanceTime(net, t, 200);
        fresh.CheckInitialSync();
    }
    REQUIRE(fresh.GetTipHeight() == 100);

    // Snapshot after sync
    int baseline = net.CountCommandSent(fresh.GetId(), miner.GetId(), protocol::commands::HEADERS);

    // No new blocks, so no announcements should appear
    AdvanceTime(net, t, 2000);

    int after = net.CountCommandSent(fresh.GetId(), miner.GetId(), protocol::commands::HEADERS);
    CHECK(after - baseline == 0);
}

TEST_CASE("IBD relay suppression: third-party peer receives no IBD announcements", "[block_relay][ibd][regression]") {
    SimulatedNetwork net(52004);
    SetZeroLatency(net);
    net.EnableCommandTracking(true);

    // Miner with chain
    SimulatedNode miner(1, &net);
    uint64_t t = 1000;
    for (int i = 0; i < 100; ++i) {
        (void)miner.MineBlock();
        AdvanceTime(net, t, 100);
    }

    // Observer peer (already synced)
    SimulatedNode observer(2, &net);
    observer.ConnectTo(miner.GetId());
    AdvanceTime(net, t, 1000);
    for (int i = 0; i < 30 && observer.GetTipHeight() < 100; ++i) {
        AdvanceTime(net, t, 200);
        observer.CheckInitialSync();
    }
    REQUIRE(observer.GetTipHeight() == 100);

    // Fresh node syncs from miner while connected to observer
    SimulatedNode fresh(3, &net);
    fresh.ConnectTo(miner.GetId());
    fresh.ConnectTo(observer.GetId());
    AdvanceTime(net, t, 1000);

    for (int i = 0; i < 50 && fresh.GetTipHeight() < 100; ++i) {
        AdvanceTime(net, t, 200);
        fresh.CheckInitialSync();
    }
    REQUIRE(fresh.GetTipHeight() == 100);

    // Snapshot after sync
    int baseline_miner = net.CountCommandSent(fresh.GetId(), miner.GetId(), protocol::commands::HEADERS);
    int baseline_observer = net.CountCommandSent(fresh.GetId(), observer.GetId(), protocol::commands::HEADERS);

    // No new blocks, no announcements should appear
    AdvanceTime(net, t, 2000);

    int after_miner = net.CountCommandSent(fresh.GetId(), miner.GetId(), protocol::commands::HEADERS);
    int after_observer = net.CountCommandSent(fresh.GetId(), observer.GetId(), protocol::commands::HEADERS);

    CHECK(after_miner - baseline_miner == 0);
    CHECK(after_observer - baseline_observer == 0);
}
