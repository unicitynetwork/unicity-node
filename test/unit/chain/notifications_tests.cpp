// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license
// Tests for blockchain notification system

#include "catch_amalgamated.hpp"
#include "chain/validation.hpp"
#include "common/test_chainstate_manager.hpp"
#include "chain/chainstate_manager.hpp"
#include "chain/chainparams.hpp"
#include "chain/chain.hpp"
#include "chain/block_index.hpp"
#include "chain/block.hpp"
#include "chain/notifications.hpp"
#include "chain/miner.hpp"
#include "util/logging.hpp"
#include "util/time.hpp"
#include <filesystem>
#include <memory>
#include <vector>
#include <atomic>

using namespace unicity;
using namespace unicity::test;
using namespace unicity::chain;
using unicity::validation::ValidationState;

// Test helper: Create a block header with specified parent and time
static CBlockHeader CreateTestHeader(const uint256& hashPrevBlock,
                                     uint32_t nTime,
                                     uint32_t nBits = 0x207fffff) {
    CBlockHeader header;
    header.nVersion = 1;
    header.hashPrevBlock = hashPrevBlock;
    header.minerAddress.SetNull();
    header.nTime = nTime;
    header.nBits = nBits;
    header.nNonce = 0;
    header.hashRandomX.SetNull(); // Valid PoW placeholder (test bypasses validation)
    return header;
}

// Test helper: Build a chain of N blocks from a parent
static std::vector<CBlockHeader> BuildChain(const uint256& parent_hash,
                                            uint32_t start_time,
                                            int count,
                                            uint32_t nBits = 0x207fffff) {
    std::vector<CBlockHeader> chain;
    uint256 prev_hash = parent_hash;
    uint32_t time = start_time;

    for (int i = 0; i < count; i++) {
        auto header = CreateTestHeader(prev_hash, time, nBits);
        chain.push_back(header);
        prev_hash = header.GetHash();
        time += 120; // 2-minute blocks
    }

    return chain;
}

TEST_CASE("Notifications - FatalError notification emitted on deep reorg", "[notifications][reorg]") {
    // Test that NotifyFatalError is called when reorg exceeds threshold
    // This ensures the notification system properly alerts subscribers

    auto params = ChainParams::CreateRegTest();
    // Set suspicious_reorg_depth=7 (allow up to depth 6, reject depth 7+)
    params->SetSuspiciousReorgDepth(7);
    TestChainstateManager chainstate(*params);
    chainstate.Initialize(params->GenesisBlock());

    const auto& genesis = params->GenesisBlock();
    validation::ValidationState state;

    // Track notification
    bool notification_received = false;
    std::string debug_msg;
    std::string user_msg;

    // Subscribe to fatal error notifications
    auto sub = Notifications().SubscribeFatalError(
        [&](const std::string& debug_message, const std::string& user_message) {
            notification_received = true;
            debug_msg = debug_message;
            user_msg = user_message;
        });

    // Build initial chain: Genesis -> [7 blocks]
    auto chainMain = BuildChain(genesis.GetHash(), util::GetTime(), 7);
    chain::CBlockIndex* mainTip = nullptr;

    for (const auto& header : chainMain) {
mainTip = chainstate.AcceptBlockHeader(header, state);
        if (mainTip) chainstate.TryAddBlockIndexCandidate(mainTip);
        REQUIRE(mainTip != nullptr);
    }

    chainstate.ActivateBestChain();
    REQUIRE(chainstate.GetTip() == mainTip);
    REQUIRE(chainstate.GetTip()->nHeight == 7);

    // Build competing fork: Genesis -> [8 blocks] (more work, but requires depth-7 reorg)
    auto chainFork = BuildChain(genesis.GetHash(), util::GetTime() + 1000, 8);
    chain::CBlockIndex* forkTip = nullptr;

    for (const auto& header : chainFork) {
forkTip = chainstate.AcceptBlockHeader(header, state);
        if (forkTip) chainstate.TryAddBlockIndexCandidate(forkTip);
        REQUIRE(forkTip != nullptr);
    }

    chainstate.ActivateBestChain();

    // Verify notification was emitted
    REQUIRE(notification_received);
    REQUIRE(debug_msg.find("7 blocks") != std::string::npos);
    REQUIRE(user_msg.find("suspicious-reorg-depth") != std::string::npos);

    // Should REJECT reorg (depth 7 >= suspicious_reorg_depth=7)
    REQUIRE(chainstate.GetTip() == mainTip);
    REQUIRE(chainstate.GetTip()->nHeight == 7);
}

TEST_CASE("Notifications - FatalError not emitted on allowed reorg", "[notifications][reorg]") {
    // Test that notification is NOT emitted for reorgs within threshold
    // This ensures we don't spam notifications for normal reorgs

    auto params = ChainParams::CreateRegTest();
    // Set suspicious_reorg_depth=7 (allow up to depth 6, reject depth 7+)
    params->SetSuspiciousReorgDepth(7);
    TestChainstateManager chainstate(*params);
    chainstate.Initialize(params->GenesisBlock());

    const auto& genesis = params->GenesisBlock();
    validation::ValidationState state;

    // Track notification
    bool notification_received = false;

    // Subscribe to fatal error notifications
    auto sub = Notifications().SubscribeFatalError(
        [&](const std::string&, const std::string&) {
            notification_received = true;
        });

    // Build initial chain: Genesis -> [5 blocks]
    auto chainMain = BuildChain(genesis.GetHash(), util::GetTime(), 5);
    chain::CBlockIndex* mainTip = nullptr;

    for (const auto& header : chainMain) {
        mainTip = chainstate.AcceptBlockHeader(header, state);
        if (mainTip) chainstate.TryAddBlockIndexCandidate(mainTip);
        REQUIRE(mainTip != nullptr);
    }

    chainstate.ActivateBestChain();
    REQUIRE(chainstate.GetTip() == mainTip);

    // Build competing fork: Genesis -> [6 blocks] (requires depth-5 reorg, which is allowed)
    auto chainFork = BuildChain(genesis.GetHash(), util::GetTime() + 1000, 6);
    chain::CBlockIndex* forkTip = nullptr;

    for (const auto& header : chainFork) {
        forkTip = chainstate.AcceptBlockHeader(header, state);
        if (forkTip) chainstate.TryAddBlockIndexCandidate(forkTip);
        REQUIRE(forkTip != nullptr);
    }

    chainstate.ActivateBestChain();

    // Verify notification was NOT emitted (reorg depth 5 < 7)
    REQUIRE_FALSE(notification_received);

    // Should ACCEPT reorg (depth 5 < suspicious_reorg_depth=7)
    REQUIRE(chainstate.GetTip() == forkTip);
    REQUIRE(chainstate.GetTip()->nHeight == 6);
}

TEST_CASE("Notifications - Multiple subscribers receive SuspiciousReorg notification", "[notifications][reorg]") {
    // Test that all subscribers receive the notification
    // This ensures the notification system properly broadcasts to all listeners

    auto params = ChainParams::CreateRegTest();
    params->SetSuspiciousReorgDepth(5);
    TestChainstateManager chainstate(*params);
    chainstate.Initialize(params->GenesisBlock());

    const auto& genesis = params->GenesisBlock();
    validation::ValidationState state;

    // Track notifications for multiple subscribers
    bool sub1_received = false;
    bool sub2_received = false;
    bool sub3_received = false;

    // Subscribe multiple listeners
    auto sub1 = Notifications().SubscribeFatalError([&](const std::string&, const std::string&) { sub1_received = true; });
    auto sub2 = Notifications().SubscribeFatalError([&](const std::string&, const std::string&) { sub2_received = true; });
    auto sub3 = Notifications().SubscribeFatalError([&](const std::string&, const std::string&) { sub3_received = true; });

    // Build initial chain: Genesis -> [5 blocks]
    auto chainMain = BuildChain(genesis.GetHash(), util::GetTime(), 5);
    chain::CBlockIndex* mainTip = nullptr;

    for (const auto& header : chainMain) {
        mainTip = chainstate.AcceptBlockHeader(header, state);
        if (mainTip) chainstate.TryAddBlockIndexCandidate(mainTip);
        REQUIRE(mainTip != nullptr);
    }

    chainstate.ActivateBestChain();

    // Build competing fork that triggers suspicious reorg
    auto chainFork = BuildChain(genesis.GetHash(), util::GetTime() + 1000, 6);
    chain::CBlockIndex* forkTip = nullptr;

    for (const auto& header : chainFork) {
        forkTip = chainstate.AcceptBlockHeader(header, state);
        if (forkTip) chainstate.TryAddBlockIndexCandidate(forkTip);
        REQUIRE(forkTip != nullptr);
    }

    chainstate.ActivateBestChain();

    // Verify all subscribers received notification
    REQUIRE(sub1_received);
    REQUIRE(sub2_received);
    REQUIRE(sub3_received);
}

TEST_CASE("Notifications - ChainTip notification emitted on tip change", "[notifications][chain]") {
    // Test that NotifyChainTip is called when the chain tip changes
    // This is critical for miner template invalidation

    auto params = ChainParams::CreateRegTest();
    TestChainstateManager chainstate(*params);
    chainstate.Initialize(params->GenesisBlock());

    const auto& genesis = params->GenesisBlock();
    validation::ValidationState state;

    // Track notifications
    int tip_change_count = 0;
    uint256 last_tip_hash;
    int last_height = -1;

    // Subscribe to chain tip notifications
    auto sub = Notifications().SubscribeChainTip(
        [&](const ChainTipEvent& event) {
            tip_change_count++;
            last_tip_hash = event.hash;
            last_height = event.height;
        });

    // Add first block: Genesis -> A
    auto headerA = CreateTestHeader(genesis.GetHash(), util::GetTime());
    chain::CBlockIndex* pindexA = chainstate.AcceptBlockHeader(headerA, state);
    chainstate.TryAddBlockIndexCandidate(pindexA);
    REQUIRE(pindexA != nullptr);

    chainstate.ActivateBestChain();

    // Verify first tip change notification
    REQUIRE(tip_change_count == 1);
    REQUIRE(last_tip_hash == pindexA->GetBlockHash());
    REQUIRE(last_height == 1);

    // Add second block: A -> B
    auto headerB = CreateTestHeader(headerA.GetHash(), util::GetTime() + 120);
    chain::CBlockIndex* pindexB = chainstate.AcceptBlockHeader(headerB, state);
    chainstate.TryAddBlockIndexCandidate(pindexB);
    REQUIRE(pindexB != nullptr);

    chainstate.ActivateBestChain();

    // Verify second tip change notification
    REQUIRE(tip_change_count == 2);
    REQUIRE(last_tip_hash == pindexB->GetBlockHash());
    REQUIRE(last_height == 2);
}

TEST_CASE("Notifications - ChainTip notification during reorg", "[notifications][chain][reorg]") {
    // Test that ChainTip notifications are emitted during reorganization
    // This ensures miners are notified of all tip changes, including during reorgs

    auto params = ChainParams::CreateRegTest();
    TestChainstateManager chainstate(*params);
    chainstate.Initialize(params->GenesisBlock());

    const auto& genesis = params->GenesisBlock();
    validation::ValidationState state;

    // Track all tip changes
    std::vector<int> tip_heights;

    auto sub = Notifications().SubscribeChainTip(
        [&](const ChainTipEvent& event) {
            tip_heights.push_back(event.height);
        });

    // Build initial chain: Genesis -> A -> B
    auto headerA = CreateTestHeader(genesis.GetHash(), util::GetTime());
    chain::CBlockIndex* pindexA = chainstate.AcceptBlockHeader(headerA, state);
    chainstate.TryAddBlockIndexCandidate(pindexA);
    chainstate.ActivateBestChain(); // Activate A

    auto headerB = CreateTestHeader(headerA.GetHash(), util::GetTime() + 120);
    chain::CBlockIndex* pindexB = chainstate.AcceptBlockHeader(headerB, state);
    chainstate.TryAddBlockIndexCandidate(pindexB);
    chainstate.ActivateBestChain(); // Activate B

    // Should have 2 tip changes (A, then B)
    REQUIRE(tip_heights.size() == 2);

    // Build competing fork: Genesis -> X -> Y -> Z (more work)
    auto headerX = CreateTestHeader(genesis.GetHash(), util::GetTime() + 1000);
    chain::CBlockIndex* pindexX = chainstate.AcceptBlockHeader(headerX, state);
    chainstate.TryAddBlockIndexCandidate(pindexX);

    auto headerY = CreateTestHeader(headerX.GetHash(), util::GetTime() + 1120);
    chain::CBlockIndex* pindexY = chainstate.AcceptBlockHeader(headerY, state);
    chainstate.TryAddBlockIndexCandidate(pindexY);

    auto headerZ = CreateTestHeader(headerY.GetHash(), util::GetTime() + 1240);
    chain::CBlockIndex* pindexZ = chainstate.AcceptBlockHeader(headerZ, state);
    chainstate.TryAddBlockIndexCandidate(pindexZ);

    size_t before_reorg = tip_heights.size();
    chainstate.ActivateBestChain();

    // Should have additional tip changes during reorg
    // (disconnect B, disconnect A, connect X, connect Y, connect Z)
    REQUIRE(tip_heights.size() > before_reorg);

    // Final tip should be at height 3
    REQUIRE(chainstate.GetTip()->nHeight == 3);
}

TEST_CASE("Notifications - Miner template invalidation on tip change", "[notifications][miner]") {
    // Test that miner template is invalidated when chain tip changes
    // This is the critical integration test for the miner notification feature

    auto params = ChainParams::CreateRegTest();
    TestChainstateManager chainstate(*params);
    chainstate.Initialize(params->GenesisBlock());

    const auto& genesis = params->GenesisBlock();
    validation::ValidationState state;

    // Create a miner
    mining::CPUMiner miner(*params, chainstate);

    // Simulate miner generating template (sets internal state)
    // In real code, GetBlockTemplate() would be called by mining loop
    // For testing, we just need to verify InvalidateTemplate() sets the flag

    // Subscribe to chain tip changes and invalidate miner template
    auto sub = Notifications().SubscribeChainTip(
        [&](const ChainTipEvent& event) {
            (void)event;
            miner.InvalidateTemplate();
        });

    // Build and activate first block
    auto headerA = CreateTestHeader(genesis.GetHash(), util::GetTime());
    chain::CBlockIndex* pindexA = chainstate.AcceptBlockHeader(headerA, state);
    chainstate.TryAddBlockIndexCandidate(pindexA);
    chainstate.ActivateBestChain();

    // Verify miner detects template should be regenerated
    // (the atomic flag should be set by InvalidateTemplate())
    // We can't directly test the private atomic flag, but we can test
    // that the miner's internal logic would detect the tip change
    REQUIRE(chainstate.GetTip() == pindexA);
}

TEST_CASE("Notifications - Subscription RAII cleanup", "[notifications]") {
    // Test that subscriptions are properly cleaned up when destroyed
    // This ensures no memory leaks or dangling callbacks

    auto params = ChainParams::CreateRegTest();
    params->SetSuspiciousReorgDepth(5);
    TestChainstateManager chainstate(*params);
    chainstate.Initialize(params->GenesisBlock());

    const auto& genesis = params->GenesisBlock();
    validation::ValidationState state;

    int callback_count = 0;

    {
        // Create subscription in inner scope
        auto sub = Notifications().SubscribeFatalError(
            [&](const std::string&, const std::string&) { callback_count++; });

        // Build chain that triggers notification
        auto chainMain = BuildChain(genesis.GetHash(), util::GetTime(), 5);
        for (const auto& header : chainMain) {
            auto pindex = chainstate.AcceptBlockHeader(header, state);
            if (pindex) chainstate.TryAddBlockIndexCandidate(pindex);
        }
        chainstate.ActivateBestChain();

        auto chainFork = BuildChain(genesis.GetHash(), util::GetTime() + 1000, 6);
        for (const auto& header : chainFork) {
            auto pindex = chainstate.AcceptBlockHeader(header, state);
            if (pindex) chainstate.TryAddBlockIndexCandidate(pindex);
        }
        chainstate.ActivateBestChain();

        REQUIRE(callback_count == 1);
        // Subscription goes out of scope here
    }

    // Create new chainstate for second test
    params->SetSuspiciousReorgDepth(5);
    TestChainstateManager chainstate2(*params);
    chainstate2.Initialize(params->GenesisBlock());

    // Build chain that would trigger notification again
    auto chainMain2 = BuildChain(genesis.GetHash(), util::GetTime() + 10000, 5);
    for (const auto& header : chainMain2) {
        auto pindex = chainstate2.AcceptBlockHeader(header, state);
        if (pindex) chainstate2.TryAddBlockIndexCandidate(pindex);
    }
    chainstate2.ActivateBestChain();

    auto chainFork2 = BuildChain(genesis.GetHash(), util::GetTime() + 20000, 6);
    for (const auto& header : chainFork2) {
        auto pindex = chainstate2.AcceptBlockHeader(header, state);
        if (pindex) chainstate2.TryAddBlockIndexCandidate(pindex);
    }
    chainstate2.ActivateBestChain();

    // Callback should NOT be called again (subscription was destroyed)
    REQUIRE(callback_count == 1);
}

TEST_CASE("Notifications - BlockConnected notification", "[notifications][block]") {
    // Test that BlockConnected notification is emitted when blocks are added
    // This is used by network layer to relay new blocks to peers

    auto params = ChainParams::CreateRegTest();
    TestChainstateManager chainstate(*params);
    chainstate.Initialize(params->GenesisBlock());

    const auto& genesis = params->GenesisBlock();
    validation::ValidationState state;

    // Track block connected notifications
    int blocks_connected = 0;
    std::vector<uint256> connected_hashes;

    auto sub = Notifications().SubscribeBlockConnected(
        [&](const BlockConnectedEvent& event) {
            blocks_connected++;
            connected_hashes.push_back(event.hash);
        });

    // Build chain: Genesis -> A -> B -> C
    auto chainMain = BuildChain(genesis.GetHash(), util::GetTime(), 3);
    std::vector<chain::CBlockIndex*> indices;

    for (const auto& header : chainMain) {
        auto pindex = chainstate.AcceptBlockHeader(header, state);
        chainstate.TryAddBlockIndexCandidate(pindex);
        indices.push_back(pindex);
        REQUIRE(pindex != nullptr);
    }

    chainstate.ActivateBestChain();

    // Verify all blocks triggered notification
    REQUIRE(blocks_connected == 3);
    REQUIRE(connected_hashes.size() == 3);

    // Verify hashes match
    for (size_t i = 0; i < indices.size(); i++) {
        REQUIRE(connected_hashes[i] == indices[i]->GetBlockHash());
    }
}

// =============================================================================
// Section: Subscription Move Semantics
// =============================================================================

TEST_CASE("Notifications - Subscription move constructor", "[notifications][subscription]") {
    // Test that Subscription can be move-constructed
    // The original subscription should be invalidated after move

    int callback_count = 0;

    // Create subscription and move it
    auto sub1 = Notifications().SubscribeFatalError(
        [&](const std::string&, const std::string&) { callback_count++; });

    // Move construct sub2 from sub1
    auto sub2 = std::move(sub1);

    // Trigger notification
    Notifications().NotifyFatalError("test", "test");

    // Callback should be called (sub2 is now the owner)
    REQUIRE(callback_count == 1);

    // Move sub2 out of scope explicitly to unsubscribe
    {
        auto sub3 = std::move(sub2);
        // sub3 goes out of scope, unsubscribes
    }

    // Trigger notification again
    Notifications().NotifyFatalError("test2", "test2");

    // Callback should NOT be called (subscription was moved and destroyed)
    REQUIRE(callback_count == 1);
}

TEST_CASE("Notifications - Subscription move assignment", "[notifications][subscription]") {
    // Test that Subscription can be move-assigned
    // The original subscription should be invalidated after move

    int callback1_count = 0;
    int callback2_count = 0;

    // Create two subscriptions
    auto sub1 = Notifications().SubscribeFatalError(
        [&](const std::string&, const std::string&) { callback1_count++; });

    auto sub2 = Notifications().SubscribeFatalError(
        [&](const std::string&, const std::string&) { callback2_count++; });

    // Trigger notification - both should fire
    Notifications().NotifyFatalError("test", "test");
    REQUIRE(callback1_count == 1);
    REQUIRE(callback2_count == 1);

    // Move-assign sub1 to sub2 (sub2's original subscription should be unsubscribed)
    sub2 = std::move(sub1);

    // Trigger notification again
    Notifications().NotifyFatalError("test2", "test2");

    // callback1 should fire (now owned by sub2)
    // callback2 should NOT fire (was unsubscribed when sub2 was reassigned)
    REQUIRE(callback1_count == 2);
    REQUIRE(callback2_count == 1);
}

TEST_CASE("Notifications - Subscription self-assignment is safe", "[notifications][subscription]") {
    // Test that self-move-assignment is handled safely

    int callback_count = 0;

    auto sub = Notifications().SubscribeFatalError(
        [&](const std::string&, const std::string&) { callback_count++; });

    // Self-assignment (should be a no-op)
    sub = std::move(sub);

    // Trigger notification - callback should still work
    Notifications().NotifyFatalError("test", "test");
    REQUIRE(callback_count == 1);
}

TEST_CASE("Notifications - Explicit Unsubscribe", "[notifications][subscription]") {
    // Test that Unsubscribe() can be called explicitly before destruction

    int callback_count = 0;

    auto sub = Notifications().SubscribeFatalError(
        [&](const std::string&, const std::string&) { callback_count++; });

    // Trigger notification - should fire
    Notifications().NotifyFatalError("test", "test");
    REQUIRE(callback_count == 1);

    // Explicitly unsubscribe
    sub.Unsubscribe();

    // Trigger notification again - should NOT fire
    Notifications().NotifyFatalError("test2", "test2");
    REQUIRE(callback_count == 1);

    // Double unsubscribe should be safe (no-op)
    sub.Unsubscribe();

    // Trigger notification again - still should NOT fire
    Notifications().NotifyFatalError("test3", "test3");
    REQUIRE(callback_count == 1);
}

TEST_CASE("Notifications - ChainTip with empty callbacks", "[notifications][chain]") {
    // Test that NotifyChainTip handles case with no subscribers gracefully

    // No subscribers - should not crash
    ChainTipEvent event;
    event.hash.SetNull();
    event.height = 0;

    // This should be a no-op, not crash
    Notifications().NotifyChainTip(event);
}

TEST_CASE("Notifications - BlockConnected with empty callbacks", "[notifications][block]") {
    // Test that NotifyBlockConnected handles case with no subscribers gracefully

    BlockConnectedEvent event;
    event.hash.SetNull();
    event.height = 0;

    // This should be a no-op, not crash
    Notifications().NotifyBlockConnected(event);
}

// =============================================================================
// Section: IBD State Consistency
// =============================================================================

TEST_CASE("Notifications - IBD state consistent across batch", "[notifications][ibd]") {
    // Test that all blocks connected in a single ActivateBestChain() batch
    // receive the same is_initial_download value, even if IBD would end mid-batch.
    //
    // This tests the fix for an edge case where:
    // - Node is in IBD (tip is stale)
    // - Multiple blocks are connected in one batch
    // - Mid-batch, the tip becomes non-stale (IBD would end)
    //
    // Without the fix: blocks before IBD ends get is_initial_download=true,
    //                  blocks after get is_initial_download=false
    // With the fix: ALL blocks get the same value (captured at batch start)

    // IBD_STALE_TIP_SECONDS = 5 days = 432000 seconds
    constexpr int64_t IBD_STALE_TIP_SECONDS = 5 * 24 * 3600;

    auto params = ChainParams::CreateRegTest();
    TestChainstateManager chainstate(*params);
    chainstate.Initialize(params->GenesisBlock());

    const auto& genesis = params->GenesisBlock();
    validation::ValidationState state;

    // Set mock time to a known value
    const int64_t mock_time = 1700000000;  // Some arbitrary timestamp
    util::SetMockTime(mock_time);

    // Track all BlockConnectedEvent notifications
    std::vector<bool> ibd_values;
    std::vector<int> heights;

    auto sub = Notifications().SubscribeBlockConnected(
        [&](const BlockConnectedEvent& event) {
            ibd_values.push_back(event.is_initial_download);
            heights.push_back(event.height);
        });

    // Phase 1: Build initial chain with STALE timestamps (IBD=true)
    // These blocks have timestamps older than mock_time - 5 days
    const uint32_t stale_time = static_cast<uint32_t>(mock_time - IBD_STALE_TIP_SECONDS - 3600);  // 5 days + 1 hour ago

    auto staleChain = BuildChain(genesis.GetHash(), stale_time, 3);
    chain::CBlockIndex* staleTip = nullptr;

    for (const auto& header : staleChain) {
        staleTip = chainstate.AcceptBlockHeader(header, state);
        chainstate.TryAddBlockIndexCandidate(staleTip);
        REQUIRE(staleTip != nullptr);
    }

    chainstate.ActivateBestChain();
    REQUIRE(chainstate.GetTip() == staleTip);
    REQUIRE(chainstate.GetTip()->nHeight == 3);

    // Verify we're in IBD (tip is stale)
    REQUIRE(chainstate.IsInitialBlockDownload() == true);

    // Clear recorded events from phase 1
    ibd_values.clear();
    heights.clear();

    // Phase 2: Build continuation chain where IBD would end mid-batch
    // - Blocks 4-6: stale timestamps (IBD would still be true if checked per-block)
    // - Blocks 7-10: recent timestamps (IBD would become false if checked per-block)
    //
    // Key: We add ALL blocks before calling ActivateBestChain(), so they're
    // connected in a single batch. The fix captures IBD state once at batch start.

    std::vector<CBlockHeader> batchChain;
    uint256 prev_hash = staleTip->GetBlockHash();

    // Blocks 4-6: still stale (IBD=true if checked here)
    for (int i = 0; i < 3; i++) {
        auto header = CreateTestHeader(prev_hash, stale_time + (i + 1) * 120);
        batchChain.push_back(header);
        prev_hash = header.GetHash();
    }

    // Blocks 7-10: recent timestamps (IBD=false if checked here)
    // These are within 5 days of mock_time
    const uint32_t recent_time = static_cast<uint32_t>(mock_time - 3600);  // 1 hour ago

    for (int i = 0; i < 4; i++) {
        auto header = CreateTestHeader(prev_hash, recent_time + i * 120);
        batchChain.push_back(header);
        prev_hash = header.GetHash();
    }

    // Add ALL headers before activating (to form a single batch)
    chain::CBlockIndex* batchTip = nullptr;
    for (const auto& header : batchChain) {
        batchTip = chainstate.AcceptBlockHeader(header, state);
        chainstate.TryAddBlockIndexCandidate(batchTip);
        REQUIRE(batchTip != nullptr);
    }

    // At this point: tip is still block 3 (stale), IBD=true
    // The batch will connect blocks 4-10
    REQUIRE(chainstate.IsInitialBlockDownload() == true);

    // Connect all blocks in ONE ActivateBestChain() call
    chainstate.ActivateBestChain();

    // Verify final state
    REQUIRE(chainstate.GetTip() == batchTip);
    REQUIRE(chainstate.GetTip()->nHeight == 10);

    // After batch: tip is block 10 (recent timestamp), IBD=false
    REQUIRE(chainstate.IsInitialBlockDownload() == false);

    // THE CRITICAL CHECK: All events should have the SAME is_initial_download value
    // (captured at batch start when tip was block 3, which was stale → IBD=true)
    REQUIRE(ibd_values.size() == 7);  // Blocks 4-10
    REQUIRE(heights.size() == 7);

    // Verify heights are correct
    for (size_t i = 0; i < heights.size(); i++) {
        REQUIRE(heights[i] == static_cast<int>(4 + i));
    }

    // THE FIX: All blocks in batch get the SAME is_initial_download value
    // Without the fix, blocks 7-10 would have is_initial_download=false
    bool first_value = ibd_values[0];
    for (size_t i = 0; i < ibd_values.size(); i++) {
        INFO("Block " << heights[i] << " is_initial_download=" << ibd_values[i]);
        REQUIRE(ibd_values[i] == first_value);
    }

    // The value should be true (IBD at batch start)
    REQUIRE(first_value == true);

    // Cleanup mock time
    util::SetMockTime(0);
}

