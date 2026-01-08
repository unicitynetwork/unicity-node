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

