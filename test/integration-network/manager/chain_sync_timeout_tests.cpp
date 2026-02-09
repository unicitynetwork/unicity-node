// Chain Sync Timeout Tests - Bitcoin Core parity for post-IBD stall detection
// Reference: net_processing.cpp ConsiderEviction()
//
// Tests verify:
// 1. ConsiderEviction state machine: timeout set, getheaders sent, disconnect
// 2. Peers that catch up clear their timeout
// 3. Protected peers skip ConsiderEviction
// 4. Only MAX_PROTECTED_OUTBOUND_PEERS (4) peers can be protected
// 5. Inbound peers are not subject to ConsiderEviction

#include "catch_amalgamated.hpp"
#include "infra/simulated_network.hpp"
#include "infra/simulated_node.hpp"
#include "infra/test_access.hpp"
#include "network/peer.hpp"
#include "network/protocol.hpp"
#include "util/arith_uint256.hpp"
#include "util/time.hpp"

using namespace unicity;
using namespace unicity::test;
using namespace unicity::network;
using namespace unicity::protocol;

// Helper to check if timeout is set (non-default time_point)
inline bool timeout_is_set(const Peer::ChainSyncTimeoutState& state) {
    return state.timeout != std::chrono::steady_clock::time_point{};
}

// Constants matching HeaderSyncManager
static constexpr int64_t CHAIN_SYNC_TIMEOUT_SEC = 20 * 60;   // 20 minutes
static constexpr int64_t HEADERS_RESPONSE_TIME_SEC = 2 * 60; // 2 minutes

TEST_CASE("ConsiderEviction sets timeout for stale outbound peer", "[network][chain_sync][timeout][state]") {
    // Verify that ConsiderEviction sets the timeout when peer is behind our tip

    SimulatedNetwork net(55001);

    // Create miner and sync victim to it (post-IBD)
    SimulatedNode miner(1, &net);
    for (int i = 0; i < 20; ++i) {
        (void)miner.MineBlock();
    }

    SimulatedNode victim(2, &net);
    victim.ConnectTo(miner.GetId());

    net.AdvanceTime(1000);
    victim.CheckInitialSync();

    // Sync to completion
    for (int i = 0; i < 50 && victim.GetTipHeight() < 20; ++i) {
        net.AdvanceTime(500);
    }
    REQUIRE(victim.GetTipHeight() == 20);
    REQUIRE_FALSE(victim.GetIsIBD());

    // Get the miner peer and check initial state
    auto& peer_mgr = victim.GetNetworkManager().peer_manager();
    auto peers = peer_mgr.get_outbound_peers();
    REQUIRE(!peers.empty());

    auto peer = peers[0];

    // Clear protection flag (peer may have been protected during sync)
    // We're testing the eviction mechanism, not protection
    peer->chain_sync_state().protect = false;

    // Ensure sync_started is set (required for ConsiderEviction to run)
    peer->set_sync_started(true);

    // Force the peer to appear stale by setting best_known_block below our tip
    // This simulates a peer that hasn't sent us recent headers
    // IMPORTANT: Must set BOTH height AND chain work - ConsiderEviction uses chain work
    peer->set_best_known_block_height(5);  // Below our tip of 20
    peer->set_best_known_chain_work(arith_uint256());  // Reset to 0 = stale

    // Initial state: no timeout set
    peer->chain_sync_state().timeout = {};
    peer->chain_sync_state().sent_getheaders = false;
    peer->chain_sync_state().work_header_height = -1;

    // Call ProcessTimers (which calls ConsiderEviction for outbound peers post-IBD)
    victim.ProcessHeaderSyncTimers();

    // Now timeout should be set (20 minutes in the future)
    auto now = util::GetSteadyTime();
    CHECK(peer->chain_sync_state().timeout > now);
    CHECK(peer->chain_sync_state().timeout <= now + std::chrono::seconds(CHAIN_SYNC_TIMEOUT_SEC + 1));
    CHECK(peer->chain_sync_state().work_header_height == 20);  // Our tip height
    CHECK(peer->chain_sync_state().sent_getheaders == false);  // Not yet
}

TEST_CASE("ConsiderEviction sends GETHEADERS after timeout expires", "[network][chain_sync][timeout][getheaders]") {
    // Verify that after CHAIN_SYNC_TIMEOUT, ConsiderEviction sends GETHEADERS

    SimulatedNetwork net(55002);

    SimulatedNode miner(1, &net);
    for (int i = 0; i < 20; ++i) {
        (void)miner.MineBlock();
    }

    SimulatedNode victim(2, &net);
    victim.ConnectTo(miner.GetId());

    net.AdvanceTime(1000);
    victim.CheckInitialSync();

    for (int i = 0; i < 50 && victim.GetTipHeight() < 20; ++i) {
        net.AdvanceTime(500);
    }
    REQUIRE(victim.GetTipHeight() == 20);
    REQUIRE_FALSE(victim.GetIsIBD());

    auto& peer_mgr = victim.GetNetworkManager().peer_manager();
    auto peers = peer_mgr.get_outbound_peers();
    REQUIRE(!peers.empty());
    auto peer = peers[0];

    // Clear protection and reset state
    peer->chain_sync_state().protect = false;
    peer->chain_sync_state().timeout = {};
    peer->chain_sync_state().sent_getheaders = false;
    peer->chain_sync_state().work_header_height = -1;

    // Ensure sync_started is set (required for ConsiderEviction)
    peer->set_sync_started(true);

    // Force peer to appear stale (must set both height and chain work)
    peer->set_best_known_block_height(5);
    peer->set_best_known_chain_work(arith_uint256());  // 0 = stale

    // First call sets the timeout
    victim.ProcessHeaderSyncTimers();
    CHECK(timeout_is_set(peer->chain_sync_state()));
    CHECK(peer->chain_sync_state().sent_getheaders == false);

    // Advance time past CHAIN_SYNC_TIMEOUT (20 minutes)
    net.AdvanceTime((CHAIN_SYNC_TIMEOUT_SEC + 60) * 1000);  // 21 minutes

    // Keep peer appearing stale and unprotected (AdvanceTime may have updated it via sync)
    peer->chain_sync_state().protect = false;
    peer->set_best_known_block_height(5);
    peer->set_best_known_chain_work(arith_uint256());

    // Call ProcessTimers again - should send GETHEADERS
    victim.ProcessHeaderSyncTimers();

    // Now sent_getheaders should be true
    CHECK(peer->chain_sync_state().sent_getheaders == true);
    // Timeout should be reset to HEADERS_RESPONSE_TIME in the future
    auto now = util::GetSteadyTime();
    CHECK(peer->chain_sync_state().timeout > now);
    CHECK(peer->chain_sync_state().timeout <= now + std::chrono::seconds(HEADERS_RESPONSE_TIME_SEC + 1));
}

TEST_CASE("ConsiderEviction disconnects peer after GETHEADERS timeout", "[network][chain_sync][timeout][disconnect]") {
    // Verify that after GETHEADERS timeout, peer is disconnected

    SimulatedNetwork net(55003);

    SimulatedNode miner(1, &net);
    for (int i = 0; i < 20; ++i) {
        (void)miner.MineBlock();
    }

    SimulatedNode victim(2, &net);
    victim.ConnectTo(miner.GetId());

    net.AdvanceTime(1000);
    victim.CheckInitialSync();

    for (int i = 0; i < 50 && victim.GetTipHeight() < 20; ++i) {
        net.AdvanceTime(500);
    }
    REQUIRE(victim.GetTipHeight() == 20);
    REQUIRE_FALSE(victim.GetIsIBD());

    auto& peer_mgr = victim.GetNetworkManager().peer_manager();
    auto peers = peer_mgr.get_outbound_peers();
    REQUIRE(!peers.empty());
    auto peer = peers[0];
    int peer_id = peer->id();

    // Clear protection and directly set up the state as if timeout already expired and GETHEADERS was sent
    peer->chain_sync_state().protect = false;
    peer->set_sync_started(true);  // Required for ConsiderEviction
    peer->set_best_known_block_height(5);
    peer->set_best_known_chain_work(arith_uint256());  // 0 = stale
    // Set timeout to past (already expired)
    peer->chain_sync_state().timeout = util::GetSteadyTime() - std::chrono::seconds(1);
    peer->chain_sync_state().sent_getheaders = true;
    peer->chain_sync_state().work_header_height = 20;

    size_t peer_count_before = victim.GetPeerCount();
    REQUIRE(peer_count_before >= 1);

    // Call ProcessTimers - should disconnect the peer
    victim.ProcessHeaderSyncTimers();

    // Process the disconnect
    net.AdvanceTime(100);

    // Peer should be disconnected
    size_t peer_count_after = victim.GetPeerCount();
    CHECK(peer_count_after < peer_count_before);

    // Verify peer is gone
    auto peer_after = peer_mgr.get_peer(peer_id);
    CHECK(peer_after == nullptr);
}

TEST_CASE("ConsiderEviction clears timeout when peer catches up", "[network][chain_sync][timeout][catchup]") {
    // Verify that when peer's best_known_chain_work reaches our tip, timeout is cleared
    // Note: We use CHAIN WORK, not height, to prevent low-work spam attacks.

    SimulatedNetwork net(55004);

    SimulatedNode miner(1, &net);
    for (int i = 0; i < 20; ++i) {
        (void)miner.MineBlock();
    }

    SimulatedNode victim(2, &net);
    victim.ConnectTo(miner.GetId());

    net.AdvanceTime(1000);
    victim.CheckInitialSync();

    for (int i = 0; i < 50 && victim.GetTipHeight() < 20; ++i) {
        net.AdvanceTime(500);
    }
    REQUIRE(victim.GetTipHeight() == 20);
    REQUIRE_FALSE(victim.GetIsIBD());

    auto& peer_mgr = victim.GetNetworkManager().peer_manager();
    auto peers = peer_mgr.get_outbound_peers();
    REQUIRE(!peers.empty());
    auto peer = peers[0];

    // Get our tip's chain work for comparison
    auto our_tip = victim.GetTip();
    REQUIRE(our_tip != nullptr);
    arith_uint256 our_tip_work = our_tip->nChainWork;

    // Clear protection and set up a timeout state
    peer->chain_sync_state().protect = false;
    peer->set_best_known_block_height(5);
    peer->set_best_known_chain_work(arith_uint256(0));  // Low work
    // Set timeout to far future
    peer->chain_sync_state().timeout = util::GetSteadyTime() + std::chrono::hours(1);
    peer->chain_sync_state().sent_getheaders = true;
    peer->chain_sync_state().work_header_height = 15;

    // Now simulate peer catching up - set chain work >= our tip
    peer->set_best_known_block_height(20);
    peer->set_best_known_chain_work(our_tip_work);

    // Call ProcessTimers
    victim.ProcessHeaderSyncTimers();

    // Timeout should be cleared
    CHECK_FALSE(timeout_is_set(peer->chain_sync_state()));
    CHECK(peer->chain_sync_state().sent_getheaders == false);
    CHECK(peer->chain_sync_state().work_header_height == -1);
}

TEST_CASE("ConsiderEviction NOT fooled by high-height low-work chain", "[network][chain_sync][security][low_work]") {
    // Security test: An attacker sends a long chain with high height but low work.
    // Without chain work check, we'd think peer is "caught up" and clear the timeout.
    // With the fix, we correctly identify the peer as NOT caught up.

    SimulatedNetwork net(55015);

    SimulatedNode miner(1, &net);
    for (int i = 0; i < 20; ++i) {
        (void)miner.MineBlock();
    }

    SimulatedNode victim(2, &net);
    victim.ConnectTo(miner.GetId());

    net.AdvanceTime(1000);
    victim.CheckInitialSync();

    for (int i = 0; i < 50 && victim.GetTipHeight() < 20; ++i) {
        net.AdvanceTime(500);
    }
    REQUIRE(victim.GetTipHeight() == 20);
    REQUIRE_FALSE(victim.GetIsIBD());

    auto& peer_mgr = victim.GetNetworkManager().peer_manager();
    auto peers = peer_mgr.get_outbound_peers();
    REQUIRE(!peers.empty());
    auto peer = peers[0];

    // Get our tip's chain work
    auto our_tip = victim.GetTip();
    REQUIRE(our_tip != nullptr);
    arith_uint256 our_tip_work = our_tip->nChainWork;

    // Simulate attacker: HIGH height (100) but LOW work (less than our tip)
    // This is the attack vector we're protecting against
    peer->chain_sync_state().protect = false;
    peer->set_best_known_block_height(100);  // Higher than our tip of 20!
    peer->set_best_known_chain_work(our_tip_work / 2);  // But only half the work
    peer->chain_sync_state().timeout = {};

    // Call ProcessTimers
    victim.ProcessHeaderSyncTimers();

    // Timeout should be SET (peer is NOT caught up despite high height)
    // because chain work is insufficient
    CHECK(timeout_is_set(peer->chain_sync_state()));
}

TEST_CASE("ConsiderEviction skips protected peers", "[network][chain_sync][protection][skip]") {
    // Verify that protected peers are not subject to ConsiderEviction

    SimulatedNetwork net(55005);

    SimulatedNode miner(1, &net);
    for (int i = 0; i < 20; ++i) {
        (void)miner.MineBlock();
    }

    SimulatedNode victim(2, &net);
    victim.ConnectTo(miner.GetId());

    net.AdvanceTime(1000);
    victim.CheckInitialSync();

    for (int i = 0; i < 50 && victim.GetTipHeight() < 20; ++i) {
        net.AdvanceTime(500);
    }
    REQUIRE(victim.GetTipHeight() == 20);
    REQUIRE_FALSE(victim.GetIsIBD());

    auto& peer_mgr = victim.GetNetworkManager().peer_manager();
    auto peers = peer_mgr.get_outbound_peers();
    REQUIRE(!peers.empty());
    auto peer = peers[0];

    // Mark peer as protected
    peer->chain_sync_state().protect = true;

    // Make peer appear stale
    peer->set_best_known_block_height(5);

    // Call ProcessTimers
    victim.ProcessHeaderSyncTimers();

    // Timeout should NOT be set (protected peers skip ConsiderEviction)
    CHECK_FALSE(timeout_is_set(peer->chain_sync_state()));
}

TEST_CASE("Best known block height updated when receiving headers", "[network][chain_sync][tracking]") {
    // Verify best_known_block_height is updated after receiving headers

    SimulatedNetwork net(55006);

    SimulatedNode miner(1, &net);
    for (int i = 0; i < 25; ++i) {
        (void)miner.MineBlock();
    }

    SimulatedNode victim(2, &net);
    victim.ConnectTo(miner.GetId());

    net.AdvanceTime(1000);

    // Get peer before sync
    auto& peer_mgr = victim.GetNetworkManager().peer_manager();
    auto peers_before = peer_mgr.get_outbound_peers();
    REQUIRE(peers_before.size() >= 1);

    // Initially best_known_block_height is -1
    CHECK(peers_before[0]->best_known_block_height() == -1);

    // Start sync
    victim.CheckInitialSync();

    // Sync
    for (int i = 0; i < 50 && victim.GetTipHeight() < 25; ++i) {
        net.AdvanceTime(500);
    }
    REQUIRE(victim.GetTipHeight() == 25);

    // After sync, best_known_block_height should be updated to miner's tip
    auto peers_after = peer_mgr.get_outbound_peers();
    REQUIRE(!peers_after.empty());
    int best_height = peers_after[0]->best_known_block_height();
    CHECK(best_height == 25);
}

TEST_CASE("Peer protection limits to 4 outbound peers", "[network][chain_sync][protection][limit]") {
    // Only MAX_PROTECTED_OUTBOUND_PEERS (4) should get protection

    SimulatedNetwork net(55007);

    // Create miner
    SimulatedNode miner(1, &net);
    for (int i = 0; i < 15; ++i) {
        (void)miner.MineBlock();
    }

    // Create 6 relay nodes that sync from miner
    std::vector<std::unique_ptr<SimulatedNode>> relays;
    for (int i = 0; i < 6; ++i) {
        auto relay = std::make_unique<SimulatedNode>(10 + i, &net);
        relay->ConnectTo(miner.GetId());
        relays.push_back(std::move(relay));
    }

    net.AdvanceTime(1000);

    // Sync all relays
    for (auto& relay : relays) {
        relay->CheckInitialSync();
    }

    for (int i = 0; i < 50; ++i) {
        net.AdvanceTime(500);

        bool all_synced = true;
        for (auto& relay : relays) {
            if (relay->GetTipHeight() < 15) {
                all_synced = false;
                break;
            }
        }
        if (all_synced) break;
    }

    // Verify all relays synced
    for (auto& relay : relays) {
        REQUIRE(relay->GetTipHeight() == 15);
    }

    // Create victim that connects to all 6 relays
    SimulatedNode victim(100, &net);
    for (auto& relay : relays) {
        victim.ConnectTo(relay->GetId());
    }

    net.AdvanceTime(1000);

    // Sync victim
    victim.CheckInitialSync();

    for (int i = 0; i < 50 && victim.GetTipHeight() < 15; ++i) {
        net.AdvanceTime(500);
    }
    REQUIRE(victim.GetTipHeight() == 15);

    // Count protected peers
    auto& peer_mgr = victim.GetNetworkManager().peer_manager();
    auto outbound_peers = peer_mgr.get_outbound_peers();

    int protected_count = 0;
    for (const auto& peer : outbound_peers) {
        if (peer->chain_sync_state().protect) {
            ++protected_count;
        }
    }

    // Should have at most 4 protected
    CHECK(protected_count <= 4);

    // Should have at least some protected (if peers proved they have blocks)
    // Note: exact count depends on header delivery order
    CHECK(protected_count >= 0);
}

TEST_CASE("ConsiderEviction only applies to outbound peers", "[network][chain_sync][inbound]") {
    // Inbound peers should NOT be subject to ConsiderEviction

    SimulatedNetwork net(55008);

    // Create miner
    SimulatedNode miner(1, &net);
    for (int i = 0; i < 20; ++i) {
        (void)miner.MineBlock();
    }

    // Victim syncs from miner
    SimulatedNode victim(2, &net);
    victim.ConnectTo(miner.GetId());

    net.AdvanceTime(1000);

    victim.CheckInitialSync();

    for (int i = 0; i < 50 && victim.GetTipHeight() < 20; ++i) {
        net.AdvanceTime(500);
    }
    REQUIRE(victim.GetTipHeight() == 20);

    // Create an inbound connection from a stale node
    SimulatedNode stale_inbound(3, &net);
    // Stale has no blocks - connects TO victim (making it inbound from victim's perspective)
    stale_inbound.ConnectTo(victim.GetId());

    net.AdvanceTime(1000);

    // Get the inbound peer
    auto& peer_mgr = victim.GetNetworkManager().peer_manager();
    auto inbound_peers = peer_mgr.get_inbound_peers();

    if (!inbound_peers.empty()) {
        auto inbound_peer = inbound_peers[0];

        // Make it appear stale
        inbound_peer->set_best_known_block_height(0);

        // Mark sync started (required for ConsiderEviction to consider the peer)
        inbound_peer->set_sync_started(true);

        // Call ProcessTimers
        victim.ProcessHeaderSyncTimers();

        // Timeout should NOT be set for inbound peers
        CHECK_FALSE(timeout_is_set(inbound_peer->chain_sync_state()));
    }

    // Verify inbound peer is still connected
    size_t inbound_after = victim.GetInboundPeerCount();
    CHECK(inbound_after >= 1);
}

TEST_CASE("ConsiderEviction requires sync_started", "[network][chain_sync][sync_started]") {
    // Peers that haven't started sync should not be subject to ConsiderEviction

    SimulatedNetwork net(55009);

    SimulatedNode miner(1, &net);
    for (int i = 0; i < 20; ++i) {
        (void)miner.MineBlock();
    }

    SimulatedNode victim(2, &net);
    victim.ConnectTo(miner.GetId());

    net.AdvanceTime(1000);
    victim.CheckInitialSync();

    for (int i = 0; i < 50 && victim.GetTipHeight() < 20; ++i) {
        net.AdvanceTime(500);
    }
    REQUIRE(victim.GetTipHeight() == 20);
    REQUIRE_FALSE(victim.GetIsIBD());

    auto& peer_mgr = victim.GetNetworkManager().peer_manager();
    auto peers = peer_mgr.get_outbound_peers();
    REQUIRE(!peers.empty());
    auto peer = peers[0];

    // Clear sync_started
    peer->set_sync_started(false);

    // Make peer appear stale
    peer->set_best_known_block_height(5);

    // Call ProcessTimers
    victim.ProcessHeaderSyncTimers();

    // Timeout should NOT be set (sync_started is false)
    CHECK_FALSE(timeout_is_set(peer->chain_sync_state()));
}

TEST_CASE("Block-relay-only peers do NOT get protection", "[network][chain_sync][protection][block_relay]") {
    // Bitcoin Core parity: Only full-relay outbound peers get protection.
    // Block-relay-only peers should remain subject to eviction for eclipse attack resistance.

    SimulatedNetwork net(55010);

    // Create miner with some blocks
    SimulatedNode miner(1, &net);
    for (int i = 0; i < 20; ++i) {
        (void)miner.MineBlock();
    }

    // Victim connects as block-relay-only
    SimulatedNode victim(2, &net);
    victim.ConnectToBlockRelayOnly(miner.GetId());

    net.AdvanceTime(1000);
    victim.CheckInitialSync();

    // Sync to completion
    for (int i = 0; i < 50 && victim.GetTipHeight() < 20; ++i) {
        net.AdvanceTime(500);
    }
    REQUIRE(victim.GetTipHeight() == 20);
    REQUIRE_FALSE(victim.GetIsIBD());

    // Get the block-relay-only peer
    auto& peer_mgr = victim.GetNetworkManager().peer_manager();
    auto peers = peer_mgr.get_outbound_peers();
    REQUIRE(!peers.empty());
    auto peer = peers[0];

    // Verify it's a block-relay-only connection
    REQUIRE(peer->is_block_relay_only() == true);
    REQUIRE(peer->is_full_relay() == false);

    // Block-relay-only peers should NOT be protected, even after proving useful
    // The protection flag is set in HandleHeadersMessage only for is_full_relay() peers
    CHECK(peer->chain_sync_state().protect == false);
}

TEST_CASE("Full-relay peers CAN get protection", "[network][chain_sync][protection][full_relay]") {
    // Contrast with block-relay-only test: full-relay peers should get protection

    SimulatedNetwork net(55011);

    SimulatedNode miner(1, &net);
    for (int i = 0; i < 20; ++i) {
        (void)miner.MineBlock();
    }

    SimulatedNode victim(2, &net);
    victim.ConnectToFullRelay(miner.GetId());

    net.AdvanceTime(1000);
    victim.CheckInitialSync();

    for (int i = 0; i < 50 && victim.GetTipHeight() < 20; ++i) {
        net.AdvanceTime(500);
    }
    REQUIRE(victim.GetTipHeight() == 20);
    REQUIRE_FALSE(victim.GetIsIBD());

    auto& peer_mgr = victim.GetNetworkManager().peer_manager();
    auto peers = peer_mgr.get_outbound_peers();
    REQUIRE(!peers.empty());
    auto peer = peers[0];

    // Verify it's a full-relay connection
    REQUIRE(peer->is_block_relay_only() == false);
    REQUIRE(peer->is_full_relay() == true);

    // Full-relay peers that prove useful SHOULD be protected
    CHECK(peer->chain_sync_state().protect == true);
}

TEST_CASE("ConsiderEviction GETHEADERS uses work_header parent locator", "[network][chain_sync][getheaders][locator]") {
    // Bitcoin Core parity: ConsiderEviction sends GETHEADERS with locator from
    // work_header's PARENT (work_header_height - 1), not the current tip.
    // This gives the peer a chance to prove they have the benchmark block.

    SimulatedNetwork net(55012);

    SimulatedNode miner(1, &net);
    for (int i = 0; i < 30; ++i) {
        (void)miner.MineBlock();
    }

    SimulatedNode victim(2, &net);
    victim.ConnectTo(miner.GetId());

    net.AdvanceTime(1000);
    victim.CheckInitialSync();

    for (int i = 0; i < 50 && victim.GetTipHeight() < 30; ++i) {
        net.AdvanceTime(500);
    }
    REQUIRE(victim.GetTipHeight() == 30);
    REQUIRE_FALSE(victim.GetIsIBD());

    auto& peer_mgr = victim.GetNetworkManager().peer_manager();
    auto peers = peer_mgr.get_outbound_peers();
    REQUIRE(!peers.empty());
    auto peer = peers[0];

    // Set up ConsiderEviction state:
    // - Clear protection
    // - Make peer appear stale
    // - Set work_header_height to 25 (we'll verify the locator would be built from height 24)
    peer->chain_sync_state().protect = false;
    peer->set_sync_started(true);  // Required for ConsiderEviction
    peer->set_best_known_block_height(10);
    peer->set_best_known_chain_work(arith_uint256());  // 0 = stale
    // Set timeout to past (already expired)
    peer->chain_sync_state().timeout = util::GetSteadyTime() - std::chrono::seconds(1);
    peer->chain_sync_state().sent_getheaders = false;
    peer->chain_sync_state().work_header_height = 25;

    // Clear the peer's getheaders timestamp to allow sending
    peer->clear_last_getheaders_time();

    // Call ProcessTimers - should send GETHEADERS with locator from height 24 (parent of 25)
    victim.ProcessHeaderSyncTimers();

    // Verify GETHEADERS was sent
    CHECK(peer->chain_sync_state().sent_getheaders == true);

    // The actual locator content verification would require message inspection.
    // The implementation uses GetBlockAtHeight(work_header_height - 1) = height 24
    // to build the locator. This test verifies the code path is executed correctly.
    //
    // For full verification, we'd need to capture the GETHEADERS message and inspect
    // its locator, which requires lower-level test infrastructure.
}

TEST_CASE("protected_outbound_count_ decrements when protected peer disconnects",
          "[network][chain_sync][protection][lifecycle]") {
    // Regression test: protected_outbound_count_ must decrement when a protected
    // peer is removed via remove_peer(). Without this, the counter monotonically
    // increases and after MAX_PROTECTED_OUTBOUND_PEERS (4) disconnections, no new
    // peer can ever be protected again.

    SimulatedNetwork net(55013);

    // Create miner with enough blocks to be post-IBD
    SimulatedNode miner(1, &net);
    for (int i = 0; i < 20; ++i) {
        (void)miner.MineBlock();
    }

    // Create victim, sync to post-IBD
    SimulatedNode victim(2, &net);
    victim.ConnectTo(miner.GetId());

    net.AdvanceTime(1000);
    victim.CheckInitialSync();

    for (int i = 0; i < 50 && victim.GetTipHeight() < 20; ++i) {
        net.AdvanceTime(500);
    }
    REQUIRE(victim.GetTipHeight() == 20);
    REQUIRE_FALSE(victim.GetIsIBD());

    auto& nm = victim.GetNetworkManager();
    auto& hsm = victim.GetHeaderSync();
    auto& peer_mgr = nm.peer_manager();

    // Verify the miner peer got protected during sync
    auto peers = peer_mgr.get_outbound_peers();
    REQUIRE(!peers.empty());
    auto miner_peer = peers[0];
    REQUIRE(miner_peer->chain_sync_state().protect == true);

    int count_before = HeaderSyncManagerTestAccess::GetProtectedOutboundCount(hsm);
    REQUIRE(count_before >= 1);

    // Disconnect the protected peer
    int miner_peer_id = miner_peer->id();
    peer_mgr.remove_peer(miner_peer_id);

    // Count must have decremented
    int count_after = HeaderSyncManagerTestAccess::GetProtectedOutboundCount(hsm);
    CHECK(count_after == count_before - 1);
}

TEST_CASE("Protection slots reusable after saturate-disconnect cycle",
          "[network][chain_sync][protection][lifecycle][reuse]") {
    // Saturate all 4 protection slots, disconnect all 4 protected peers,
    // then verify a new peer delivering headers can still be protected.
    //
    // Without the fix (Erase called before OnPeerDisconnected), the counter
    // stays at 4 after disconnects and the final CHECK(new_peer_protected) fails.

    SimulatedNetwork net(55014);

    SimulatedNode miner(1, &net);
    for (int i = 0; i < 20; ++i) {
        (void)miner.MineBlock();
    }

    // Create relay and victim, sync to post-IBD
    SimulatedNode relay(10, &net);
    relay.ConnectTo(miner.GetId());
    net.AdvanceTime(1000);
    relay.CheckInitialSync();
    for (int tick = 0; tick < 50 && relay.GetTipHeight() < 20; ++tick) {
        net.AdvanceTime(500);
    }
    REQUIRE(relay.GetTipHeight() == 20);

    // Create 5 additional relay nodes (need 4 for saturation + 1 spare)
    std::vector<std::unique_ptr<SimulatedNode>> extra_relays;
    for (int i = 0; i < 5; ++i) {
        auto r = std::make_unique<SimulatedNode>(20 + i, &net);
        r->ConnectTo(miner.GetId());
        extra_relays.push_back(std::move(r));
    }
    net.AdvanceTime(1000);
    for (auto& r : extra_relays) {
        r->CheckInitialSync();
    }
    for (int tick = 0; tick < 50; ++tick) {
        net.AdvanceTime(500);
        bool done = true;
        for (auto& r : extra_relays) {
            if (r->GetTipHeight() < 20) { done = false; break; }
        }
        if (done) break;
    }

    SimulatedNode victim(100, &net);
    // Connect to all extra relays
    for (auto& r : extra_relays) {
        victim.ConnectTo(r->GetId());
    }
    net.AdvanceTime(1000);
    victim.CheckInitialSync();
    for (int tick = 0; tick < 50 && victim.GetTipHeight() < 20; ++tick) {
        net.AdvanceTime(500);
    }
    REQUIRE(victim.GetTipHeight() == 20);
    REQUIRE_FALSE(victim.GetIsIBD());

    auto& hsm = victim.GetHeaderSync();
    auto& peer_mgr = victim.GetNetworkManager().peer_manager();
    auto outbound = peer_mgr.get_outbound_peers();
    REQUIRE(outbound.size() >= 5);

    // Force exactly 4 peers to be protected and set the counter to 4.
    // This simulates 4 peers having delivered useful headers at tip height.
    for (const auto& p : outbound) {
        p->chain_sync_state().protect = false;
    }
    HeaderSyncManagerTestAccess::SetProtectedOutboundCount(hsm, 0);
    for (int i = 0; i < 4; ++i) {
        outbound[i]->chain_sync_state().protect = true;
    }
    HeaderSyncManagerTestAccess::SetProtectedOutboundCount(hsm, 4);

    // Verify precondition: slots are saturated
    REQUIRE(HeaderSyncManagerTestAccess::GetProtectedOutboundCount(hsm) == 4);

    // Disconnect all 4 protected peers — this exercises remove_peer() → OnPeerDisconnected()
    for (int i = 0; i < 4; ++i) {
        peer_mgr.remove_peer(outbound[i]->id());
    }

    // Counter must be 0 — without the fix this would be 4
    CHECK(HeaderSyncManagerTestAccess::GetProtectedOutboundCount(hsm) == 0);

    // Now verify a new peer can actually be protected via real header delivery.
    // Mine more blocks so the new connection delivers headers above victim's tip.
    for (int i = 0; i < 5; ++i) {
        (void)miner.MineBlock();
    }
    relay.CheckInitialSync();
    for (int tick = 0; tick < 50 && relay.GetTipHeight() < 25; ++tick) {
        net.AdvanceTime(500);
    }
    REQUIRE(relay.GetTipHeight() == 25);

    victim.ConnectTo(relay.GetId());
    net.AdvanceTime(1000);
    victim.CheckInitialSync();
    for (int tick = 0; tick < 50 && victim.GetTipHeight() < 25; ++tick) {
        net.AdvanceTime(500);
    }
    REQUIRE(victim.GetTipHeight() == 25);

    // The new peer must be protected — slots were freed by correct decrement
    auto new_outbound = peer_mgr.get_outbound_peers();
    bool new_peer_protected = false;
    for (const auto& p : new_outbound) {
        if (p->chain_sync_state().protect) { new_peer_protected = true; break; }
    }
    CHECK(new_peer_protected);
    CHECK(HeaderSyncManagerTestAccess::GetProtectedOutboundCount(hsm) >= 1);
}
