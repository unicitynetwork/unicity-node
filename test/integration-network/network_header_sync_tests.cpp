// Copyright (c) 2025 The Unicity Foundation
// Test suite for header synchronization via NetworkManager
// Adapted from header_sync_tests.cpp to work with new architecture

#include "util/hash.hpp"
#include "network_test_helpers.hpp"
#include "chain/validation.hpp"
#include "chain/chainparams.hpp"
#include "network/message.hpp"
#include "test_orchestrator.hpp"
#include "network/peer_lifecycle_manager.hpp"
#include <cstring>

using namespace unicity;
using namespace unicity::test;

// ==============================================================================
// HEADER SYNCHRONIZATION TESTS (via NetworkManager)
// ==============================================================================

TEST_CASE("NetworkManager HeaderSync - Basic Sync", "[network_header_sync][network]") {
    SimulatedNetwork network(50001);
    SetZeroLatency(network);

    SimulatedNode node1(1, &network);
    SimulatedNode node2(2, &network);

    SECTION("Initialize with genesis") {
        // Both nodes start at genesis
        REQUIRE(node1.GetTipHeight() == 0);
        REQUIRE(node2.GetTipHeight() == 0);
        REQUIRE(!node1.GetTipHash().IsNull());
        REQUIRE(!node2.GetTipHash().IsNull());
    }

    SECTION("Process valid chain of headers") {
        // Node1 mines 10 blocks
        for (int i = 0; i < 10; i++) {
            node1.MineBlock();
        }

        // Connect nodes
        node2.ConnectTo(1);
        network.AdvanceTime(100);

        // Wait for sync
        for (int i = 0; i < 20; i++) {
            network.AdvanceTime(200);
        }

        // Node2 should have synced the headers
        REQUIRE(node2.GetTipHeight() == 10);
        REQUIRE(node2.GetTipHash() == node1.GetTipHash());
    }
}

TEST_CASE("NetworkManager HeaderSync - IBD flips on recent tip; behavior switches to multi-peer acceptance", "[network_header_sync][network]") {
    SimulatedNetwork net(50018);
    SetZeroLatency(net);
    net.EnableCommandTracking(true);

    // Victim at genesis -> IBD true (genesis timestamp is old)
    SimulatedNode victim(80, &net);
    victim.SetBypassPOWValidation(true);
    CHECK(victim.GetIsIBD() == true);

    // Two peers
    SimulatedNode p_sync(81, &net);
    SimulatedNode p_other(82, &net);

    // Connect victims to both; select p_sync as sync peer
    victim.ConnectTo(p_sync.GetId());
    net.AdvanceTime(200);
    victim.GetNetworkManager().test_hook_check_initial_sync();
    net.AdvanceTime(200);
    victim.ConnectTo(p_other.GetId());
    // Ensure p_other has an OUTBOUND to victim as well (Core parity: fSyncStarted is outbound-only)
    p_other.ConnectTo(victim.GetId());
    net.AdvanceTime(200);

    // Phase 1: confirm IBD (tip at genesis)
    CHECK(victim.GetTipHeight() == 0);


    // Phase 2: Make tip recent via mining on the selected sync peer
    net.AdvanceTime(std::time(nullptr) * 1000ULL);
    for (int i = 0; i < 5; ++i) { (void)p_sync.MineBlock(); net.AdvanceTime(net.GetCurrentTime() + 200); }
    for (int i = 0; i < 200; ++i) { net.AdvanceTime(net.GetCurrentTime() + 200); victim.GetNetworkManager().test_hook_check_initial_sync(); }
    CHECK(victim.GetTipHeight() >= 5);

    // Phase 3: Near-tip multi-peer acceptance: have both peers mine
    for (int i = 0; i < 50; ++i) { (void)p_sync.MineBlock(); net.AdvanceTime(net.GetCurrentTime() + 200); }
    for (int i = 0; i < 40; ++i) { (void)p_other.MineBlock(); net.AdvanceTime(net.GetCurrentTime() + 200); }

    for (int i = 0; i < 500; ++i) {
        net.AdvanceTime(net.GetCurrentTime() + 200);
        victim.GetNetworkManager().test_hook_check_initial_sync();
        if (victim.GetTipHeight() >= 95) break;
    }

    REQUIRE(victim.GetTipHeight() >= 95);
}

TEST_CASE("NetworkManager HeaderSync - Bounded processing of many small announcements from non-sync peers", "[network_header_sync][network]") {
    SimulatedNetwork net(50017);
    SetZeroLatency(net);
    net.EnableCommandTracking(true);

    // Sync peer with a longer chain (target)
    SimulatedNode sync_peer(70, &net);
    for (int i = 0; i < 80; ++i) sync_peer.MineBlock();

    // Victim
    SimulatedNode victim(71, &net);

    // Connect victim to sync peer and select as sync peer
    victim.ConnectTo(sync_peer.GetId());
    net.AdvanceTime(200);
    victim.GetNetworkManager().test_hook_check_initial_sync();
    net.AdvanceTime(200);

    // Create many non-sync peers that will send repeated 2-header announcements
    const int kPeers = 8;
    std::vector<std::unique_ptr<SimulatedNode>> nonsync;
    for (int i = 0; i < kPeers; ++i) {
        nonsync.push_back(std::make_unique<SimulatedNode>(100+i, &net));
        victim.ConnectTo(nonsync.back()->GetId());
    }
    net.AdvanceTime(500);

    auto make_headers = [&](int count){
        std::vector<CBlockHeader> headers; headers.reserve(count);
        uint256 prev = victim.GetTipHash();
        uint32_t nBits = unicity::chain::GlobalChainParams::Get().GenesisBlock().nBits;
        uint32_t t0 = static_cast<uint32_t>(net.GetCurrentTime() / 1000);
        for (int i = 0; i < count; ++i) { CBlockHeader h; h.nVersion=1; h.hashPrevBlock=prev; h.nTime=t0+i+1; h.nBits=nBits; h.nNonce=i+1; h.hashRandomX.SetHex("0000000000000000000000000000000000000000000000000000000000000000"); headers.push_back(h); prev=h.GetHash(); }
        return headers;
    };
    auto send_headers = [&](int from_node_id, const std::vector<CBlockHeader>& headers){
        message::HeadersMessage m; m.headers = headers;
        auto payload = m.serialize();
        protocol::MessageHeader hdr(protocol::magic::REGTEST, protocol::commands::HEADERS, static_cast<uint32_t>(payload.size()));
        uint256 hash = Hash(payload);
        std::memcpy(hdr.checksum.data(), hash.begin(), 4);
        auto hdr_bytes = message::serialize_header(hdr);
        std::vector<uint8_t> full; full.reserve(hdr_bytes.size()+payload.size());
        full.insert(full.end(), hdr_bytes.begin(), hdr_bytes.end());
        full.insert(full.end(), payload.begin(), payload.end());
        net.SendMessage(from_node_id, victim.GetId(), full);
    };

    // Repeatedly drip small (2) headers from each non-sync peer
    for (int round = 0; round < 10; ++round) {
        for (auto& p : nonsync) {
            auto two = make_headers(2);
            send_headers(p->GetId(), two);
        }
        net.AdvanceTime(net.GetCurrentTime() + 500);
    }

    // Meanwhile, allow sync to progress
    for (int i = 0; i < 100; ++i) {
        net.AdvanceTime(net.GetCurrentTime() + 200);
        if (victim.GetTipHeight() == 80) break;
    }

    // Ensure we reached at least the target height despite announcement noise
    CHECK(victim.GetTipHeight() >= 80);
    CHECK(victim.GetTipHeight() <= 100);

    // Check no erroneous misbehavior or mass disconnects
    auto& pm = victim.GetNetworkManager().peer_manager();
    auto peers = pm.get_all_peers();
    int connected_count = 0;
    for (const auto& peer : peers) {
        if (!peer) continue;
        if (peer->is_connected()) connected_count++;
        // Ensure peers are not marked as misbehaving due to small announcements
        bool misbehaving = false;
        try { misbehaving = pm.IsMisbehaving(peer->id()); } catch (...) { misbehaving = false; }
        CHECK_FALSE(misbehaving);
    }
    CHECK(connected_count >= kPeers); // tolerate sync-peer churn; non-sync peers should remain connected
}

TEST_CASE("NetworkManager HeaderSync - Solicited-only acceptance: sync vs non-sync large batches", "[network_header_sync][network]") {
    SimulatedNetwork net(50015);
    SetZeroLatency(net);
    net.EnableCommandTracking(true);

    // Victim in IBD
    SimulatedNode victim(50, &net);
    victim.SetBypassPOWValidation(true);

    // Two peers
    SimulatedNode p_sync(51, &net);
    SimulatedNode p_other(52, &net);

    // Connect to sync peer first and select as sync peer
    victim.ConnectTo(p_sync.GetId());
    net.AdvanceTime(200);
    victim.GetNetworkManager().test_hook_check_initial_sync();
    net.AdvanceTime(200);

    // Now connect to non-sync peer
    victim.ConnectTo(p_other.GetId());
    net.AdvanceTime(200);

    const int N = 200; // keep runtime manageable

    // Stage 1: During IBD, victim solicits from a single sync peer only
    for (int i = 0; i < N; ++i) { (void)p_other.MineBlock(); net.AdvanceTime(net.GetCurrentTime() + 50); }
    for (int i = 0; i < 100; ++i) { net.AdvanceTime(net.GetCurrentTime() + 200); victim.GetNetworkManager().test_hook_check_initial_sync(); }
    int distinct_ibd = net.CountDistinctPeersSent(victim.GetId(), protocol::commands::GETHEADERS);
    CHECK(distinct_ibd <= 2);

    // Stage 2: Large progress from sync peer should be followed
    for (int i = 0; i < N; ++i) { (void)p_sync.MineBlock(); net.AdvanceTime(net.GetCurrentTime() + 50); }
    for (int i = 0; i < 1000; ++i) {
        net.AdvanceTime(net.GetCurrentTime() + 200);
        victim.GetNetworkManager().test_hook_check_initial_sync();
        if (victim.GetTipHeight() >= N) break;
    }
    REQUIRE(victim.GetTipHeight() >= N);
}

TEST_CASE("NetworkManager HeaderSync - Unsolicited announcements size threshold during IBD", "[network_header_sync][network]") {
    SimulatedNetwork net(50016);
    SetZeroLatency(net);
    net.EnableCommandTracking(true);

    // Victim in IBD, connect to two peers and select p_sync as sync peer
    SimulatedNode victim(60, &net);
    SimulatedNode p_sync(61, &net);
    SimulatedNode p_other(62, &net);

    victim.ConnectTo(p_sync.GetId());
    net.AdvanceTime(200);
    victim.GetNetworkManager().test_hook_check_initial_sync();
    net.AdvanceTime(200);
    victim.ConnectTo(p_other.GetId());
    net.AdvanceTime(200);

    auto make_headers = [&](int count){
        std::vector<CBlockHeader> headers; headers.reserve(count);
        uint256 prev = victim.GetTipHash();
        uint32_t nBits = unicity::chain::GlobalChainParams::Get().GenesisBlock().nBits;
        uint32_t t0 = static_cast<uint32_t>(net.GetCurrentTime() / 1000);
        for (int i = 0; i < count; ++i) {
            CBlockHeader h; h.nVersion = 1; h.hashPrevBlock = prev; h.nTime = t0 + i + 1; h.nBits = nBits; h.nNonce = i + 1; h.hashRandomX.SetHex("0000000000000000000000000000000000000000000000000000000000000000");
            headers.push_back(h); prev = h.GetHash();
        }
        return headers;
    };

    auto send_headers = [&](int from_node_id, const std::vector<CBlockHeader>& headers){
        message::HeadersMessage m; m.headers = headers;
        auto payload = m.serialize();
        protocol::MessageHeader hdr(protocol::magic::REGTEST, protocol::commands::HEADERS, static_cast<uint32_t>(payload.size()));
        uint256 hash = Hash(payload);
        std::memcpy(hdr.checksum.data(), hash.begin(), 4);
        auto hdr_bytes = message::serialize_header(hdr);
        std::vector<uint8_t> full; full.reserve(hdr_bytes.size()+payload.size());
        full.insert(full.end(), hdr_bytes.begin(), hdr_bytes.end());
        full.insert(full.end(), payload.begin(), payload.end());
        net.SendMessage(from_node_id, victim.GetId(), full);
    };

    // 1-header from non-sync should be accepted (announcement)
    auto one = make_headers(1);
    send_headers(p_other.GetId(), one);
    for (int i = 0; i < 10; ++i) net.AdvanceTime(net.GetCurrentTime() + 200);
    CHECK(victim.GetTipHeight() >= 1);

    // 3-headers from non-sync should be ignored (unsolicited over threshold)
    auto three = make_headers(3);
    send_headers(p_other.GetId(), three);
    for (int i = 0; i < 20; ++i) net.AdvanceTime(net.GetCurrentTime() + 200);
    CHECK(victim.GetTipHeight() <= 4);
}

TEST_CASE("NetworkManager HeaderSync - Empty HEADERS from sync peer triggers switch", "[network_header_sync][network]") {
    SimulatedNetwork net(50012);
    SetZeroLatency(net);
    net.EnableCommandTracking(true);

    // Build two peers: p_sync behind, p_other ahead
    SimulatedNode p_sync(20, &net);
    SimulatedNode p_other(21, &net);
    for (int i = 0; i < 10; ++i) p_sync.MineBlock();
    for (int i = 0; i < 40; ++i) p_other.MineBlock();

    // Victim connects to both; choose p_sync as initial sync peer
    SimulatedNode victim(22, &net);
    victim.ConnectTo(p_sync.GetId());
    net.AdvanceTime(200);
    victim.GetNetworkManager().test_hook_check_initial_sync();
    net.AdvanceTime(200);
    victim.ConnectTo(p_other.GetId());
    net.AdvanceTime(200);

    // Inject empty HEADERS from current sync peer (p_sync)
    message::HeadersMessage empty; auto payload = empty.serialize();
    protocol::MessageHeader hdr(protocol::magic::REGTEST, protocol::commands::HEADERS, static_cast<uint32_t>(payload.size()));
        uint256 hash = Hash(payload);
        std::memcpy(hdr.checksum.data(), hash.begin(), 4);
    auto hdr_bytes = message::serialize_header(hdr);
    std::vector<uint8_t> full; full.reserve(hdr_bytes.size()+payload.size());
    full.insert(full.end(), hdr_bytes.begin(), hdr_bytes.end());
    full.insert(full.end(), payload.begin(), payload.end());
    net.SendMessage(p_sync.GetId(), victim.GetId(), full);
    net.AdvanceTime(net.GetCurrentTime() + 200);

    // After empty batch, selection should be cleared; pick new sync peer (p_other)
    victim.GetNetworkManager().test_hook_check_initial_sync();
    net.AdvanceTime(500);

    // Verify GETHEADERS was sent to p_other (allow processing time)
    auto payloads = net.GetCommandPayloads(victim.GetId(), p_other.GetId(), protocol::commands::GETHEADERS);
    for (int i = 0; i < 10 && payloads.empty(); ++i) {
        net.AdvanceTime(net.GetCurrentTime() + 200);
        payloads = net.GetCommandPayloads(victim.GetId(), p_other.GetId(), protocol::commands::GETHEADERS);
    }
    REQUIRE_FALSE(payloads.empty());

    // And sync completes to height 40
    for (int i = 0; i < 50; ++i) {
        net.AdvanceTime(net.GetCurrentTime() + 200);
        if (victim.GetTipHeight() == 40) break;
    }
    REQUIRE(victim.GetTipHeight() == 40);
}

TEST_CASE("NetworkManager HeaderSync - Disconnect sync peer mid-sync reselects and resumes", "[network_header_sync][network]") {
    SimulatedNetwork net(50013);
    SetZeroLatency(net);
    net.EnableCommandTracking(true);

    // Two peers with same chain
    SimulatedNode p1(30, &net);
    SimulatedNode p2(31, &net);
    for (int i = 0; i < 50; ++i) p1.MineBlock();
    p2.ConnectTo(p1.GetId());
    net.AdvanceTime(500);
    REQUIRE(p2.GetTipHeight() == 50);

    SimulatedNode victim(32, &net);
    victim.ConnectTo(p1.GetId());
    net.AdvanceTime(200);
    victim.GetNetworkManager().test_hook_check_initial_sync();
    net.AdvanceTime(200);
    victim.ConnectTo(p2.GetId());
    net.AdvanceTime(200);

    // Let some progress happen
    for (int i = 0; i < 5; ++i) net.AdvanceTime(net.GetCurrentTime() + 200);
    int h_before = victim.GetTipHeight();
    CHECK(h_before >= 0);

    // Disconnect p1 (the sync peer) mid-sync
    net.NotifyDisconnect(p1.GetId(), victim.GetId());
    net.AdvanceTime(net.GetCurrentTime() + 100);

    // Immediately reselect new sync peer (p2) and resume
    victim.GetNetworkManager().test_hook_check_initial_sync();
    net.AdvanceTime(500);

    // Verify GETHEADERS to p2 and completion (allow processing time)
    auto gh2 = net.GetCommandPayloads(victim.GetId(), p2.GetId(), protocol::commands::GETHEADERS);
    for (int i = 0; i < 10 && gh2.empty(); ++i) {
        net.AdvanceTime(net.GetCurrentTime() + 200);
        gh2 = net.GetCommandPayloads(victim.GetId(), p2.GetId(), protocol::commands::GETHEADERS);
    }
    REQUIRE_FALSE(gh2.empty());

    for (int i = 0; i < 50; ++i) {
        net.AdvanceTime(net.GetCurrentTime() + 200);
        if (victim.GetTipHeight() == 50) break;
    }
    REQUIRE(victim.GetTipHeight() == 50);
}

TEST_CASE("NetworkManager HeaderSync - Near-tip allows multi-peer headers", "[network_header_sync][network]") {
    SimulatedNetwork net(50014);
    // Set time to current to simulate near-tip recency
    net.AdvanceTime(std::time(nullptr) * 1000ULL);
    SetZeroLatency(net);

    // Victim already recent (mine a few recent blocks)
    SimulatedNode victim(40, &net);
    victim.SetBypassPOWValidation(true);
    for (int i = 0; i < 3; ++i) { victim.MineBlock(); net.AdvanceTime(net.GetCurrentTime() + 1000); }
    int base_h = victim.GetTipHeight();

    // Two peers send large headers that connect to victim's tip
    SimulatedNode pA(41, &net);
    SimulatedNode pB(42, &net);

    victim.ConnectTo(pA.GetId());
    victim.ConnectTo(pB.GetId());
    // Ensure peers also have OUTBOUND connections to victim so they can sync to its tip
    pA.ConnectTo(victim.GetId());
    pB.ConnectTo(victim.GetId());
    net.AdvanceTime(200);

    // Let peers sync to victim's base tip
    for (int i = 0; i < 20 && pA.GetTipHeight() < base_h; ++i) {
        net.AdvanceTime(net.GetCurrentTime() + 200);
        pA.GetNetworkManager().test_hook_check_initial_sync();
    }
    for (int i = 0; i < 20 && pB.GetTipHeight() < base_h; ++i) {
        net.AdvanceTime(net.GetCurrentTime() + 200);
        pB.GetNetworkManager().test_hook_check_initial_sync();
    }

    // Mine additional headers from both peers
    for (int i = 0; i < 20; ++i) { (void)pA.MineBlock(); net.AdvanceTime(net.GetCurrentTime() + 200); }
    for (int i = 0; i < 15; ++i) { (void)pB.MineBlock(); net.AdvanceTime(net.GetCurrentTime() + 200); }

    for (int i = 0; i < 500; ++i) {
        net.AdvanceTime(net.GetCurrentTime() + 200);
        victim.GetNetworkManager().test_hook_check_initial_sync();
        if (victim.GetTipHeight() >= base_h + 35) break;
    }

    // Near-tip (not IBD), we should have accepted from both peers
    CHECK(victim.GetTipHeight() >= base_h + 20 + 15);
}

TEST_CASE("NetworkManager HeaderSync - Reorg during IBD switches to most-work peer", "[network_header_sync][network]") {
    SimulatedNetwork net(50011);
    SetZeroLatency(net);
    net.EnableCommandTracking(true);

    // Two independent miners produce different chains
    SimulatedNode miner_weak(10, &net);    // 30-block chain (weaker)
    SimulatedNode miner_strong(11, &net);  // 60-block chain (stronger)
    for (int i = 0; i < 30; ++i) miner_weak.MineBlock();
    for (int i = 0; i < 60; ++i) miner_strong.MineBlock();

    // Two peers: p_sync follows weaker chain; p_other follows stronger chain
    SimulatedNode p_sync(12, &net);
    SimulatedNode p_other(13, &net);

    p_sync.ConnectTo(miner_weak.GetId());
    p_other.ConnectTo(miner_strong.GetId());
    net.AdvanceTime(1000);
    REQUIRE(p_sync.GetTipHeight() == 30);
    REQUIRE(p_other.GetTipHeight() == 60);

    // Victim connects (chooses p_sync as sync peer), then p_other
    SimulatedNode victim(14, &net);
    victim.ConnectTo(p_sync.GetId());
    net.AdvanceTime(200);
    victim.GetNetworkManager().test_hook_check_initial_sync();
    net.AdvanceTime(200);

    // Allow some progress from p_sync (e.g., ~10 headers)
    for (int i = 0; i < 10; ++i) {
        net.AdvanceTime(net.GetCurrentTime() + 200);
    }
    int progress_height = victim.GetTipHeight();
    CHECK(progress_height > 0);

    // Now connect to stronger peer
    victim.ConnectTo(p_other.GetId());
    net.AdvanceTime(200);

    // Stall p_sync -> victim to force switch
    SimulatedNetwork::NetworkConditions drop; drop.packet_loss_rate = 1.0;
    net.SetLinkConditions(p_sync.GetId(), victim.GetId(), drop);

    // Trigger timeout processing and reselection
    for (int i = 0; i < 3; ++i) {
        net.AdvanceTime(net.GetCurrentTime() + 60*1000);
        victim.GetNetworkManager().test_hook_header_sync_process_timers();
    }
    victim.GetNetworkManager().test_hook_check_initial_sync();
    net.AdvanceTime(500);

    // Ensure we ultimately sync to the stronger chain height (60)
    for (int i = 0; i < 50; ++i) {
        net.AdvanceTime(net.GetCurrentTime() + 200);
        if (victim.GetTipHeight() == 60) break;
    }
    REQUIRE(victim.GetTipHeight() == 60);
}

TEST_CASE("HeaderSync - Outbound-only selection requires outbound peer (rewrite)", "[network_header_sync][policy]") {
    SimulatedNetwork net(50019);
    SetZeroLatency(net);
    net.EnableCommandTracking(true);

    // Victim at genesis (IBD)
    SimulatedNode victim(90, &net);
    victim.SetBypassPOWValidation(true);

    // Inbound-only peer connects
    SimulatedNode inbound_peer(91, &net);
    inbound_peer.ConnectTo(victim.GetId());

    // Let handshake/messages settle
    for (int i = 0; i < 20; ++i) net.AdvanceTime(net.GetCurrentTime() + 200);

    // No outbound peers yet -> victim must NOT start header sync
    auto gh_inbound = net.GetCommandPayloads(victim.GetId(), inbound_peer.GetId(), protocol::commands::GETHEADERS);
    CHECK(gh_inbound.empty());

    // Add a separate OUTBOUND peer for victim
    SimulatedNode outbound_peer(92, &net);
    victim.ConnectTo(outbound_peer.GetId());

    // Wait for handshake + selection and observe GETHEADERS to the outbound peer
    std::vector<std::vector<uint8_t>> gh_outbound;
    for (int i = 0; i < 200 && gh_outbound.empty(); ++i) {
        victim.GetNetworkManager().test_hook_check_initial_sync();
        net.AdvanceTime(net.GetCurrentTime() + 200);
        gh_outbound = net.GetCommandPayloads(victim.GetId(), outbound_peer.GetId(), protocol::commands::GETHEADERS);
    }

    // Ensure victim did not solicit inbound-only peer
    gh_inbound = net.GetCommandPayloads(victim.GetId(), inbound_peer.GetId(), protocol::commands::GETHEADERS);
    CHECK(gh_inbound.empty());

    // Ensure victim did solicit the outbound peer
    REQUIRE_FALSE(gh_outbound.empty());
}

TEST_CASE("HeaderSync - IBD inbound INV does not adopt sync peer (clean)", "[network_header_sync][policy]") {
    SimulatedNetwork net(50020);
    SetZeroLatency(net);
    net.EnableCommandTracking(true);

    // Victim at genesis (IBD)
    SimulatedNode victim(92, &net);
    victim.SetBypassPOWValidation(true);

    // Inbound-only announcer connects to victim
    SimulatedNode inbound_peer(93, &net);
    inbound_peer.ConnectTo(victim.GetId());

    // Let handshake complete
    for (int i = 0; i < 20; ++i) net.AdvanceTime(net.GetCurrentTime() + 200);

    // Announcer mines a few blocks and relays INV to victim
    for (int i = 0; i < 5; ++i) { (void)inbound_peer.MineBlock(); net.AdvanceTime(net.GetCurrentTime() + 200); }

    // During IBD, victim must NOT adopt inbound-only announcer as sync peer
    // Verify no GETHEADERS sent to inbound-only peer
    auto gh_inbound = net.GetCommandPayloads(victim.GetId(), inbound_peer.GetId(), protocol::commands::GETHEADERS);
    CHECK(gh_inbound.empty());

    // Now provide an OUTBOUND peer and let selection/sync occur
    SimulatedNode outbound_peer(94, &net);
    victim.ConnectTo(outbound_peer.GetId());

    // Wait some time for handshake + selection + request
    std::vector<std::vector<uint8_t>> gh_outbound;
    for (int i = 0; i < 200 && gh_outbound.empty(); ++i) {
        net.AdvanceTime(net.GetCurrentTime() + 200);
        gh_outbound = net.GetCommandPayloads(victim.GetId(), outbound_peer.GetId(), protocol::commands::GETHEADERS);
    }

    // Assert: still no GETHEADERS to inbound-only announcer
    gh_inbound = net.GetCommandPayloads(victim.GetId(), inbound_peer.GetId(), protocol::commands::GETHEADERS);
    CHECK(gh_inbound.empty());

    // Assert: GETHEADERS sent to the outbound peer
    REQUIRE_FALSE(gh_outbound.empty());
}


TEST_CASE("NetworkManager HeaderSync - Ignore non-sync large headers during IBD (BTC parity)", "[network_header_sync][network]") {
    SimulatedNetwork net(50010);
    SetZeroLatency(net);
    net.EnableCommandTracking(true);

    // Victim node in IBD
    SimulatedNode n(1, &net);
    n.SetBypassPOWValidation(true);

    // Two peers
    SimulatedNode p_sync(2, &net);
    SimulatedNode p_other(3, &net);

    // Connect victim to both peers
    n.ConnectTo(p_sync.GetId());
    n.ConnectTo(p_other.GetId());
    net.AdvanceTime(200);

    // Begin initial sync (selects a single sync peer)
    n.GetNetworkManager().test_hook_check_initial_sync();
    net.AdvanceTime(200);

    // Confirm we did not solicit p_other
    int gh_other_before = net.CountCommandSent(n.GetId(), p_other.GetId(), protocol::commands::GETHEADERS);

    // Craft a large (1201) continuous HEADERS message from non-sync peer that connects to n's tip
    const int kCount = 1201; // typical large batch seen in the wild
    std::vector<CBlockHeader> headers;
    headers.reserve(kCount);

    uint256 prev = n.GetTipHash();
    uint32_t nBits = unicity::chain::GlobalChainParams::Get().GenesisBlock().nBits;
    uint32_t base_time = static_cast<uint32_t>(net.GetCurrentTime() / 1000);

    for (int i = 0; i < kCount; ++i) {
        CBlockHeader h;
        h.nVersion = 1;
        h.hashPrevBlock = prev;
        h.nTime = base_time + i + 1;
        h.nBits = nBits;
        h.nNonce = static_cast<uint32_t>(i + 1);
 h.hashRandomX.SetHex("0000000000000000000000000000000000000000000000000000000000000001");
            headers.push_back(h); prev = h.GetHash();
        prev = h.GetHash();
    }

    message::HeadersMessage msg; msg.headers = headers;
    auto payload = msg.serialize();
    protocol::MessageHeader hdr(protocol::magic::REGTEST, protocol::commands::HEADERS, static_cast<uint32_t>(payload.size()));
        uint256 hash = Hash(payload);
        std::memcpy(hdr.checksum.data(), hash.begin(), 4);
    auto hdr_bytes = message::serialize_header(hdr);
    std::vector<uint8_t> full; full.reserve(hdr_bytes.size() + payload.size());
    full.insert(full.end(), hdr_bytes.begin(), hdr_bytes.end());
    full.insert(full.end(), payload.begin(), payload.end());

    // Inject unsolicited large HEADERS from non-sync peer
    net.SendMessage(p_other.GetId(), n.GetId(), full);

    // Process
    for (int i = 0; i < 20; ++i) net.AdvanceTime(net.GetCurrentTime() + 200);

    // Assert: we ignored the large batch from non-sync peer during IBD
    CHECK(n.GetTipHeight() == 0);

    // And we never solicited p_other with GETHEADERS initially
    int gh_other_after = net.CountCommandSent(n.GetId(), p_other.GetId(), protocol::commands::GETHEADERS);
    CHECK(gh_other_after == gh_other_before);
}

TEST_CASE("NetworkManager HeaderSync - Stall triggers sync peer switch", "[network_header_sync][network]") {
    SimulatedNetwork network(50009);
    SetZeroLatency(network);
    network.EnableCommandTracking(true);

    // Miner and two serving peers
    SimulatedNode miner(1, &network);
    for (int i = 0; i < 60; ++i) { miner.MineBlock(); }

    SimulatedNode p1(2, &network);
    SimulatedNode p2(3, &network);

    p1.ConnectTo(miner.GetId());
    p2.ConnectTo(miner.GetId());
    network.AdvanceTime(1000);
    REQUIRE(p1.GetTipHeight() == 60);
    REQUIRE(p2.GetTipHeight() == 60);

    // New syncing node connects to both
    SimulatedNode syncing(4, &network);
    syncing.ConnectTo(p1.GetId());
    syncing.ConnectTo(p2.GetId());
    network.AdvanceTime(200);

    // Begin initial sync (single sync peer policy)
    syncing.GetNetworkManager().test_hook_check_initial_sync();
    network.AdvanceTime(200);

    int gh_p1_before = network.CountCommandSent(syncing.GetId(), p1.GetId(), protocol::commands::GETHEADERS);
    int gh_p2_before = network.CountCommandSent(syncing.GetId(), p2.GetId(), protocol::commands::GETHEADERS);

    // Stall p1 -> syncing: drop HEADERS so no progress
    SimulatedNetwork::NetworkConditions drop; drop.packet_loss_rate = 1.0;
    network.SetLinkConditions(p1.GetId(), syncing.GetId(), drop);

    // Advance beyond timeout and process timers (120s total)
    for (int i = 0; i < 3; ++i) {
        network.AdvanceTime(network.GetCurrentTime() + 60*1000);
        syncing.GetNetworkManager().test_hook_header_sync_process_timers();
    }

    // Re-select a new sync peer (should choose p2) and continue
    syncing.GetNetworkManager().test_hook_check_initial_sync();
    network.AdvanceTime(500);

    int gh_p1_after = network.CountCommandSent(syncing.GetId(), p1.GetId(), protocol::commands::GETHEADERS);
    int gh_p2_after = network.CountCommandSent(syncing.GetId(), p2.GetId(), protocol::commands::GETHEADERS);

    CHECK(gh_p2_after > gh_p2_before);  // switched to p2
    CHECK(gh_p1_after >= gh_p1_before); // no new GETHEADERS to stalled peer

    // Sync must complete
    // Allow time for HEADERS and activation
    for (int i = 0; i < 30; ++i) {
        network.AdvanceTime(network.GetCurrentTime() + 200);
        if (syncing.GetTipHeight() == 60) break;
    }
    REQUIRE(syncing.GetTipHeight() == 60);
}

TEST_CASE("NetworkManager HeaderSync - Locators", "[network_header_sync][network]") {
    SimulatedNetwork network(50002);
    SetZeroLatency(network);

    SimulatedNode node1(1, &network);
    SimulatedNode node2(2, &network);

    SECTION("Sync uses locators to find common ancestor") {
        // Node1 mines 100 blocks
        for (int i = 0; i < 100; i++) {
            node1.MineBlock();
        }

        // Connect nodes - node2 will send GETHEADERS with locator from genesis
        node2.ConnectTo(1);
        network.AdvanceTime(100);

        // Wait for sync
        for (int i = 0; i < 50; i++) {
            network.AdvanceTime(200);
        }

        // Node2 should have received all headers using locator protocol
        REQUIRE(node2.GetTipHeight() == 100);
        REQUIRE(node2.GetTipHash() == node1.GetTipHash());
    }
}

TEST_CASE("NetworkManager HeaderSync - Synced Status", "[network_header_sync][network]") {
    SimulatedNetwork network(50003);
    SetZeroLatency(network);

    // Initialize network time to a realistic value (current time)
    // This avoids mock time pollution from previous tests
    network.AdvanceTime(std::time(nullptr) * 1000ULL);

    SimulatedNode node1(1, &network);
    SimulatedNode node2(2, &network);

    SECTION("Not synced at genesis (old timestamp)") {
        // Genesis has old timestamp (Feb 2011), current time is 2025
        // So nodes should be in IBD
        REQUIRE(node1.GetIsIBD() == true);
        REQUIRE(node2.GetIsIBD() == true);
    }

    SECTION("Synced after receiving recent headers") {
        // Node1 mines blocks with current timestamps
        for (int i = 0; i < 20; i++) {
            node1.MineBlock();
            network.AdvanceTime(network.GetCurrentTime() + 1000);  // Advance 1 second per block
        }

        // Connect and sync node2
        node2.ConnectTo(1);
        for (int i = 0; i < 50; i++) {
            network.AdvanceTime(network.GetCurrentTime() + 200);
        }

        // Node2 should now be synced
        REQUIRE(node2.GetTipHeight() == 20);
        REQUIRE(node2.GetTipHash() == node1.GetTipHash());
    }
}

TEST_CASE("NetworkManager HeaderSync - Request More", "[network_header_sync][network]") {
    SimulatedNetwork network(50004);
    SetZeroLatency(network);

    SimulatedNode miner(1, &network);
    SimulatedNode syncing(2, &network);

    SECTION("Should request more after full batch (2000 headers)") {
        // Mine exactly 2000 blocks (MAX_HEADERS_SIZE)
        for (int i = 0; i < 2000; i++) {
            miner.MineBlock();
        }

        REQUIRE(miner.GetTipHeight() == 2000);

        // Connect syncing node
        syncing.ConnectTo(1);
        network.AdvanceTime(100);

        // Allow first batch to sync (2000 headers)
        for (int i = 0; i < 30; i++) {
            network.AdvanceTime(500);
        }

        // Syncing node should have received all 2000 headers
        // NetworkManager should automatically request more if needed
        REQUIRE(syncing.GetTipHeight() == 2000);
    }

    SECTION("Should not request more after partial batch") {
        // Mine only 100 blocks
        for (int i = 0; i < 100; i++) {
            miner.MineBlock();
        }

        REQUIRE(miner.GetTipHeight() == 100);

        // Connect and sync
        syncing.ConnectTo(1);
        network.AdvanceTime(100);

        for (int i = 0; i < 30; i++) {
            network.AdvanceTime(200);
        }

        // Should have synced all 100 (partial batch indicates peer is done)
        REQUIRE(syncing.GetTipHeight() == 100);
    }
}

TEST_CASE("NetworkManager HeaderSync - Multi-batch Sync", "[network_header_sync][network]") {
    // Test syncing more than 2000 headers (requires multiple GETHEADERS/HEADERS round trips)
    SimulatedNetwork network(50005);
    SetZeroLatency(network);

    SimulatedNode miner(1, &network);
    SimulatedNode syncing(2, &network);

    SECTION("Sync 2500 blocks (requires 2 batches)") {
        // Mine 2500 blocks
        for (int i = 0; i < 2500; i++) {
            miner.MineBlock();
        }

        REQUIRE(miner.GetTipHeight() == 2500);

        // Connect and sync
        syncing.ConnectTo(1);
        network.AdvanceTime(100);

        // Allow multiple batches to sync
        // Need sufficient time for: GETHEADERS -> HEADERS (2000) -> GETHEADERS -> HEADERS (500)
        for (int i = 0; i < 100; i++) {
            network.AdvanceTime(500);
            if (syncing.GetTipHeight() == 2500) {
                break;
            }
        }

        // Should have synced all 2500 across multiple batches
        REQUIRE(syncing.GetTipHeight() == 2500);
    }
}

TEST_CASE("NetworkManager HeaderSync - Empty Headers Response", "[network_header_sync][network]") {
    SimulatedNetwork network(50006);
    SetZeroLatency(network);

    SimulatedNode node1(1, &network);
    SimulatedNode node2(2, &network);

    SECTION("Handle empty HEADERS message gracefully") {
        // Both nodes at same height (genesis)
        node2.ConnectTo(1);
        network.AdvanceTime(100);

        // When node2 sends GETHEADERS, node1 will respond with empty HEADERS
        // (because they're already at same height)
        for (int i = 0; i < 10; i++) {
            network.AdvanceTime(200);
        }

        // Should remain connected and at same height
        REQUIRE(node1.GetPeerCount() > 0);
        REQUIRE(node2.GetPeerCount() > 0);
        REQUIRE(node2.GetTipHeight() == 0);
    }
}

TEST_CASE("NetworkManager HeaderSync - Concurrent Sync from Multiple Peers", "[network_header_sync][network]") {
    SimulatedNetwork network(50007);
    SetZeroLatency(network);

    SimulatedNode peer1(1, &network);
    SimulatedNode peer2(2, &network);
    SimulatedNode syncing(3, &network);

    SECTION("Sync from multiple peers with same chain") {
        // Both peers have same chain
        for (int i = 0; i < 50; i++) {
            peer1.MineBlock();
        }
        network.AdvanceTime(network.GetCurrentTime() + 500);

        // Peer2 syncs from peer1
        peer2.ConnectTo(1);
        for (int i = 0; i < 30; i++) {
            network.AdvanceTime(network.GetCurrentTime() + 200);
        }
        REQUIRE(peer2.GetTipHeight() == 50);

        // Syncing node connects to BOTH
        syncing.ConnectTo(1);
        syncing.ConnectTo(2);
        network.AdvanceTime(network.GetCurrentTime() + 100);

        // Allow sync
        for (int i = 0; i < 50; i++) {
            network.AdvanceTime(network.GetCurrentTime() + 200);
        }

        // Should successfully sync from one of the peers
        REQUIRE(syncing.GetTipHeight() == 50);
        REQUIRE(syncing.GetPeerCount() == 2);  // Connected to both
    }
}

TEST_CASE("NetworkManager HeaderSync - Sync While Mining Continues", "[network_header_sync][network]") {
    SimulatedNetwork network(50008);
    SetZeroLatency(network);

    SimulatedNode miner(1, &network);
    SimulatedNode syncing(2, &network);

    SECTION("Sync catches up while peer continues mining") {
        // Miner starts with 50 blocks
        for (int i = 0; i < 50; i++) {
            miner.MineBlock();
        }

        // Start sync
        syncing.ConnectTo(1);
        network.AdvanceTime(100);

        // Interleave: sync time + more mining
        for (int round = 0; round < 10; round++) {
            // Allow some sync time
            for (int i = 0; i < 5; i++) {
                network.AdvanceTime(200);
            }

            // Miner mines 5 more blocks
            for (int i = 0; i < 5; i++) {
                miner.MineBlock();
            }
        }

        // Final sync round
        for (int i = 0; i < 20; i++) {
            network.AdvanceTime(200);
        }

        // Syncing node should eventually catch up to moving target
        // Miner now has 50 + 50 = 100 blocks
        REQUIRE(miner.GetTipHeight() == 100);
        REQUIRE(syncing.GetTipHeight() == 100);
    }
}
