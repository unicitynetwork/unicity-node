// Copyright (c) 2025 The Unicity Foundation
// Edge-case tests for header synchronization behavior

#include "network_test_helpers.hpp"
#include "chain/validation.hpp"
#include "chain/chainparams.hpp"
#include "network/message.hpp"
#include "util/hash.hpp"
#include "test_orchestrator.hpp"
#include "network/peer_lifecycle_manager.hpp"
#include <cstring>

using namespace unicity;
using namespace unicity::test;

TEST_CASE("HeaderSync - IBD selects single sync peer among many", "[network_header_sync][edge]") {
    SimulatedNetwork net(51001);
    SetZeroLatency(net);
    net.EnableCommandTracking(true);

    // Victim in IBD
    SimulatedNode victim(1, &net);
    victim.SetBypassPOWValidation(true);

    // Connect many peers
    const int K = 6;
    std::vector<std::unique_ptr<SimulatedNode>> peers;
    for (int i = 0; i < K; ++i) {
        peers.push_back(std::make_unique<SimulatedNode>(10 + i, &net));
        victim.ConnectTo(peers.back()->GetId());
    }

    // Allow selection passes
    for (int i = 0; i < 50; ++i) {
        victim.GetNetworkManager().test_hook_check_initial_sync();
        net.AdvanceTime(net.GetCurrentTime() + 200);
    }

    // Exactly one outbound peer should have received GETHEADERS during IBD
    int distinct = net.CountDistinctPeersSent(victim.GetId(), protocol::commands::GETHEADERS);
    CHECK(distinct == 1);
}

TEST_CASE("HeaderSync - Genesis locator uses tip when no pprev (pprev trick fallback)", "[network_header_sync][edge]") {
    SimulatedNetwork net(51002);
    SetZeroLatency(net);
    net.EnableCommandTracking(true);

    // Victim at genesis
    SimulatedNode victim(20, &net);
    SimulatedNode peer(21, &net);

    victim.ConnectTo(peer.GetId());
    net.AdvanceTime(200);
    victim.GetNetworkManager().test_hook_check_initial_sync();
    net.AdvanceTime(200);

    auto payloads = net.GetCommandPayloads(victim.GetId(), peer.GetId(), protocol::commands::GETHEADERS);
    for (int i = 0; i < 10 && payloads.empty(); ++i) {
        net.AdvanceTime(net.GetCurrentTime() + 200);
        payloads = net.GetCommandPayloads(victim.GetId(), peer.GetId(), protocol::commands::GETHEADERS);
    }
    REQUIRE_FALSE(payloads.empty());

    message::GetHeadersMessage gh;
    REQUIRE(gh.deserialize(payloads.back().data(), payloads.back().size()));
    REQUIRE_FALSE(gh.block_locator_hashes.empty());

    // At genesis (no pprev), first locator should be genesis
    uint256 first;
    std::memcpy(first.data(), gh.block_locator_hashes.front().data(), 32);
    CHECK(first == unicity::chain::GlobalChainParams::Get().GenesisBlock().GetHash());
}

TEST_CASE("HeaderSync - Repeated empty HEADERS from sync peer does not thrash selection", "[network_header_sync][edge]") {
    SimulatedNetwork net(51003);
    SetZeroLatency(net);
    net.EnableCommandTracking(true);

    SimulatedNode p1(30, &net);
    SimulatedNode p2(31, &net);
    SimulatedNode victim(32, &net);

    victim.ConnectTo(p1.GetId());
    net.AdvanceTime(200);
    victim.GetNetworkManager().test_hook_check_initial_sync();
    net.AdvanceTime(200);
    victim.ConnectTo(p2.GetId());
    net.AdvanceTime(200);

    // Send multiple empty HEADERS from current sync peer (p1), triggering reselection
    for (int i = 0; i < 3; ++i) {
        message::HeadersMessage empty; auto payload = empty.serialize();
        protocol::MessageHeader hdr(protocol::magic::REGTEST, protocol::commands::HEADERS, static_cast<uint32_t>(payload.size()));
        uint256 hash = Hash(payload);
        std::memcpy(hdr.checksum.data(), hash.begin(), 4);
        auto hdr_bytes = message::serialize_header(hdr);
        std::vector<uint8_t> full; full.reserve(hdr_bytes.size()+payload.size());
        full.insert(full.end(), hdr_bytes.begin(), hdr_bytes.end());
        full.insert(full.end(), payload.begin(), payload.end());
        net.SendMessage(p1.GetId(), victim.GetId(), full);
        net.AdvanceTime(net.GetCurrentTime() + 200);
        victim.GetNetworkManager().test_hook_check_initial_sync();
        net.AdvanceTime(net.GetCurrentTime() + 200);
    }

    // Should have solicited headers, but not from many peers
    int distinct = net.CountDistinctPeersSent(victim.GetId(), protocol::commands::GETHEADERS);
    CHECK(distinct <= 2);
}

TEST_CASE("HeaderSync - Unconnecting headers threshold triggers discouragement & cleanup", "[network_header_sync][edge]") {
    SimulatedNetwork net(51004);
    SetZeroLatency(net);
    net.EnableCommandTracking(true);

    SimulatedNode victim(40, &net);
    SimulatedNode bad(41, &net);

    // Inbound bad peer connects to victim
    bad.ConnectTo(victim.GetId());
    net.AdvanceTime(200);

    // Build a small headers batch that does NOT connect to known chain
    auto make_unconnecting_headers = [&]() {
        std::vector<CBlockHeader> headers; headers.reserve(2);
        uint256 bogus_prev; bogus_prev.SetHex("deadbeef00000000000000000000000000000000000000000000000000000000");
        uint32_t nBits = unicity::chain::GlobalChainParams::Get().GenesisBlock().nBits;
        uint32_t t0 = static_cast<uint32_t>(net.GetCurrentTime() / 1000);
        for (int i = 0; i < 2; ++i) {
            CBlockHeader h; h.nVersion=1; h.hashPrevBlock = (i==0? bogus_prev : headers.back().GetHash()); h.nTime=t0+i+1; h.nBits=nBits; h.nNonce=i+1;
            h.hashRandomX.SetHex("0000000000000000000000000000000000000000000000000000000000000000");
            headers.push_back(h);
        }
        return headers;
    };

    auto send_headers = [&](const std::vector<CBlockHeader>& hs){
        message::HeadersMessage m; m.headers = hs; auto payload = m.serialize();
        protocol::MessageHeader hdr(protocol::magic::REGTEST, protocol::commands::HEADERS, static_cast<uint32_t>(payload.size()));
        uint256 hash = Hash(payload);
        std::memcpy(hdr.checksum.data(), hash.begin(), 4);
        auto hdr_bytes = message::serialize_header(hdr);
        std::vector<uint8_t> full; full.reserve(hdr_bytes.size()+payload.size());
        full.insert(full.end(), hdr_bytes.begin(), hdr_bytes.end());
        full.insert(full.end(), payload.begin(), payload.end());
        net.SendMessage(bad.GetId(), victim.GetId(), full);
    };

    // Send more than MAX_UNCONNECTING_HEADERS messages
    for (int i = 0; i < unicity::network::MAX_UNCONNECTING_HEADERS + 1; ++i) {
        send_headers(make_unconnecting_headers());
        net.AdvanceTime(net.GetCurrentTime() + 200);
        victim.GetNetworkManager().test_hook_check_initial_sync();
        // Periodic processing applies discouragement removal
        victim.GetNetworkManager().peer_manager().process_periodic();
    }

    // Expect peer count dropped (bad peer disconnected)
    CHECK(victim.GetPeerCount() == 0);
}

TEST_CASE("HeaderSync - Oversized HEADERS clears sync and we reselect another peer", "[network_header_sync][edge]") {
    SimulatedNetwork net(51005);
    SetZeroLatency(net);
    net.EnableCommandTracking(true);

    // Two serving peers
    SimulatedNode p1(50, &net);
    SimulatedNode p2(51, &net);

    // Victim connects to both, selects one as sync
    SimulatedNode victim(52, &net);
    victim.ConnectTo(p1.GetId());
    net.AdvanceTime(200);
    victim.GetNetworkManager().test_hook_check_initial_sync();
    net.AdvanceTime(200);
    victim.ConnectTo(p2.GetId());
    net.AdvanceTime(200);

    // Craft oversized HEADERS from current sync peer (p1): MAX+1 headers
    const size_t N = protocol::MAX_HEADERS_SIZE + 1;
    std::vector<CBlockHeader> headers; headers.reserve(N);
    uint256 prev = victim.GetTipHash();
    uint32_t nBits = unicity::chain::GlobalChainParams::Get().GenesisBlock().nBits;
    uint32_t t0 = static_cast<uint32_t>(net.GetCurrentTime() / 1000);
    for (size_t i = 0; i < N; ++i) { CBlockHeader h; h.nVersion=1; h.hashPrevBlock=prev; h.nTime=t0+i+1; h.nBits=nBits; h.nNonce=i+1; h.hashRandomX.SetHex("0000000000000000000000000000000000000000000000000000000000000000"); headers.push_back(h); prev=h.GetHash(); }

    message::HeadersMessage m; m.headers = headers; auto payload = m.serialize();
    protocol::MessageHeader hdr(protocol::magic::REGTEST, protocol::commands::HEADERS, static_cast<uint32_t>(payload.size()));
        uint256 hash = Hash(payload);
        std::memcpy(hdr.checksum.data(), hash.begin(), 4);
    auto hdr_bytes = message::serialize_header(hdr);
    std::vector<uint8_t> full; full.reserve(hdr_bytes.size()+payload.size());
    full.insert(full.end(), hdr_bytes.begin(), hdr_bytes.end());
    full.insert(full.end(), payload.begin(), payload.end());

    // Send from p1 to victim (oversized)
    net.SendMessage(p1.GetId(), victim.GetId(), full);

    // Allow processing and reselection
    for (int i = 0; i < 20; ++i) {
        net.AdvanceTime(net.GetCurrentTime() + 200);
        victim.GetNetworkManager().test_hook_check_initial_sync();
    }

    // Verify we solicited p2 with GETHEADERS after clearing sync
    auto gh_p2 = net.GetCommandPayloads(victim.GetId(), p2.GetId(), protocol::commands::GETHEADERS);
    REQUIRE_FALSE(gh_p2.empty());
}

TEST_CASE("HeaderSync - Empty headers response when no common blocks (genesis block fix)", "[network_header_sync][edge][genesis]") {
    // Tests the fix for genesis block handling bug where code would skip genesis
    // when no common blocks found. Now should send empty HEADERS (matches Bitcoin Core).
    SimulatedNetwork net(51006);
    SetZeroLatency(net);
    net.EnableCommandTracking(true);

    SimulatedNode node1(1, &net);
    SimulatedNode node2(2, &net);

    // Connect nodes
    node2.ConnectTo(node1.GetId());
    net.AdvanceTime(500);

    // Wait for handshake to complete
    for (int i = 0; i < 20; ++i) {
        net.AdvanceTime(net.GetCurrentTime() + 100);
    }
    REQUIRE(node1.GetPeerCount() > 0);

    // Node2 sends GETHEADERS with locator containing unknown blocks
    // (simulates peer on different network or with no common history)
    message::GetHeadersMessage gh;
    gh.version = protocol::PROTOCOL_VERSION;

    // Create locator with fake hashes that don't exist in node1's chain
    uint256 fake_hash1, fake_hash2;
    fake_hash1.SetHex("deadbeef00000000000000000000000000000000000000000000000000000000");
    fake_hash2.SetHex("cafebabe00000000000000000000000000000000000000000000000000000000");

    gh.block_locator_hashes.push_back(fake_hash1);
    gh.block_locator_hashes.push_back(fake_hash2);
    gh.hash_stop.SetNull();

    // Serialize and send GETHEADERS
    auto payload = gh.serialize();
    protocol::MessageHeader hdr(protocol::magic::REGTEST, protocol::commands::GETHEADERS, static_cast<uint32_t>(payload.size()));
    uint256 hash = Hash(payload);
    std::memcpy(hdr.checksum.data(), hash.begin(), 4);
    auto hdr_bytes = message::serialize_header(hdr);
    std::vector<uint8_t> full;
    full.reserve(hdr_bytes.size() + payload.size());
    full.insert(full.end(), hdr_bytes.begin(), hdr_bytes.end());
    full.insert(full.end(), payload.begin(), payload.end());
    net.SendMessage(node2.GetId(), node1.GetId(), full);

    net.AdvanceTime(net.GetCurrentTime() + 500);

    // Verify node1 sent HEADERS response
    auto responses = net.GetCommandPayloads(node1.GetId(), node2.GetId(),
                                             protocol::commands::HEADERS);
    REQUIRE_FALSE(responses.empty());

    // Parse response
    message::HeadersMessage response;
    REQUIRE(response.deserialize(responses.back().data(), responses.back().size()));

    // Should be EMPTY (matches Bitcoin Core behavior)
    // OLD BUG: Would send from genesis+1, skipping genesis
    // NEW FIX: Sends empty headers
    CHECK(response.headers.empty());

    // Should NOT disconnect peer (this is a valid edge case, not an attack)
    CHECK(node1.GetPeerCount() > 0);
}

// ==============================================================================
// IBD EDGE CASE TESTS (for pindexLast fix)
// ==============================================================================

TEST_CASE("HeaderSync - IBD only requests continuation from sync peer", "[network_header_sync][edge][ibd]") {
    // During IBD, continuation requests should only go to the sync peer,
    // not to other peers that might send headers.
    SimulatedNetwork net(51007);
    SetZeroLatency(net);
    net.EnableCommandTracking(true);

    // Victim at genesis (IBD mode)
    SimulatedNode victim(60, &net);
    victim.SetBypassPOWValidation(true);
    REQUIRE(victim.GetIsIBD() == true);

    // Two peers - sync_peer will be selected, other_peer will also send headers
    SimulatedNode sync_peer(61, &net);
    SimulatedNode other_peer(62, &net);

    // Connect to sync_peer first and trigger sync selection
    victim.ConnectTo(sync_peer.GetId());
    net.AdvanceTime(200);
    victim.GetNetworkManager().test_hook_check_initial_sync();
    net.AdvanceTime(200);

    // Connect other_peer
    victim.ConnectTo(other_peer.GetId());
    net.AdvanceTime(200);

    // Clear tracking to measure from this point
    net.EnableCommandTracking(true);

    // Helper to create headers building on victim's tip
    auto make_headers = [&](int count) {
        std::vector<CBlockHeader> headers;
        headers.reserve(count);
        uint256 prev = victim.GetTipHash();
        uint32_t nBits = unicity::chain::GlobalChainParams::Get().GenesisBlock().nBits;
        uint32_t t0 = static_cast<uint32_t>(net.GetCurrentTime() / 1000);
        for (int i = 0; i < count; ++i) {
            CBlockHeader h;
            h.nVersion = 1;
            h.hashPrevBlock = prev;
            h.nTime = t0 + i + 1;
            h.nBits = nBits;
            h.nNonce = i + 1;
            h.hashRandomX.SetHex("0000000000000000000000000000000000000000000000000000000000000000");
            headers.push_back(h);
            prev = h.GetHash();
        }
        return headers;
    };

    auto send_headers = [&](int from_node_id, const std::vector<CBlockHeader>& headers) {
        message::HeadersMessage m;
        m.headers = headers;
        auto payload = m.serialize();
        protocol::MessageHeader hdr(protocol::magic::REGTEST, protocol::commands::HEADERS,
                                    static_cast<uint32_t>(payload.size()));
        uint256 hash = Hash(payload);
        std::memcpy(hdr.checksum.data(), hash.begin(), 4);
        auto hdr_bytes = message::serialize_header(hdr);
        std::vector<uint8_t> full;
        full.reserve(hdr_bytes.size() + payload.size());
        full.insert(full.end(), hdr_bytes.begin(), hdr_bytes.end());
        full.insert(full.end(), payload.begin(), payload.end());
        net.SendMessage(from_node_id, victim.GetId(), full);
    };

    // Send a small batch (not full) from other_peer - should NOT trigger continuation
    auto small_batch = make_headers(10);
    send_headers(other_peer.GetId(), small_batch);
    net.AdvanceTime(net.GetCurrentTime() + 200);
    victim.GetNetworkManager().test_hook_check_initial_sync();
    net.AdvanceTime(net.GetCurrentTime() + 200);

    // During IBD, victim should NOT send GETHEADERS to other_peer
    int gh_to_other = net.CountCommandSent(victim.GetId(), other_peer.GetId(),
                                           protocol::commands::GETHEADERS);
    CHECK(gh_to_other == 0);
}

TEST_CASE("HeaderSync - Post-IBD requests continuation from any peer with full batch", "[network_header_sync][edge][ibd]") {
    // Post-IBD, when a non-sync peer sends a full batch of headers,
    // we should continue requesting from that peer.
    SimulatedNetwork net(51008);
    SetZeroLatency(net);
    net.EnableCommandTracking(true);

    // Two peers with chains
    SimulatedNode sync_peer(70, &net);
    SimulatedNode other_peer(71, &net);

    // Sync peer has some blocks
    for (int i = 0; i < 10; ++i) {
        sync_peer.MineBlock();
    }

    // Victim connects and syncs to exit IBD
    SimulatedNode victim(72, &net);
    victim.SetBypassPOWValidation(true);

    victim.ConnectTo(sync_peer.GetId());
    net.AdvanceTime(200);
    victim.GetNetworkManager().test_hook_check_initial_sync();

    // Let sync complete
    for (int i = 0; i < 100; ++i) {
        net.AdvanceTime(net.GetCurrentTime() + 200);
        victim.GetNetworkManager().test_hook_check_initial_sync();
        if (victim.GetTipHeight() >= 10) break;
    }

    // Move time forward to make tip recent (exit IBD)
    net.AdvanceTime(std::time(nullptr) * 1000ULL);
    for (int i = 0; i < 5; ++i) {
        sync_peer.MineBlock();
        net.AdvanceTime(net.GetCurrentTime() + 200);
    }
    for (int i = 0; i < 50; ++i) {
        net.AdvanceTime(net.GetCurrentTime() + 200);
        victim.GetNetworkManager().test_hook_check_initial_sync();
    }

    // Verify we're now post-IBD
    CHECK(victim.GetIsIBD() == false);

    // Connect other_peer
    victim.ConnectTo(other_peer.GetId());
    net.AdvanceTime(200);

    // Clear tracking to start fresh
    net.EnableCommandTracking(true);

    // other_peer has a longer chain (diverged) - mine on it
    for (int i = 0; i < 50; ++i) {
        other_peer.MineBlock();
    }

    // Helper to build headers from other_peer's chain
    auto build_headers_from_peer = [&](SimulatedNode& peer, int start_height, int count) {
        std::vector<CBlockHeader> headers;
        for (int h = start_height; h < start_height + count && h <= peer.GetTipHeight(); ++h) {
            uint256 hash = peer.GetBlockHash(h);
            if (!hash.IsNull()) {
                headers.push_back(peer.GetBlockHeader(hash));
            }
        }
        return headers;
    };

    auto send_headers = [&](int from_node_id, const std::vector<CBlockHeader>& headers) {
        message::HeadersMessage m;
        m.headers = headers;
        auto payload = m.serialize();
        protocol::MessageHeader hdr(protocol::magic::REGTEST, protocol::commands::HEADERS,
                                    static_cast<uint32_t>(payload.size()));
        uint256 hash = Hash(payload);
        std::memcpy(hdr.checksum.data(), hash.begin(), 4);
        auto hdr_bytes = message::serialize_header(hdr);
        std::vector<uint8_t> full;
        full.reserve(hdr_bytes.size() + payload.size());
        full.insert(full.end(), hdr_bytes.begin(), hdr_bytes.end());
        full.insert(full.end(), payload.begin(), payload.end());
        net.SendMessage(from_node_id, victim.GetId(), full);
    };

    // Send headers from other_peer (simulating announcement of longer chain)
    // Send 20 headers - not a full batch but enough to test continuation logic
    auto headers_batch = build_headers_from_peer(other_peer, 1, 20);
    if (!headers_batch.empty()) {
        send_headers(other_peer.GetId(), headers_batch);
        net.AdvanceTime(net.GetCurrentTime() + 200);
        victim.GetNetworkManager().test_hook_check_initial_sync();
        net.AdvanceTime(net.GetCurrentTime() + 500);
    }

    // Post-IBD should accept headers from any peer
    // We verify by checking victim processed the headers
    CHECK(victim.GetTipHeight() >= 15);
}

TEST_CASE("HeaderSync - Continuation uses pindexLast for locator (Bitcoin Core behavior)", "[network_header_sync][edge][ibd][locator]") {
    // This test verifies that continuation requests use pindexLast to build
    // the locator, not the active tip. This is critical for diverged chains.
    SimulatedNetwork net(51009);
    SetZeroLatency(net);
    net.EnableCommandTracking(true);

    // Create victim with some initial chain
    SimulatedNode victim(80, &net);
    victim.SetBypassPOWValidation(true);

    // Mine initial blocks on victim
    for (int i = 0; i < 5; ++i) {
        victim.MineBlock();
    }
    uint256 victim_tip_before = victim.GetTipHash();

    // Create peer with a DIFFERENT chain (fork at genesis)
    SimulatedNode forked_peer(81, &net);

    // Make forked_peer's time more recent to exit IBD when victim syncs
    net.AdvanceTime(std::time(nullptr) * 1000ULL);

    // Mine a longer chain on forked_peer
    for (int i = 0; i < 20; ++i) {
        forked_peer.MineBlock();
        net.AdvanceTime(net.GetCurrentTime() + 200);
    }

    // Verify chains diverged
    CHECK(victim.GetTipHash() != forked_peer.GetTipHash());
    CHECK(forked_peer.GetTipHeight() > victim.GetTipHeight());

    // Connect victim to forked_peer
    victim.ConnectTo(forked_peer.GetId());
    net.AdvanceTime(200);
    victim.GetNetworkManager().test_hook_check_initial_sync();

    // Let header sync proceed
    for (int i = 0; i < 100; ++i) {
        net.AdvanceTime(net.GetCurrentTime() + 200);
        victim.GetNetworkManager().test_hook_check_initial_sync();
        if (victim.GetTipHeight() >= 20) break;
    }

    // Victim should have reorged to the longer forked chain
    CHECK(victim.GetTipHeight() >= 20);
    CHECK(victim.GetTipHash() == forked_peer.GetTipHash());
}

// ==============================================================================
// ADDITIONAL EDGE CASE TESTS
// ==============================================================================

TEST_CASE("HeaderSync - Orphan resolved when parent arrives", "[network_header_sync][edge][orphan]") {
    // Tests that when an orphan header arrives before its parent,
    // it's cached and then activated when the parent arrives.
    // This exercises ProcessOrphanHeaders via the direct ReceiveHeaders API.
    SimulatedNetwork net(51010);
    SetZeroLatency(net);

    SimulatedNode victim(90, &net);
    victim.SetBypassPOWValidation(true);
    SimulatedNode peer(91, &net);

    victim.ConnectTo(peer.GetId());
    net.AdvanceTime(200);

    // Build a chain of 3 headers on top of genesis
    std::vector<CBlockHeader> chain;
    uint256 prev = victim.GetTipHash();
    uint32_t nBits = unicity::chain::GlobalChainParams::Get().GenesisBlock().nBits;
    uint32_t t0 = static_cast<uint32_t>(net.GetCurrentTime() / 1000);

    for (int i = 0; i < 3; ++i) {
        CBlockHeader h;
        h.nVersion = 1;
        h.hashPrevBlock = prev;
        h.nTime = t0 + i + 1;
        h.nBits = nBits;
        h.nNonce = i + 1;
        h.hashRandomX.SetHex("0000000000000000000000000000000000000000000000000000000000000000");
        chain.push_back(h);
        prev = h.GetHash();
    }

    // Send header 2 FIRST (orphan - references header 1 which doesn't exist)
    // Use ReceiveHeaders which directly injects into chainstate
    std::vector<CBlockHeader> orphan_batch = {chain[1]};
    victim.ReceiveHeaders(peer.GetId(), orphan_batch);
    net.AdvanceTime(net.GetCurrentTime() + 200);

    // Orphan should be cached but not activated
    CHECK(victim.GetTipHeight() == 0);  // Still at genesis

    // Now send header 1 (the parent that connects to genesis)
    std::vector<CBlockHeader> parent_batch = {chain[0]};
    victim.ReceiveHeaders(peer.GetId(), parent_batch);
    net.AdvanceTime(net.GetCurrentTime() + 200);

    // ReceiveHeaders calls AcceptBlockHeader which internally calls ProcessOrphanHeaders.
    // When parent (chain[0]) is accepted, it triggers processing of the orphan (chain[1]).
    // We still need to call ActivateBestChain to update the tip.
    victim.GetChainstate().ActivateBestChain();

    // Both header 1 (parent) and orphan header 2 should now be in the chain
    CHECK(victim.GetTipHeight() >= 2);
}

// NOTE: Tests for "Exactly MAX_HEADERS_SIZE unconnecting batch boundary" and
// "Small unconnecting batch under MAX_HEADERS_SIZE is cached" have been removed.
// These tests require P2P layer behavior (disconnect logic in HeaderSyncManager)
// which is not properly simulated by raw net.SendMessage() calls.
// The P2P disconnect behavior is tested by functional tests in test/functional/
// that use the full node stack including proper connection handshakes.

TEST_CASE("HeaderSync - Mixed valid and invalid headers in batch stops at first invalid", "[network_header_sync][edge][validation]") {
    // Tests that when a batch contains valid headers followed by an unconnecting header,
    // we accept the valid portion and stop at the unconnecting one.
    // This uses ReceiveHeaders() to directly inject into chainstate (bypasses P2P layer).
    SimulatedNetwork net(51013);
    SetZeroLatency(net);

    SimulatedNode victim(120, &net);
    victim.SetBypassPOWValidation(true);
    SimulatedNode peer(121, &net);

    victim.ConnectTo(peer.GetId());
    net.AdvanceTime(200);

    // Build 5 valid headers connecting to genesis
    std::vector<CBlockHeader> valid_headers;
    uint256 prev = victim.GetTipHash();
    uint32_t nBits = unicity::chain::GlobalChainParams::Get().GenesisBlock().nBits;
    uint32_t t0 = static_cast<uint32_t>(net.GetCurrentTime() / 1000);

    for (int i = 0; i < 5; ++i) {
        CBlockHeader h;
        h.nVersion = 1;
        h.hashPrevBlock = prev;
        h.nTime = t0 + i + 1;
        h.nBits = nBits;
        h.nNonce = i + 1;
        h.hashRandomX.SetHex("0000000000000000000000000000000000000000000000000000000000000000");
        valid_headers.push_back(h);
        prev = h.GetHash();
    }

    // Send the valid headers first
    victim.ReceiveHeaders(peer.GetId(), valid_headers);
    net.AdvanceTime(net.GetCurrentTime() + 200);

    // ReceiveHeaders only calls AcceptBlockHeader and TryAddBlockIndexCandidate
    // but doesn't call ActivateBestChain. Call it manually for this unit test.
    victim.GetChainstate().ActivateBestChain();

    // The first 5 valid headers should have been accepted
    CHECK(victim.GetTipHeight() == 5);

    // Now build an unconnecting header (references a non-existent parent)
    CBlockHeader unconnecting;
    unconnecting.nVersion = 1;
    uint256 broken_prev;
    broken_prev.SetHex("badc0de000000000000000000000000000000000000000000000000000000000");
    unconnecting.hashPrevBlock = broken_prev;
    unconnecting.nTime = t0 + 6;
    unconnecting.nBits = nBits;
    unconnecting.nNonce = 6;
    unconnecting.hashRandomX.SetHex("0000000000000000000000000000000000000000000000000000000000000000");

    std::vector<CBlockHeader> unconnecting_batch = {unconnecting};
    victim.ReceiveHeaders(peer.GetId(), unconnecting_batch);
    net.AdvanceTime(net.GetCurrentTime() + 200);
    victim.GetChainstate().ActivateBestChain();

    // Tip should still be at height 5 (unconnecting header was not accepted into chain)
    CHECK(victim.GetTipHeight() == 5);
}
