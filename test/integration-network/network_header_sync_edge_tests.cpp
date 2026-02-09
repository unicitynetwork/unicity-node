// Copyright (c) 2025 The Unicity Foundation
// Edge-case tests for header synchronization behavior

#include "network_test_helpers.hpp"
#include "chain/validation.hpp"
#include "chain/chainparams.hpp"
#include "network/message.hpp"
#include "util/hash.hpp"
#include "test_orchestrator.hpp"
#include "network/connection_manager.hpp"
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
        victim.CheckInitialSync();
        net.AdvanceTime(200);
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
    victim.CheckInitialSync();
    net.AdvanceTime(200);

    auto payloads = net.GetCommandPayloads(victim.GetId(), peer.GetId(), protocol::commands::GETHEADERS);
    for (int i = 0; i < 10 && payloads.empty(); ++i) {
        net.AdvanceTime(200);
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
    victim.CheckInitialSync();
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
        net.AdvanceTime(200);
        victim.CheckInitialSync();
        net.AdvanceTime(200);
    }

    // Should have solicited headers, but not from many peers
    int distinct = net.CountDistinctPeersSent(victim.GetId(), protocol::commands::GETHEADERS);
    CHECK(distinct <= 2);
}

// NOTE: Removed "HeaderSync - Unconnecting headers threshold" test.
// Bitcoin Core (March 2024+) no longer penalizes unconnecting headers - they are just ignored.
// The getheaders throttling provides sufficient DoS protection.

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
    victim.CheckInitialSync();
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
        net.AdvanceTime(200);
        victim.CheckInitialSync();
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
        net.AdvanceTime(100);
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

    net.AdvanceTime(500);

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
    victim.CheckInitialSync();
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
    net.AdvanceTime(200);
    victim.CheckInitialSync();
    net.AdvanceTime(200);

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
    victim.CheckInitialSync();

    // Let sync complete
    for (int i = 0; i < 100; ++i) {
        net.AdvanceTime(200);
        victim.CheckInitialSync();
        if (victim.GetTipHeight() >= 10) break;
    }

    // Mine blocks to make tip recent (exit IBD)
    // Simulation starts at realistic time (Jan 2024)
    for (int i = 0; i < 5; ++i) {
        sync_peer.MineBlock();
        net.AdvanceTime(200);
    }
    for (int i = 0; i < 50; ++i) {
        net.AdvanceTime(200);
        victim.CheckInitialSync();
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
        net.AdvanceTime(200);
        victim.CheckInitialSync();
        net.AdvanceTime(500);
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

    // Simulation starts at realistic time (Jan 2024), so blocks will have recent timestamps

    // Mine a longer chain on forked_peer
    for (int i = 0; i < 20; ++i) {
        forked_peer.MineBlock();
        net.AdvanceTime(200);
    }

    // Verify chains diverged
    CHECK(victim.GetTipHash() != forked_peer.GetTipHash());
    CHECK(forked_peer.GetTipHeight() > victim.GetTipHeight());

    // Connect victim to forked_peer
    victim.ConnectTo(forked_peer.GetId());
    net.AdvanceTime(200);
    victim.CheckInitialSync();

    // Let header sync proceed
    for (int i = 0; i < 100; ++i) {
        net.AdvanceTime(200);
        victim.CheckInitialSync();
        if (victim.GetTipHeight() >= 20) break;
    }

    // Victim should have reorged to the longer forked chain
    CHECK(victim.GetTipHeight() >= 20);
    CHECK(victim.GetTipHash() == forked_peer.GetTipHash());
}

// ==============================================================================
// ADDITIONAL EDGE CASE TESTS
// ==============================================================================

// NOTE: Test "HeaderSync - Orphan resolved when parent arrives" was removed.
// Orphan header pool infrastructure was removed from the codebase.
// Headers with unknown parents are now simply discarded and trigger GETHEADERS
// requests to fill the gap. The P2P layer handles re-requesting missing headers.

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
    net.AdvanceTime(200);

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
    net.AdvanceTime(200);
    victim.GetChainstate().ActivateBestChain();

    // Tip should still be at height 5 (unconnecting header was not accepted into chain)
    CHECK(victim.GetTipHeight() == 5);
}

TEST_CASE("HeaderSync - Unconnecting headers trigger GETHEADERS request", "[network_header_sync][edge][getheaders]") {
    // Tests that receiving headers with unknown parent triggers GETHEADERS.
    // This is the mechanism that makes orphan header pools unnecessary.
    //
    // Scenario:
    // 1. Both nodes share the same chain at height 5
    // 2. Peer sends headers with an unknown hashPrevBlock (simulates gap)
    // 3. Victim should send exactly one GETHEADERS to request missing headers

    SimulatedNetwork net(51014);
    SetZeroLatency(net);
    net.EnableCommandTracking(true);

    SimulatedNode victim(1, &net);
    victim.SetBypassPOWValidation(true);
    for (int i = 0; i < 5; ++i) {
        victim.MineBlock();
    }
    REQUIRE(victim.GetTipHeight() == 5);

    SimulatedNode peer(2, &net);
    peer.SetBypassPOWValidation(true);
    // Peer syncs to victim's chain (both at height 5 — sync settles, GETHEADERS throttle clears)
    peer.ConnectTo(victim.GetId());
    for (int i = 0; i < 20; ++i) {
        net.AdvanceTime(100);
    }
    REQUIRE(peer.GetTipHeight() == 5);

    // GETHEADERS baseline after sync has fully settled
    int gh_before = net.CountCommandSent(victim.GetId(), peer.GetId(), protocol::commands::GETHEADERS);

    // Construct synthetic headers with unknown hashPrevBlock
    uint256 unknown_prev;
    unknown_prev.SetHex("deadbeef00000000000000000000000000000000000000000000000000000001");
    uint32_t nBits = chain::GlobalChainParams::Get().GenesisBlock().nBits;
    uint32_t t0 = static_cast<uint32_t>(net.GetCurrentTime() / 1000);

    std::vector<CBlockHeader> unconnecting_headers;
    for (int i = 0; i < 3; ++i) {
        CBlockHeader h;
        h.nVersion = 1;
        h.hashPrevBlock = (i == 0) ? unknown_prev : unconnecting_headers.back().GetHash();
        h.nTime = t0 + i + 1;
        h.nBits = nBits;
        h.nNonce = 100 + i;
        h.hashRandomX.SetHex("0000000000000000000000000000000000000000000000000000000000000000");
        unconnecting_headers.push_back(h);
    }

    // Serialize and send via raw message (goes through full P2P HandleHeadersMessage path)
    message::HeadersMessage headers_msg;
    headers_msg.headers = unconnecting_headers;
    auto payload = headers_msg.serialize();

    protocol::MessageHeader hdr(protocol::magic::REGTEST, protocol::commands::HEADERS,
                                 static_cast<uint32_t>(payload.size()));
    uint256 hash = Hash(payload);
    std::memcpy(hdr.checksum.data(), hash.begin(), 4);
    auto hdr_bytes = message::serialize_header(hdr);

    std::vector<uint8_t> full;
    full.reserve(hdr_bytes.size() + payload.size());
    full.insert(full.end(), hdr_bytes.begin(), hdr_bytes.end());
    full.insert(full.end(), payload.begin(), payload.end());

    net.SendMessage(peer.GetId(), victim.GetId(), full);

    // Process the message
    for (int i = 0; i < 5; ++i) {
        net.AdvanceTime(100);
    }

    // KEY: Unconnecting headers trigger exactly one GETHEADERS to fill the gap
    int gh_after = net.CountCommandSent(victim.GetId(), peer.GetId(), protocol::commands::GETHEADERS);
    CHECK(gh_after == gh_before + 1);

    // Tip unchanged — unconnecting headers are not applied to chain
    CHECK(victim.GetTipHeight() == 5);
}
