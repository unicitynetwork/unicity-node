// BlockRelay comprehensive tests: dedup, chunking, READY gating

#include "catch_amalgamated.hpp"
#include "infra/simulated_network.hpp"
#include "infra/simulated_node.hpp"
#include "network/protocol.hpp"
#include "network/message.hpp"
#include "network/peer_lifecycle_manager.hpp"
#include "network/peer.hpp"
#include <random>
#include <unordered_set>
#include <cstring>

using namespace unicity;
using namespace unicity::test;

static void SetZeroLatency(SimulatedNetwork& network) {
    SimulatedNetwork::NetworkConditions cond{};
    cond.latency_min = std::chrono::milliseconds(0);
    cond.latency_max = std::chrono::milliseconds(0);
    cond.jitter_max = std::chrono::milliseconds(0);
    network.SetNetworkConditions(cond);
}

static void AdvanceSeconds(SimulatedNetwork& net, int seconds) {
    for (int i = 0; i < seconds * 5; ++i) {
        net.AdvanceTime(net.GetCurrentTime() + 200);
    }
}

static std::array<uint8_t,32> ToArr(const uint256& h) {
    std::array<uint8_t,32> a{};
    std::memcpy(a.data(), h.data(), 32);
    return a;
}

static int CountHashInInvPayloads(const std::vector<std::vector<uint8_t>>& payloads,
                                  const uint256& needle) {
    int count = 0;
    for (const auto& p : payloads) {
        message::InvMessage inv;
        if (!inv.deserialize(p.data(), p.size())) continue;
        for (const auto& iv : inv.inventory) {
            if (iv.type == protocol::InventoryType::MSG_BLOCK && iv.hash == needle) {
                count++;
            }
        }
    }
    return count;
}

static std::vector<message::InvMessage> ParseInvs(const std::vector<std::vector<uint8_t>>& payloads) {
    std::vector<message::InvMessage> out;
    out.reserve(payloads.size());
    for (const auto& p : payloads) {
        message::InvMessage inv;
        if (inv.deserialize(p.data(), p.size())) out.push_back(inv);
    }
    return out;
}

TEST_CASE("BlockRelay: immediate relay prunes queued duplicate", "[block_relay][dedup]") {
    SimulatedNetwork net(50001);
    SetZeroLatency(net);
    net.EnableCommandTracking(true);

    SimulatedNode a(1, &net);
    SimulatedNode b(2, &net);

    // Connect b -> a and complete handshake
    b.ConnectTo(1);
    AdvanceSeconds(net, 2);

    // Get A's single peer (b as inbound on A's side)
    auto& pm = a.GetNetworkManager().peer_manager();
    auto peers = pm.get_all_peers();
    REQUIRE(peers.size() == 1);
    auto peer = peers.front();

    // Create a random test hash distinct from tip
    std::mt19937_64 rng(42);
    uint256 h;
    for (size_t i = 0; i < 4; ++i) {
        uint64_t w = rng();
        std::memcpy(h.data() + i*8, &w, 8);
    }
    // Pre-queue the hash into A's per-peer INV queue to simulate duplicate pending
    pm.AddBlockForInvRelay(peer->id(), h);

    // Relay immediately: should send once and prune queued duplicate
    a.GetNetworkManager().relay_block(h);
    AdvanceSeconds(net, 1);

    // Flush announcements: should NOT send the same hash again
    a.GetNetworkManager().flush_block_announcements();
    AdvanceSeconds(net, 1);

    auto payloads = net.GetCommandPayloads(a.GetId(), b.GetId(), protocol::commands::INV);
    int occurrences = CountHashInInvPayloads(payloads, h);
    CHECK(occurrences == 1);

    // Verify queue is empty
    auto queue = pm.GetBlocksForInvRelay(peer->id());
    CHECK(queue.empty());
}

TEST_CASE("BlockRelay: flush chunking respects MAX_INV_SIZE and completeness", "[block_relay][chunking][slow]") {
    SimulatedNetwork net(50002);
    SetZeroLatency(net);
    net.EnableCommandTracking(true);

    SimulatedNode a(1, &net);
    SimulatedNode b(2, &net);

    b.ConnectTo(1);
    AdvanceSeconds(net, 2);

    auto& pm = a.GetNetworkManager().peer_manager();
    auto peers = pm.get_all_peers();
    REQUIRE(peers.size() == 1);
    auto peer = peers.front();

    // Create N = MAX_INV_SIZE + 37 unique hashes and queue them
    const size_t N = static_cast<size_t>(protocol::MAX_INV_SIZE) + 37;
    std::vector<uint256> hashes;
    hashes.reserve(N);
    std::unordered_set<std::string> expected;
    std::mt19937_64 rng(1337);
    for (size_t i = 0; i < N; ++i) {
        uint256 h{};
        for (size_t w = 0; w < 4; ++w) {
            uint64_t x = rng();
            std::memcpy(h.data() + w*8, &x, 8);
        }
        hashes.push_back(h);
        expected.insert(h.GetHex());
    }

    for (const auto& h : hashes) {
        pm.AddBlockForInvRelay(peer->id(), h);
    }

    // Flush and process
    a.GetNetworkManager().flush_block_announcements();
    AdvanceSeconds(net, 1);

    // Gather INV payloads A->B and filter only those that include one of our hashes
    auto payloads = net.GetCommandPayloads(a.GetId(), b.GetId(), protocol::commands::INV);
    auto invs = ParseInvs(payloads);

    std::unordered_set<std::string> seen;
    size_t chunk_msgs = 0;
    for (const auto& inv : invs) {
        bool has_test_hash = false;
        for (const auto& iv : inv.inventory) {
            if (iv.type != protocol::InventoryType::MSG_BLOCK) continue;
            uint256 tmp; std::memcpy(tmp.data(), iv.hash.data(), 32);
            std::string hx = tmp.GetHex();
            if (expected.count(hx)) { has_test_hash = true; }
        }
        if (!has_test_hash) continue; // ignore other INV (e.g., handshakes)

        // This INV is part of our batch; verify chunk size and record hashes
        chunk_msgs++;
        CHECK(inv.inventory.size() <= protocol::MAX_INV_SIZE);
        for (const auto& iv : inv.inventory) {
            if (iv.type != protocol::InventoryType::MSG_BLOCK) continue;
            uint256 tmp; std::memcpy(tmp.data(), iv.hash.data(), 32);
            std::string hx = tmp.GetHex();
            if (expected.count(hx)) seen.insert(hx);
        }
    }

    CHECK(seen.size() == expected.size());
    size_t expected_chunks = (N + protocol::MAX_INV_SIZE - 1) / protocol::MAX_INV_SIZE;
    CHECK(chunk_msgs == expected_chunks);

    // Verify queue is cleared
    auto queue = pm.GetBlocksForInvRelay(peer->id());
    CHECK(queue.empty());
}

TEST_CASE("BlockRelay: immediate relay only to READY peers", "[block_relay][ready_gating]") {
    SimulatedNetwork net(50003);
    SetZeroLatency(net);
    net.EnableCommandTracking(true);

    SimulatedNode a(1, &net);
    SimulatedNode b(2, &net);
    SimulatedNode c(3, &net);

    // b becomes READY; c connects but remains non-READY (no time advance)
    b.ConnectTo(1);
    AdvanceSeconds(net, 2);
    c.ConnectTo(1);

    // Unique random hash
    std::mt19937_64 rng(7);
    uint256 h{}; for (size_t i=0;i<4;++i){ uint64_t w=rng(); std::memcpy(h.data()+i*8,&w,8);}

    a.GetNetworkManager().relay_block(h);
    AdvanceSeconds(net, 1);

    auto pb = net.GetCommandPayloads(a.GetId(), b.GetId(), protocol::commands::INV);
    auto pc = net.GetCommandPayloads(a.GetId(), c.GetId(), protocol::commands::INV);

    int b_hits = CountHashInInvPayloads(pb, h);
    int c_hits = CountHashInInvPayloads(pc, h);

    CHECK(b_hits == 1);
    CHECK(c_hits == 0);
}
