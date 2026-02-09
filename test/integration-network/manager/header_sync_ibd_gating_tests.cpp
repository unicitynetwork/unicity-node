#include "catch_amalgamated.hpp"
#include "infra/simulated_network.hpp"
#include "infra/simulated_node.hpp"
#include "infra/node_simulator.hpp"
#include "network/protocol.hpp"
#include "network/message.hpp"
#include "util/hash.hpp"

using namespace unicity;
using namespace unicity::test;
using namespace unicity::protocol;

static void ZeroLatency(SimulatedNetwork& net){
    SimulatedNetwork::NetworkConditions c; c.latency_min=c.latency_max=std::chrono::milliseconds(0); c.jitter_max=std::chrono::milliseconds(0); net.SetNetworkConditions(c);
}

TEST_CASE("IBD gating: don't request more headers from non-sync peer", "[network][ibd][gating]") {
    // Test that during IBD, receiving unsolicited HEADERS from non-sync peers does NOT
    // trigger follow-up GETHEADERS requests. This matches Bitcoin Core behavior.
    //
    // Bitcoin Core behavior (net_processing.cpp:5549-5551):
    // - During IBD: Only actively REQUEST headers from a single designated sync peer
    // - Headers from other peers ARE processed if valid, but no follow-up requests sent
    // - Post-IBD ("close to today" = within 24h): Request headers from all peers
    //
    // This prevents resource waste by not chasing headers from multiple peers during IBD.

    SimulatedNetwork net(56001);
    ZeroLatency(net);
    net.EnableCommandTracking(true);

    // Create honest peer that N will sync from
    SimulatedNode honest(10, &net);

    // Create a node that will be in IBD
    SimulatedNode N(1, &net);
    REQUIRE(N.GetTipHeight() == 0);  // At genesis, in IBD

    // N connects to honest peer (outbound - will be selected as sync peer)
    N.ConnectTo(honest.GetId());
    uint64_t t = 100;
    net.AdvanceTime(t);

    // Trigger sync peer selection - honest peer should be selected
    N.CheckInitialSync();
    t += 100;
    net.AdvanceTime(t);

    // Create an attacker that will try to send unsolicited headers
    NodeSimulator attacker(12, &net);

    // Attacker connects to N (inbound from N's perspective)
    attacker.ConnectTo(N.GetId());
    t += 100;
    net.AdvanceTime(t);

    // Verify N is still in IBD (honest peer has no blocks to share)
    REQUIRE(N.GetTipHeight() == 0);

    int pre_peer_count = N.GetPeerCount();
    REQUIRE(pre_peer_count >= 2);  // honest + attacker

    // Record GETHEADERS count before attack
    int gh_before = net.CountCommandSent(N.GetId(), attacker.GetId(), commands::GETHEADERS);

    // Build 10 headers connecting to N's genesis
    std::vector<CBlockHeader> hdrs;
    uint256 prev = N.GetTipHash();
    for (int i = 0; i < 10; i++) {
        CBlockHeader h;
        h.nVersion = 1;
        h.hashPrevBlock = prev;
        h.nTime = static_cast<uint32_t>(net.GetCurrentTime() / 1000);
        h.nBits = chain::GlobalChainParams::Get().GenesisBlock().nBits;
        h.nNonce = i + 1;
        h.hashRandomX.SetNull();
        hdrs.push_back(h);
        prev = h.GetHash();
    }

    // Serialize and send HEADERS message
    message::HeadersMessage msg;
    msg.headers = hdrs;
    auto payload = msg.serialize();
    protocol::MessageHeader hdr(magic::REGTEST, commands::HEADERS, static_cast<uint32_t>(payload.size()));
    uint256 hash = Hash(payload);
    std::memcpy(hdr.checksum.data(), hash.begin(), 4);
    auto hdr_bytes = message::serialize_header(hdr);
    std::vector<uint8_t> full;
    full.reserve(hdr_bytes.size() + payload.size());
    full.insert(full.end(), hdr_bytes.begin(), hdr_bytes.end());
    full.insert(full.end(), payload.begin(), payload.end());

    // Attacker sends unsolicited HEADERS to N during IBD
    net.SendMessage(attacker.GetId(), N.GetId(), full);

    for (int i = 0; i < 10; i++) {
        t += 50;
        net.AdvanceTime(t);
    }

    // N should still be connected to attacker (no disconnect for unsolicited headers)
    REQUIRE(N.GetPeerCount() == pre_peer_count);

    // N should NOT have responded with GETHEADERS to non-sync peer during IBD
    // Core behavior: only actively request headers from designated sync peer during IBD
    int gh_after = net.CountCommandSent(N.GetId(), attacker.GetId(), commands::GETHEADERS);
    REQUIRE(gh_after == gh_before);

    // N should still be at genesis (headers have invalid PoW so weren't accepted)
    // Note: The IBD gating prevents GETHEADERS response, not header processing itself
    REQUIRE(N.GetTipHeight() == 0);
}
