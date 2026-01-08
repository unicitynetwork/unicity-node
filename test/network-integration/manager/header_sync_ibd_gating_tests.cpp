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

TEST_CASE("IBD gating: ignore large HEADERS from non-sync peer", "[network][ibd][gating]") {
    SimulatedNetwork net(56001);
    ZeroLatency(net);
    net.EnableCommandTracking(true);

    // Miner with chain
    SimulatedNode miner(100, &net);
    for (int i=0;i<40;i++) (void)miner.MineBlock();

    // Serving peers (P1, P2)
    SimulatedNode P1(11, &net);
    NodeSimulator P2(12, &net); // attacker to inject large HEADERS
    REQUIRE(P1.ConnectTo(miner.GetId()));
    REQUIRE(P2.ConnectTo(miner.GetId()));

    uint64_t t=100; net.AdvanceTime(t);
    REQUIRE(P1.GetTipHeight()==40);
    REQUIRE(P2.GetTipHeight()==40);

    // New node N in IBD
    SimulatedNode N(1, &net);
    REQUIRE(N.ConnectTo(P1.GetId()));
    REQUIRE(N.ConnectTo(P2.GetId()));
    t+=200; net.AdvanceTime(t);

    // Begin initial sync (single sync peer adoption)
    N.GetNetworkManager().test_hook_check_initial_sync();
    t+=200; net.AdvanceTime(t);

    // Identify sync peer by checking who received GETHEADERS from N
    int gh_to_p1 = net.CountCommandSent(N.GetId(), P1.GetId(), commands::GETHEADERS);
    int gh_to_p2 = net.CountCommandSent(N.GetId(), P2.GetId(), commands::GETHEADERS);
    REQUIRE( (gh_to_p1>0) ^ (gh_to_p2>0) ); // exactly one sync peer

    // Non-sync peer sends >2 HEADERS; must be ignored (no disconnect, no GETHEADERS back)
    int pre_peer_count = N.GetPeerCount();

    // Build 10 connecting headers off N's current tip (likely genesis)
    std::vector<CBlockHeader> hdrs;
    uint256 prev = N.GetTipHash();
    for (int i=0;i<10;i++){
        CBlockHeader h; h.nVersion=1; h.hashPrevBlock=prev; h.nTime=(uint32_t)(net.GetCurrentTime()/1000);
        h.nBits = chain::GlobalChainParams::Get().GenesisBlock().nBits; h.nNonce=i+1; h.hashRandomX.SetNull(); hdrs.push_back(h); prev=h.GetHash();
    }
    message::HeadersMessage msg; msg.headers=hdrs; auto payload=msg.serialize();
    protocol::MessageHeader hdr(magic::REGTEST, commands::HEADERS, static_cast<uint32_t>(payload.size()));
    uint256 hash = Hash(payload);
    std::memcpy(hdr.checksum.data(), hash.begin(), 4);
    auto hdr_bytes=message::serialize_header(hdr);
    std::vector<uint8_t> full; full.reserve(hdr_bytes.size()+payload.size()); full.insert(full.end(), hdr_bytes.begin(), hdr_bytes.end()); full.insert(full.end(), payload.begin(), payload.end());

    // Send from P2 (treat as non-sync peer)
    net.SendMessage(P2.GetId(), N.GetId(), full);

    for (int i=0;i<10;i++){ t+=50; net.AdvanceTime(t);} // process

    // Still connected to both peers
    REQUIRE(N.GetPeerCount()==pre_peer_count);

    // Ensure we did not respond to P2 with GETHEADERS due to gating
    int gh_to_p2_after = net.CountCommandSent(N.GetId(), P2.GetId(), commands::GETHEADERS);
    REQUIRE(gh_to_p2_after == gh_to_p2);
}
