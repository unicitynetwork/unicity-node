#include "catch_amalgamated.hpp"
#include "infra/simulated_network.hpp"
#include "infra/simulated_node.hpp"
#include "network/protocol.hpp"
#include "network/message.hpp"
#include "util/hash.hpp"

using namespace unicity;
using namespace unicity::test;
using namespace unicity::protocol;

static void ZeroLatency(SimulatedNetwork& net){
    SimulatedNetwork::NetworkConditions c; c.latency_min=c.latency_max=std::chrono::milliseconds(0); c.jitter_max=std::chrono::milliseconds(0); net.SetNetworkConditions(c);
}

TEST_CASE("DoS: Ping flood elicits PONG without disconnect", "[dos][ping]") {
    SimulatedNetwork net(58001);
    ZeroLatency(net);
    net.EnableCommandTracking(true);

    SimulatedNode victim(1, &net);
    SimulatedNode attacker(2, &net);

    REQUIRE(attacker.ConnectTo(victim.GetId()));
    uint64_t t=100; net.AdvanceTime(t);

    // Craft a PING payload
    auto make_ping = [](uint64_t nonce){
        message::PingMessage ping(nonce);
        auto payload = ping.serialize();
        protocol::MessageHeader hdr(magic::REGTEST, commands::PING, static_cast<uint32_t>(payload.size()));
        uint256 hash = Hash(payload);
        std::memcpy(hdr.checksum.data(), hash.begin(), 4);
        auto hdr_bytes = message::serialize_header(hdr);
        std::vector<uint8_t> full; full.reserve(hdr_bytes.size()+payload.size());
        full.insert(full.end(), hdr_bytes.begin(), hdr_bytes.end());
        full.insert(full.end(), payload.begin(), payload.end());
        return full;
    };

    // Flood PINGs
    const int N = 50;
    for (int i=0;i<N;i++) {
        net.SendMessage(attacker.GetId(), victim.GetId(), make_ping(0xABC00000ULL + i));
        t+=5; net.AdvanceTime(t);
    }

    // Victim should still be connected and must have replied with PONGs
    REQUIRE(victim.GetPeerCount() == 1);
    int pongs = net.CountCommandSent(victim.GetId(), attacker.GetId(), commands::PONG);
    REQUIRE(pongs >= N);
}
