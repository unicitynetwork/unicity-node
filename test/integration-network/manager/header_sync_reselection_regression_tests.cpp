// Header sync reselection regression tests

#include "catch_amalgamated.hpp"
#include "infra/simulated_network.hpp"
#include "infra/simulated_node.hpp"
#include "network/protocol.hpp"
#include "network/message.hpp"
#include "util/hash.hpp"

using namespace unicity;
using namespace unicity::test;
using namespace unicity::protocol;

static void SetZeroLatency(SimulatedNetwork& net) {
    SimulatedNetwork::NetworkConditions c; c.latency_min=c.latency_max=std::chrono::milliseconds(0); c.jitter_max=std::chrono::milliseconds(0); net.SetNetworkConditions(c);
}

TEST_CASE("HeaderSync - Reselection after stall and empty HEADERS can reuse peer", "[network_header_sync][regression]") {
    SimulatedNetwork net(52001);
    // DON'T use zero latency - we need time to install stall before HEADERS arrive
    net.EnableCommandTracking(true);

    // Miner builds a short chain
    SimulatedNode miner(10, &net);
    for (int i = 0; i < 30; ++i) (void)miner.MineBlock();

    // Two serving peers that sync to miner
    SimulatedNode p1(11, &net);
    SimulatedNode p2(12, &net);
    p1.ConnectTo(miner.GetId());
    p2.ConnectTo(miner.GetId());
    net.AdvanceTime(1000);
    for (int i = 0; i < 20 && p1.GetTipHeight() < 30; ++i) { net.AdvanceTime(200); p1.CheckInitialSync(); }
    for (int i = 0; i < 20 && p2.GetTipHeight() < 30; ++i) { net.AdvanceTime(200); p2.CheckInitialSync(); }
    REQUIRE(p1.GetTipHeight() == 30);
    REQUIRE(p2.GetTipHeight() == 30);

    // Victim connects to both
    SimulatedNode victim(13, &net);
    // Connect victim to p1 first to force initial sync selection to p1
    victim.ConnectTo(p1.GetId());
    net.AdvanceTime(200);

    // NOW connect to p2 (will be available for reselection)
    victim.ConnectTo(p2.GetId());
    net.AdvanceTime(200);

    int sync_peer_id = p1.GetId();
    int other_peer_id = p2.GetId();

    // Round 1: Install stall BEFORE triggering sync to prevent victim from syncing and exiting IBD
    {
        // Install stall BEFORE sync starts to ensure victim stays in IBD
        SimulatedNetwork::NetworkConditions drop; drop.packet_loss_rate = 1.0; // stall: drop messages to victim
        net.SetLinkConditions(sync_peer_id, victim.GetId(), drop);

        // Trigger initial sync selection to p1 (now stalled)
        victim.CheckInitialSync();
        net.AdvanceTime(100);

        // Verify GETHEADERS went to p1 at least once
        int gh_p1_initial = net.CountCommandSent(victim.GetId(), p1.GetId(), commands::GETHEADERS);
        REQUIRE(gh_p1_initial >= 1);

        // Record baseline GETHEADERS to other peer
        int gh_other_baseline = net.CountCommandSent(victim.GetId(), other_peer_id, commands::GETHEADERS);

        // Advance beyond stall timeout (5 min) and process timers
        for (int i = 0; i < 6; ++i) {
            net.AdvanceTime(60 * 1000);
            victim.ProcessHeaderSyncTimers();
        }

        // Trigger re-selection after stall and poll for GETHEADERS to other peer
        bool switched = false;
        for (int i = 0; i < 20; ++i) {
            net.AdvanceTime(200);
            victim.CheckInitialSync();
            int gh_now = net.CountCommandSent(victim.GetId(), other_peer_id, commands::GETHEADERS);
            if (gh_now > gh_other_baseline) { switched = true; break; }
        }
        CHECK(switched);

        // Switch roles: track the new sync peer
        sync_peer_id = other_peer_id;
        other_peer_id = (sync_peer_id == p1.GetId()) ? p2.GetId() : p1.GetId();
    }

    // Round 2: From current sync peer, send empty HEADERS.
    // Bitcoin Core behavior: empty HEADERS does NOT trigger reselection.
    // The sync peer should remain the same (Core's fSyncStarted persists).
    {
        // Baseline counts on both peers
        int gh_p1_base = net.CountCommandSent(victim.GetId(), p1.GetId(), commands::GETHEADERS);
        int gh_p2_base = net.CountCommandSent(victim.GetId(), p2.GetId(), commands::GETHEADERS);

        // Build empty HEADERS message
        message::HeadersMessage empty;
        auto payload = empty.serialize();
        protocol::MessageHeader hdr(protocol::magic::REGTEST, commands::HEADERS, static_cast<uint32_t>(payload.size()));
        uint256 hash = Hash(payload);
        std::memcpy(hdr.checksum.data(), hash.begin(), 4);
        auto hdr_bytes = message::serialize_header(hdr);
        std::vector<uint8_t> full; full.reserve(hdr_bytes.size()+payload.size());
        full.insert(full.end(), hdr_bytes.begin(), hdr_bytes.end());
        full.insert(full.end(), payload.begin(), payload.end());

        // Inject empty HEADERS from current sync peer
        net.SendMessage(sync_peer_id, victim.GetId(), full);
        for (int i = 0; i < 5; ++i) { net.AdvanceTime(200); }

        // Verify NO reselection occurs (Bitcoin Core sticks with sync peer)
        // Try multiple times to give reselection a chance (it shouldn't happen)
        bool incorrectly_reselected = false;
        for (int i = 0; i < 20; ++i) {
            net.AdvanceTime(200);
            victim.CheckInitialSync();
            int gh_p1_now = net.CountCommandSent(victim.GetId(), p1.GetId(), commands::GETHEADERS);
            int gh_p2_now = net.CountCommandSent(victim.GetId(), p2.GetId(), commands::GETHEADERS);
            if (gh_p1_now > gh_p1_base || gh_p2_now > gh_p2_base) { incorrectly_reselected = true; break; }
        }
        // Bitcoin Core behavior: should NOT reselect after empty headers
        CHECK_FALSE(incorrectly_reselected);
    }
}
