#include "catch_amalgamated.hpp"
#include "network/connection_manager.hpp"
#include "network/protocol.hpp"
#include "infra/mock_transport.hpp"
#include <asio.hpp>

using namespace unicity;
using namespace unicity::network;

TEST_CASE("Manual outbound connections don't consume slots", "[network][limits][manual]") {
    asio::io_context io;
    ConnectionManager::Config cfg;
    cfg.max_outbound_peers = 1; // small to exercise gating
    ConnectionManager plm(io, cfg);

    // Create a full-relay outbound peer and add it (consumes the single slot)
    auto conn1 = std::make_shared<MockTransportConnection>();
    auto p1 = Peer::create_outbound(io, conn1, protocol::magic::REGTEST, /*height=*/0,
                                    "127.0.0.1", protocol::ports::REGTEST,
                                    ConnectionType::OUTBOUND_FULL_RELAY);
    REQUIRE(p1);
    int id1 = plm.add_peer(p1, NetPermissionFlags::None, p1->address());
    REQUIRE(id1 > 0);

    // Now create a manual outbound peer and ensure add_peer succeeds even though full-relay slots are full
    auto conn2 = std::make_shared<MockTransportConnection>();
    auto p2 = Peer::create_outbound(io, conn2, protocol::magic::REGTEST, /*height=*/0,
                                    "127.0.0.2", protocol::ports::REGTEST,
                                    ConnectionType::MANUAL);
    REQUIRE(p2);
    int id2 = plm.add_peer(p2, NetPermissionFlags::Manual | NetPermissionFlags::NoBan, p2->address());
    REQUIRE(id2 > 0);

    // outbound_count excludes manual and feeler; should still report 1
    REQUIRE(plm.outbound_count() == 1);
    // total peers should be 2
    REQUIRE(plm.peer_count() == 2);

    // Cleanup: remove peers to ensure proper disconnect lifecycle in test
    plm.remove_peer(id1);
    plm.remove_peer(id2);
}
