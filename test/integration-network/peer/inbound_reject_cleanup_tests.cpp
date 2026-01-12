#include "catch_amalgamated.hpp"
#include "network/peer_lifecycle_manager.hpp"
#include "network/protocol.hpp"
#include "infra/mock_transport.hpp"
#include <asio.hpp>

using namespace unicity;
using namespace unicity::network;

TEST_CASE("Inbound reject cleanly disconnects transient peer", "[network][inbound][cleanup]") {
    // Configure manager to reject all inbound (max_inbound_peers = 0)
    asio::io_context io;
    PeerLifecycleManager::Config cfg;
    cfg.max_inbound_peers = 0;
    PeerLifecycleManager plm(io, cfg);

    // Build a mock inbound connection and pass it to HandleInboundConnection
    auto conn = std::make_shared<MockTransportConnection>();
    conn->set_inbound(true);

    auto is_running = [](){ return true; };
    auto setup_handler = [](Peer*){};

    plm.HandleInboundConnection(
        conn,
        is_running,
        setup_handler,
        protocol::magic::REGTEST,
        /*height=*/0,
        /*local_nonce=*/42,
        NetPermissionFlags::None
    );

    // No peers should be added; connection must be closed by transient peer cleanup
    REQUIRE(plm.peer_count() == 0);
    REQUIRE_FALSE(conn->is_open());
}
