#include "catch_amalgamated.hpp"
#include "network/connection_manager.hpp"
#include "network/network_manager.hpp" // for ConnectionResult enum
#include "network/protocol.hpp"
#include "infra/mock_transport.hpp"
#include <asio.hpp>
#include <memory>

using namespace unicity;
using namespace unicity::network;

namespace {

// Transport that calls the callback synchronously BEFORE returning the connection
class SyncCallbackTransport : public Transport {
public:
    TransportConnectionPtr connect(const std::string&, uint16_t, ConnectCallback callback) override {
        auto conn = std::make_shared<MockTransportConnection>();
        conn->set_inbound(false);
        if (callback) callback(true); // callback first (connection not yet returned to caller)
        return conn;                   // then return the connection
    }

    bool listen(uint16_t, std::function<void(TransportConnectionPtr)>) override { return true; }
    void stop_listening() override {}
    void run() override {}
    void stop() override {}
    bool is_running() const override { return true; }

};

static protocol::NetworkAddress MakeAddr(const std::string& ip, uint16_t port) {
    return protocol::NetworkAddress::from_string(ip, port);
}

} // namespace

TEST_CASE("Synchronous transport callback still yields a connected peer", "[network][regression][transport]") {
    asio::io_context io;
    ConnectionManager plm(io, ConnectionManager::Config{});

    auto transport = std::make_shared<SyncCallbackTransport>();
    plm.Init(transport, [](Peer*){}, [](){ return true; }, protocol::magic::REGTEST, /*local_nonce=*/777);

    auto addr = MakeAddr("127.0.0.7", protocol::ports::REGTEST);

    auto result = plm.ConnectTo(addr, NetPermissionFlags::None, /*chain_height=*/0);

    REQUIRE(result == ConnectionResult::Success);

    // Run the posted continuation that executes after holder assignment
    io.poll();
    io.restart();

    REQUIRE(plm.peer_count() == 1);
    auto peers = plm.get_all_peers();
    REQUIRE(peers.size() == 1);
    REQUIRE(peers[0]);
    // Outbound full-relay peer (not feeler)
    REQUIRE_FALSE(peers[0]->is_inbound());
    REQUIRE_FALSE(peers[0]->is_feeler());
}
