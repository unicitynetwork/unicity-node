#include "catch_amalgamated.hpp"
#include "network/peer_lifecycle_manager.hpp"
#include "network/peer_discovery_manager.hpp"
#include "network/protocol.hpp"
#include "infra/mock_transport.hpp"
#include <asio.hpp>
#include <memory>

using namespace unicity;
using namespace unicity::network;

namespace {

class FakeTransport : public Transport {
public:
    explicit FakeTransport(bool next_success = true) : next_success_(next_success) {}

    void SetNextConnectResult(bool success) { next_success_ = success; }

    TransportConnectionPtr connect(const std::string& address, uint16_t port, ConnectCallback callback) override {
        // Simulate immediate connect success/failure
        if (!next_success_) {
            if (callback) callback(false);
            return nullptr;
        }
        auto conn = std::make_shared<MockTransportConnection>();
        conn->set_inbound(false);
        conn->set_id(++next_id_);
        if (callback) callback(true);
        return conn;
    }

    bool listen(uint16_t, std::function<void(TransportConnectionPtr)>) override { return true; }
    void stop_listening() override {}
    void run() override {}
    void stop() override {}
    bool is_running() const override { return true; }

private:
    bool next_success_;
    uint64_t next_id_{0};
};

static protocol::NetworkAddress MakeAddr(const std::string& ip, uint16_t port) {
    return protocol::NetworkAddress::from_string(ip, port);
}

} // namespace

TEST_CASE("Feeler ID allocation and slot exclusion", "[network][feeler][peer_id]") {
    asio::io_context io;
    PeerLifecycleManager::Config cfg; // defaults: target_outbound_peers = 8
    PeerLifecycleManager plm(io, cfg);

    // Discovery manager (owns addrman); registers itself with plm
    PeerDiscoveryManager pdm(&plm);

    // Seed one routable address into NEW table for feeler
    auto addr = MakeAddr("93.184.216.34", protocol::ports::REGTEST);
    REQUIRE(pdm.addr_manager_for_test().add(addr));

    auto transport = std::make_shared<FakeTransport>(/*next_success=*/false);

    auto is_running = [](){ return true; };
    auto get_transport = [transport](){ return std::static_pointer_cast<Transport>(transport); };
    auto setup_handler = [](Peer*){};

    // Attempt feeler with failing transport: should NOT allocate a peer/ID
    plm.AttemptFeelerConnection(is_running, get_transport, setup_handler,
                                protocol::magic::REGTEST, /*height=*/0, /*nonce=*/12345);
    // Run posted callback
    io.poll();
    io.restart();

    REQUIRE(plm.peer_count() == 0);           // No peer added => no ID allocated
    REQUIRE(plm.outbound_count() == 0);       // No outbound slots consumed

    // Now succeed: should allocate exactly one feeler peer and still not consume outbound slot
    transport->SetNextConnectResult(true);
    plm.AttemptFeelerConnection(is_running, get_transport, setup_handler,
                                protocol::magic::REGTEST, /*height=*/0, /*nonce=*/12346);
    io.poll();
    io.restart();

    REQUIRE(plm.peer_count() == 1);
    REQUIRE(plm.outbound_count() == 0);       // Feelers are excluded from outbound slots

    auto peers = plm.get_all_peers();
    REQUIRE(peers.size() == 1);
    REQUIRE(peers[0]);
    REQUIRE(peers[0]->is_feeler());
}
