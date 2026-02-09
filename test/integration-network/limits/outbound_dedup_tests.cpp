#include "catch_amalgamated.hpp"
#include "infra/test_access.hpp"
#include "infra/mock_transport.hpp"
#include "network/connection_manager.hpp"
#include "network/addr_relay_manager.hpp"
#include "network/network_manager.hpp" // for ConnectionResult enum
#include "network/protocol.hpp"
#include <asio.hpp>
#include <atomic>

using namespace unicity;
using unicity::test::AddrRelayManagerTestAccess;
using namespace unicity::network;

namespace {

// Transport that counts connect() calls and succeeds/fails on demand
class CountingTransport : public Transport {
public:
    explicit CountingTransport(bool succeed = true) : succeed_(succeed) {}
    void SetSucceed(bool s) { succeed_ = s; }
    int connect_count() const { return count_.load(std::memory_order_relaxed); }

    TransportConnectionPtr connect(const std::string& address, uint16_t port, ConnectCallback callback) override {
        count_.fetch_add(1, std::memory_order_relaxed);
        if (!succeed_) {
            // Simulate immediate failure
            return nullptr;
        }
        auto conn = std::make_shared<MockTransportConnection>(address, port);
        conn->set_inbound(false);
        if (callback) callback(true);
        return conn;
    }

    bool listen(uint16_t, std::function<void(TransportConnectionPtr)>) override { return true; }
    void stop_listening() override {}
    void run() override {}
    void stop() override {}
    bool is_running() const override { return true; }

private:
    bool succeed_;
    std::atomic<int> count_{0};
};

} // namespace

TEST_CASE("Outbound per-cycle and in-flight dedup", "[network][limits][dedup]") {
    asio::io_context io;
    ConnectionManager plm(io, ConnectionManager::Config{});
    AddrRelayManager pdm(&plm);

    // Seed a single routable address so Select() would otherwise keep returning it
    protocol::NetworkAddress addr = protocol::NetworkAddress::from_string("93.184.216.34", protocol::ports::REGTEST);
    REQUIRE(AddrRelayManagerTestAccess::GetAddrManager(pdm).add(addr));

    auto transport = std::make_shared<CountingTransport>(/*succeed=*/true);
    plm.Init(transport, [](Peer*){}, [](){ return true; }, protocol::magic::REGTEST, /*local_nonce=*/42);

    // First cycle: we should attempt once (per-cycle dedup prevents multiple dials to same addr within the cycle)
    plm.AttemptOutboundConnections(/*current_height=*/0);
    io.poll();
    io.restart();
    REQUIRE(transport->connect_count() == 1);

    // Second cycle: the first connection is in pending_outbound_ (async callback not yet processed),
    // so in-flight dedup inside ConnectTo will skip it. But io.poll() already ran the posted callback
    // which created the peer, so the address is now in the peer list and find_peer_by_address
    // returns AlreadyConnected.
    plm.AttemptOutboundConnections(/*current_height=*/0);
    io.poll();
    io.restart();
    // Should not make a second connection to the same address
    REQUIRE(transport->connect_count() == 1);

    // Test with failing transport: connection attempts don't persist in pending or peer list
    ConnectionManager plm2(io, ConnectionManager::Config{});
    AddrRelayManager pdm2(&plm2);
    REQUIRE(AddrRelayManagerTestAccess::GetAddrManager(pdm2).add(addr));

    auto transport2 = std::make_shared<CountingTransport>(/*succeed=*/false);
    plm2.Init(transport2, [](Peer*){}, [](){ return true; }, protocol::magic::REGTEST, /*local_nonce=*/43);

    // First cycle with failing transport: attempt is made but fails immediately
    plm2.AttemptOutboundConnections(/*current_height=*/0);
    io.poll();
    io.restart();
    REQUIRE(transport2->connect_count() == 1);

    // Second cycle: since the first attempt failed (no peer created, pending cleared),
    // the address can be attempted again
    plm2.AttemptOutboundConnections(/*current_height=*/0);
    io.poll();
    io.restart();
    REQUIRE(transport2->connect_count() == 2);
}
