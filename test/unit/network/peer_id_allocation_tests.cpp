#include "catch_amalgamated.hpp"
#include "network/peer_lifecycle_manager.hpp"
#include "network/transport.hpp"
#include "network/protocol.hpp"
#include "network/peer.hpp"
#include <asio.hpp>

using namespace unicity::network;
using unicity::protocol::NetworkAddress;

namespace {
// Build an IPv4-mapped IPv6 address for 127.0.0.X:port
// last_octet allows creating different IPs to avoid duplicate connection checks
static NetworkAddress mk_addr(uint16_t port, uint8_t last_octet = 1) {
    NetworkAddress a{};
    a.services = unicity::protocol::NODE_NETWORK;
    a.port = port;
    for (int i = 0; i < 10; ++i) a.ip[i] = 0;
    a.ip[10] = 0xFF; a.ip[11] = 0xFF;
    a.ip[12] = 127; a.ip[13] = 0; a.ip[14] = 0; a.ip[15] = last_octet;
    return a;
}

// Minimal stub connection
class StubConnection : public TransportConnection {
public:
    explicit StubConnection(const std::string& addr, uint16_t port)
        : open_(true), addr_(addr), port_(port) {}
    void start() override {}
    bool send(const std::vector<uint8_t>&) override { return open_; }
    void close() override { open_ = false; if (disc_) disc_(); }
    bool is_open() const override { return open_; }
    std::string remote_address() const override { return addr_; }
    uint16_t remote_port() const override { return port_; }
    bool is_inbound() const override { return false; }
    uint64_t connection_id() const override { return 1; }
    void set_receive_callback(ReceiveCallback cb) override { recv_ = std::move(cb); }
    void set_disconnect_callback(DisconnectCallback cb) override { disc_ = std::move(cb); }
private:
    bool open_;
    std::string addr_;
    uint16_t port_;
    ReceiveCallback recv_;
    DisconnectCallback disc_;
};

// Minimal transport that can force success/failure connect outcomes
class MiniTransport : public Transport {
public:
    explicit MiniTransport(asio::io_context& io) : io_(io) {}
    void set_next_success(bool s) { next_success_ = s; }

    TransportConnectionPtr connect(const std::string &address,
                                   uint16_t port,
                                   ConnectCallback callback) override {
        auto conn = std::make_shared<StubConnection>(address, port);
        // Simulate async callback via io_.post
        asio::post(io_, [cb = std::move(callback), s = next_success_]() {
            if (cb) cb(s);
        });
        return conn;
    }

    bool listen(uint16_t, std::function<void(TransportConnectionPtr)>) override { return false; }
    void stop_listening() override {}
    void run() override {}
    void stop() override {}
    bool is_running() const override { return true; }
private:
    asio::io_context& io_;
    bool next_success_{false};
};
} // namespace

TEST_CASE("Outbound connect failures do not consume peer IDs", "[network][peer_id]") {
    asio::io_context io;
    PeerLifecycleManager::Config cfg;
    PeerLifecycleManager pm(io, cfg);

    // Speed up timers to avoid waiting on real handshake/idle defaults during io.run()
    using unicity::network::Peer;
    Peer::SetTimeoutsForTest(std::chrono::milliseconds(50), std::chrono::milliseconds(200));
    struct ResetTimeoutsGuard { ~ResetTimeoutsGuard() { Peer::ResetTimeoutsForTest(); } } _guard;

    auto transport = std::make_shared<MiniTransport>(io);
    auto addr = mk_addr(9999);

    // 100 failing attempts
    for (int i = 0; i < 100; ++i) {
        transport->set_next_success(false);
        auto rc = pm.ConnectTo(
            addr,
            NetPermissionFlags::None,
            transport,
            nullptr, // on_good
            nullptr, // on_attempt
            [](Peer*){}, // setup handler
            0x12345678,
            0,
            42
        );
        // pump callbacks
        io.poll();
        // No peer should be added
        REQUIRE(pm.peer_count() == 0);
    }

    // Now one success -> should allocate first ID (1) and add exactly one peer
    transport->set_next_success(true);
    auto rc = pm.ConnectTo(
        addr,
        NetPermissionFlags::None,
        transport,
        nullptr,
        nullptr,
        [](Peer*){},
        0x12345678,
        0,
        4242
    );
    io.restart();
    io.run(); // process deferred posts

    REQUIRE(pm.peer_count() == 1);

    // Retrieve the only peer and check its id is 1
    auto peers = pm.get_all_peers();
    REQUIRE(peers.size() == 1);
    REQUIRE(peers[0] != nullptr);
    REQUIRE(peers[0]->id() == 1);

    // Second success -> id should be 2
    // Use different IP (last_octet=2) because Bitcoin Core prevents duplicate connections to same IP
    io.restart();
    auto addr2 = mk_addr(10000, 2);
    transport->set_next_success(true);
    rc = pm.ConnectTo(
        addr2,
        NetPermissionFlags::None,
        transport,
        nullptr,
        nullptr,
        [](Peer*){},
        0x12345678,
        0,
        7777
    );
    io.run();

    REQUIRE(pm.peer_count() == 2);
    auto peers2 = pm.get_all_peers();
    REQUIRE(peers2.size() == 2);
    // peers are sorted by id in get_all_peers(); last should be id 2
    REQUIRE(peers2[1]->id() == 2);
}
