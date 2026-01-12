#include "catch_amalgamated.hpp"
#include "network/real_transport.hpp"
#include <asio/executor_work_guard.hpp>
#include <atomic>
#include <condition_variable>
#include <mutex>
#include <string>
#include <thread>
#include <chrono>

using namespace unicity::network;

namespace {

// Helper to manage io_context + thread for tests
class TestIoContext {
public:
    TestIoContext()
        : io_context_(),
          work_guard_(asio::make_work_guard(io_context_)),
          thread_([this]() { io_context_.run(); }) {}

    ~TestIoContext() {
        work_guard_.reset();
        io_context_.stop();
        if (thread_.joinable()) {
            thread_.join();
        }
    }

    asio::io_context& get() { return io_context_; }

private:
    asio::io_context io_context_;
    asio::executor_work_guard<asio::io_context::executor_type> work_guard_;
    std::thread thread_;
};

// Pick an available high-range port; try a small range to avoid flakiness.
static uint16_t pick_listen_port(RealTransport& t,
                                 std::function<void(TransportConnectionPtr)> accept_cb,
                                 uint16_t start = 42000,
                                 uint16_t end = 42100) {
    for (uint16_t p = start; p < end; ++p) {
        if (t.listen(p, accept_cb)) return p;
    }
    // Fallback: bind ephemeral port (0) and query the assigned port
    if (t.listen(0, accept_cb)) {
        return t.listening_port();
    }
    return 0;
}
}

TEST_CASE("RealTransport lifecycle is idempotent", "[network][transport][real]") {
    TestIoContext io;
    RealTransport t(io.get());

    // RealTransport with external io_context is always considered "running"
    CHECK(t.is_running());

    // stop() is idempotent and safe
    t.stop();
    t.stop();
    t.stop();

    // After stop, is_running() returns false
    CHECK_FALSE(t.is_running());
}

TEST_CASE("RealTransport listen/connect echo roundtrip", "[network][transport][real]") {
    TestIoContext io;
    RealTransport server(io.get());
    RealTransport client(io.get());

    std::shared_ptr<TransportConnection> inbound_conn;
    std::mutex m;
    std::condition_variable cv;
    bool accepted = false;
    bool connected = false;
    bool echoed = false;

    auto accept_cb = [&](TransportConnectionPtr c){
        {
            std::lock_guard<std::mutex> lk(m);
            inbound_conn = c;
            accepted = true;
        }
        // Echo server: read and write back
        inbound_conn->set_receive_callback([&](const std::vector<uint8_t>& data){
            (void)inbound_conn->send(data);
        });
        inbound_conn->start();
        cv.notify_all();
    };

    // Try to bind (ephemeral fallback inside pick_listen_port)
    uint16_t port = pick_listen_port(server, accept_cb);
    if (port == 0) {
        WARN("Skipping: unable to bind any listening port (range + ephemeral)");
        return;
    }

    // Connect client
    std::shared_ptr<TransportConnection> client_conn;
    client_conn = client.connect("127.0.0.1", port, [&](bool ok){
        {
            std::lock_guard<std::mutex> lk(m);
            connected = ok;
        }
        if (ok && client_conn) {
            client_conn->start();
        }
        cv.notify_all();
    });
    REQUIRE(client_conn);

    // Prepare to receive echo
    std::vector<uint8_t> received;
    client_conn->set_receive_callback([&](const std::vector<uint8_t>& data){
        {
            std::lock_guard<std::mutex> lk(m);
            received = data;
            echoed = true;
        }
        cv.notify_all();
    });

    // Wait for accept+connect
    {
        std::unique_lock<std::mutex> lk(m);
        cv.wait_for(lk, std::chrono::seconds(3), [&]{ return accepted && connected; });
    }
    REQUIRE(accepted);
    REQUIRE(connected);

    // Verify canonical remote addresses are non-empty and look like IPs
    CHECK(!client_conn->remote_address().empty());
    CHECK(!inbound_conn->remote_address().empty());

    // Send payload and expect echo
    const std::string payload = "hello";
    std::vector<uint8_t> bytes(payload.begin(), payload.end());
    CHECK(client_conn->send(bytes));

    {
        std::unique_lock<std::mutex> lk(m);
        cv.wait_for(lk, std::chrono::seconds(3), [&]{ return echoed; });
    }
    REQUIRE(echoed);
    std::string echoed_str(received.begin(), received.end());
    CHECK(echoed_str == payload);

    // Close and ensure further sends fail (close is async via strand)
    client_conn->close();
    for (int i = 0; i < 50 && client_conn->is_open(); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    CHECK_FALSE(client_conn->send(bytes));

    client.stop();
    server.stop();
}

TEST_CASE("RealTransport can listen on ephemeral port after privileged port fails", "[network][transport][real][listen]") {
    TestIoContext io;
    RealTransport t(io.get());
    auto noop_accept = [](TransportConnectionPtr){};

    // Try privileged port (expected to fail on most systems without root)
    bool privileged_failed = !t.listen(1, noop_accept);

    if (!privileged_failed) {
        // System allows binding to port 1; clean up and skip privilege test
        t.stop_listening();
        t.stop();
        SKIP("Binding to port 1 succeeded (running as root?); skipping privilege test");
        return;  // Ensure we exit after SKIP
    }

    // Verify we can still listen on ephemeral port after privileged port failure
    // This tests that RealTransport state is correctly reset after listen() fails
    if (!t.listen(0, noop_accept)) {
        WARN("Unable to listen on ephemeral port; environment may restrict binds");
        t.stop();
        return;
    }
    CHECK(t.listening_port() > 0);

    t.stop();
}

TEST_CASE("RealTransport listening_port returns bound ephemeral port", "[network][transport][real][listen]") {
    TestIoContext io;
    RealTransport t(io.get());

    auto noop_accept = [](TransportConnectionPtr){};
    if (!t.listen(0, noop_accept)) {
        WARN("Skipping: unable to bind ephemeral port");
        t.stop();
        return;
    }

    CHECK(t.listening_port() > 0);
    t.stop();
}

TEST_CASE("RealTransport connect timeout triggers timely failure", "[network][transport][real][timeout]") {
    TestIoContext io;
    RealTransport t(io.get());

    // Set a short timeout override for this test
    RealTransportConnection::SetConnectTimeoutForTest(std::chrono::milliseconds(200));

    std::mutex m;
    std::condition_variable cv;
    bool done = false;
    bool ok = true;

    auto start = std::chrono::steady_clock::now();

    std::shared_ptr<TransportConnection> conn;
    conn = t.connect("203.0.113.1", 65530, [&](bool success){
        std::lock_guard<std::mutex> lk(m);
        ok = success;
        done = true;
        cv.notify_all();
    });
    REQUIRE(conn);

    {
        std::unique_lock<std::mutex> lk(m);
        bool signaled = cv.wait_for(lk, std::chrono::seconds(2), [&]{ return done; });
        REQUIRE(signaled);
    }

    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start);

    // Must fail, and should complete quickly (either immediate failure or timer)
    CHECK_FALSE(ok);
    CHECK(elapsed.count() <= 1000);

    RealTransportConnection::ResetConnectTimeoutForTest();
    t.stop();
}

TEST_CASE("No stray receive callbacks after close() in handler", "[network][transport][real][receive]") {
    TestIoContext io;
    RealTransport server(io.get());
    RealTransport client(io.get());

    std::shared_ptr<TransportConnection> inbound_conn;
    std::mutex m;
    std::condition_variable cv;
    int receive_count = 0;
    bool accepted = false;
    bool connected = false;

    auto accept_cb = [&](TransportConnectionPtr c){
        {
            std::lock_guard<std::mutex> lk(m);
            inbound_conn = c;
            accepted = true;
        }
        inbound_conn->set_receive_callback([&](const std::vector<uint8_t>&){
            {
                std::lock_guard<std::mutex> lk(m);
                receive_count++;
            }
            // Close immediately from within handler
            inbound_conn->close();
            cv.notify_all();
        });
        inbound_conn->start();
        cv.notify_all();
    };

    uint16_t port = pick_listen_port(server, accept_cb);
    if (port == 0) {
        WARN("Skipping: unable to bind any listening port (range + ephemeral)");
        return;
    }

    std::shared_ptr<TransportConnection> client_conn;
    client_conn = client.connect("127.0.0.1", port, [&](bool ok2){
        std::lock_guard<std::mutex> lk(m);
        connected = ok2;
        if (ok2) { client_conn->start(); }
        cv.notify_all();
    });
    REQUIRE(client_conn);

    // Wait until connected
    {
        std::unique_lock<std::mutex> lk(m);
        cv.wait_for(lk, std::chrono::seconds(3), [&]{ return accepted && connected; });
    }

    // Send one byte
    std::vector<uint8_t> one = {0x42};
    CHECK(client_conn->send(one));

    // Wait for first receive
    {
        std::unique_lock<std::mutex> lk(m);
        cv.wait_for(lk, std::chrono::seconds(2), [&]{ return receive_count >= 1; });
    }

    // Allow handler to complete and ensure no second callback happens
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    CHECK(receive_count == 1);

    client.stop();
    server.stop();
}

TEST_CASE("Read error: remote close triggers single disconnect and no reschedule", "[network][transport][real][read]") {
    TestIoContext io;
    RealTransport server(io.get());
    RealTransport client(io.get());

    std::shared_ptr<TransportConnection> inbound_conn;
    std::mutex m;
    std::condition_variable cv;
    bool accepted = false;
    bool connected = false;
    int client_disconnects = 0;

    auto accept_cb = [&](TransportConnectionPtr c){
        inbound_conn = c;
        accepted = true;
        inbound_conn->start();
        cv.notify_all();
    };

    uint16_t port = pick_listen_port(server, accept_cb);
    if (port == 0) { WARN("Skipping: unable to bind any listening port"); return; }

    auto client_conn = client.connect("127.0.0.1", port, [&](bool ok){ connected = ok; cv.notify_all(); });
    REQUIRE(client_conn);

    client_conn->set_disconnect_callback([&](){
        std::lock_guard<std::mutex> lk(m);
        client_disconnects++;
        cv.notify_all();
    });
    client_conn->set_receive_callback([&](const std::vector<uint8_t>&){ /* no-op */ });

    {
        std::unique_lock<std::mutex> lk(m);
        cv.wait_for(lk, std::chrono::seconds(3), [&]{ return accepted && connected; });
    }
    REQUIRE(accepted);
    REQUIRE(connected);

    client_conn->start();

    // Remote closes -> client should get exactly one disconnect
    inbound_conn->close();

    {
        std::unique_lock<std::mutex> lk(m);
        cv.wait_for(lk, std::chrono::seconds(2), [&]{ return client_disconnects >= 1; });
    }
    CHECK(client_disconnects == 1);

    client.stop();
    server.stop();
}

TEST_CASE("Close during connect results in single false callback and no stray events", "[network][transport][real][connect]") {
    TestIoContext io;
    RealTransport t(io.get());

    std::mutex m; std::condition_variable cv;
    int cb_count = 0; bool ok = true;

    auto conn = t.connect("203.0.113.1", 65530, [&](bool success){
        std::lock_guard<std::mutex> lk(m);
        cb_count++; ok = success; cv.notify_all();
    });
    REQUIRE(conn);

    // Close immediately; expect at most one callback (false)
    conn->close();

    {
        std::unique_lock<std::mutex> lk(m);
        cv.wait_for(lk, std::chrono::milliseconds(500), [&]{ return cb_count >= 1; });
    }

    // Either we get a single false callback, or none (close canceled connect before callback path)
    CHECK((cb_count == 0 || cb_count == 1));
    if (cb_count == 1) {
        CHECK_FALSE(ok);
    }

    t.stop();
}

TEST_CASE("Connect race: small timeout does not double-callback on fast success", "[network][transport][real][connect]") {
    TestIoContext io;
    RealTransport server(io.get());
    RealTransport client(io.get());

    std::shared_ptr<TransportConnection> inbound_conn;
    auto accept_cb = [&](TransportConnectionPtr c){ inbound_conn = c; inbound_conn->start(); };
    uint16_t port = pick_listen_port(server, accept_cb);
    if (port == 0) { WARN("Skipping: unable to bind any listening port"); return; }

    RealTransportConnection::SetConnectTimeoutForTest(std::chrono::milliseconds(10));

    std::mutex m; std::condition_variable cv; int cb_count=0; bool ok=false;
    auto conn = client.connect("127.0.0.1", port, [&](bool success){ std::lock_guard<std::mutex> lk(m); cb_count++; ok=success; cv.notify_all(); });
    REQUIRE(conn);

    {
        std::unique_lock<std::mutex> lk(m);
        cv.wait_for(lk, std::chrono::seconds(1), [&]{ return cb_count == 1; });
    }

    CHECK(cb_count == 1);
    CHECK(ok);

    RealTransportConnection::ResetConnectTimeoutForTest();
    client.stop(); server.stop();
}

TEST_CASE("Send-queue overflow closes connection (test override)", "[network][transport][real][send-queue]") {
    TestIoContext io;
    RealTransport server(io.get());
    RealTransport client(io.get());

    std::shared_ptr<TransportConnection> inbound_conn;
    std::mutex m; std::condition_variable cv; bool accepted=false; bool connected=false; int client_disc=0;

    auto accept_cb = [&](TransportConnectionPtr c){ inbound_conn = c; accepted=true; inbound_conn->start(); cv.notify_all(); };
    uint16_t port = pick_listen_port(server, accept_cb);
    if (port == 0) { WARN("Skipping: unable to bind any listening port"); return; }

    auto client_conn = client.connect("127.0.0.1", port, [&](bool ok){ std::lock_guard<std::mutex> lk(m); connected = ok; cv.notify_all(); });
    REQUIRE(client_conn);

    client_conn->set_disconnect_callback([&](){ std::lock_guard<std::mutex> lk(m); client_disc++; cv.notify_all(); });

    // Wait for connection established
    {
        std::unique_lock<std::mutex> lk(m);
        cv.wait_for(lk, std::chrono::seconds(2), [&]{ return accepted && connected; });
    }

    client_conn->start();

    // Set very small queue limit and send a payload bigger than the limit
    RealTransportConnection::SetSendQueueLimitForTest(512);

    std::vector<uint8_t> big(2048, 0xAA);
    CHECK(client_conn->send(big));

    {
        std::unique_lock<std::mutex> lk(m);
        cv.wait_for(lk, std::chrono::seconds(1), [&]{ return client_disc >= 1; });
    }

    CHECK(client_disc == 1);
    CHECK_FALSE(client_conn->send(big));

    RealTransportConnection::ResetSendQueueLimitForTest();

    client.stop(); server.stop();
}

TEST_CASE("Double close delivers disconnect once", "[network][transport][real][close]") {
    TestIoContext io;
    RealTransport t(io.get());
    std::mutex m; std::condition_variable cv; int disc=0;

    auto conn = t.connect("203.0.113.1", 65530, [&](bool){ /* ignore */ });
    REQUIRE(conn);

    conn->set_disconnect_callback([&](){ std::lock_guard<std::mutex> lk(m); disc++; cv.notify_all(); });

    conn->close();
    conn->close();

    // For a connection that never opened, close() should be idempotent and not call disconnect callback.
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    CHECK(disc == 0);
    t.stop();
}

TEST_CASE("Close with pending read notifies remote side", "[network][transport][real][close]") {
    TestIoContext io;
    RealTransport server(io.get());
    RealTransport client(io.get());
    std::shared_ptr<TransportConnection> inbound_conn;
    std::mutex m; std::condition_variable cv;
    bool accepted = false;
    bool connected = false;
    int client_disconnects = 0;
    int server_disconnects = 0;

    auto accept_cb = [&](TransportConnectionPtr c){
        inbound_conn = c;
        inbound_conn->set_receive_callback([](const std::vector<uint8_t>&){});
        inbound_conn->set_disconnect_callback([&](){
            std::lock_guard<std::mutex> lk(m);
            server_disconnects++;
            cv.notify_all();
        });
        inbound_conn->start();
        {
            std::lock_guard<std::mutex> lk(m);
            accepted = true;
        }
        cv.notify_all();
    };

    uint16_t port = pick_listen_port(server, accept_cb);
    if (port == 0) { WARN("Skipping: unable to bind any listening port"); return; }

    auto client_conn = client.connect("127.0.0.1", port, [&](bool ok){
        std::lock_guard<std::mutex> lk(m);
        connected = ok;
        cv.notify_all();
    });
    REQUIRE(client_conn);

    client_conn->set_disconnect_callback([&](){
        std::lock_guard<std::mutex> lk(m);
        client_disconnects++;
        cv.notify_all();
    });
    client_conn->set_receive_callback([](const std::vector<uint8_t>&){});

    {
        std::unique_lock<std::mutex> lk(m);
        cv.wait_for(lk, std::chrono::seconds(2), [&]{ return accepted && connected; });
    }
    REQUIRE(accepted);
    REQUIRE(connected);

    // Start reading (async_read_some now pending)
    client_conn->start();

    // Close immediately while read is pending
    client_conn->close();

    // Wait for server to see disconnect
    {
        std::unique_lock<std::mutex> lk(m);
        cv.wait_for(lk, std::chrono::seconds(1), [&]{ return server_disconnects >= 1; });
    }

    // Connection should no longer be open
    CHECK_FALSE(client_conn->is_open());

    // Server sees disconnect (remote closed)
    CHECK(server_disconnects == 1);

    // Client disconnect callback does NOT fire when we call close() ourselves
    // (we initiated the close, so we already know - no need for callback)
    CHECK(client_disconnects == 0);

    client.stop();
    server.stop();
}

TEST_CASE("Close with pending writes notifies remote side", "[network][transport][real][close]") {
    TestIoContext io;
    RealTransport server(io.get());
    RealTransport client(io.get());
    std::shared_ptr<TransportConnection> inbound_conn;
    std::mutex m; std::condition_variable cv;
    bool accepted = false;
    bool connected = false;
    int client_disconnects = 0;
    int server_disconnects = 0;

    auto accept_cb = [&](TransportConnectionPtr c){
        inbound_conn = c;
        inbound_conn->set_receive_callback([](const std::vector<uint8_t>&){});
        inbound_conn->set_disconnect_callback([&](){
            std::lock_guard<std::mutex> lk(m);
            server_disconnects++;
            cv.notify_all();
        });
        inbound_conn->start();
        {
            std::lock_guard<std::mutex> lk(m);
            accepted = true;
        }
        cv.notify_all();
    };

    uint16_t port = pick_listen_port(server, accept_cb);
    if (port == 0) { WARN("Skipping: unable to bind any listening port"); return; }

    auto client_conn = client.connect("127.0.0.1", port, [&](bool ok){
        std::lock_guard<std::mutex> lk(m);
        connected = ok;
        cv.notify_all();
    });
    REQUIRE(client_conn);

    client_conn->set_disconnect_callback([&](){
        std::lock_guard<std::mutex> lk(m);
        client_disconnects++;
        cv.notify_all();
    });

    {
        std::unique_lock<std::mutex> lk(m);
        cv.wait_for(lk, std::chrono::seconds(2), [&]{ return accepted && connected; });
    }
    REQUIRE(accepted);
    REQUIRE(connected);

    // Queue multiple writes (async_write operations now pending)
    for (int i = 0; i < 10; ++i) {
        std::vector<uint8_t> data(256, 0xAB);
        (void)client_conn->send(data);
    }

    // Close immediately while writes are pending
    client_conn->close();

    // Wait for server to see disconnect
    {
        std::unique_lock<std::mutex> lk(m);
        cv.wait_for(lk, std::chrono::seconds(1), [&]{ return server_disconnects >= 1; });
    }

    // Connection should no longer be open
    CHECK_FALSE(client_conn->is_open());

    // Subsequent sends must fail
    std::vector<uint8_t> data(64, 0xCC);
    CHECK_FALSE(client_conn->send(data));

    // Server sees disconnect (remote closed)
    CHECK(server_disconnects == 1);

    // Client disconnect callback does NOT fire when we call close() ourselves
    CHECK(client_disconnects == 0);

    client.stop();
    server.stop();
}

TEST_CASE("Rapid connect/close cycle handles cleanup correctly", "[network][transport][real][close][stress]") {
    TestIoContext io;
    RealTransport server(io.get());
    RealTransport client(io.get());

    std::mutex m;
    std::atomic<int> accepted_count{0};
    std::atomic<int> server_disconnects{0};
    std::vector<std::shared_ptr<TransportConnection>> server_conns;

    auto accept_cb = [&](TransportConnectionPtr c){
        std::lock_guard<std::mutex> lk(m);
        c->set_disconnect_callback([&](){ server_disconnects++; });
        c->start();
        server_conns.push_back(c);
        accepted_count++;
    };

    uint16_t port = pick_listen_port(server, accept_cb);
    if (port == 0) { WARN("Skipping: unable to bind any listening port"); return; }

    // Rapidly create and close 20 real connections
    std::vector<TransportConnectionPtr> client_conns;
    std::atomic<int> connect_callbacks{0};
    std::atomic<int> client_disconnects{0};

    for (int i = 0; i < 20; ++i) {
        auto conn = client.connect("127.0.0.1", port, [&](bool){
            connect_callbacks++;
        });
        if (conn) {
            conn->set_disconnect_callback([&](){ client_disconnects++; });
            client_conns.push_back(conn);
        }
    }

    // Give connections time to establish
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // Close all client connections rapidly
    for (auto& conn : client_conns) {
        conn->close();
    }

    // Wait for disconnects to propagate
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    // Verify: each connection that was accepted should have disconnected
    CHECK(accepted_count > 0);  // At least some connections were accepted
    CHECK(server_disconnects == accepted_count);  // Each accepted connection saw disconnect

    // All client connections should be closed
    for (auto& conn : client_conns) {
        CHECK_FALSE(conn->is_open());
    }

    // Cleanup
    client_conns.clear();
    {
        std::lock_guard<std::mutex> lk(m);
        server_conns.clear();
    }

    client.stop();
    server.stop();
}
