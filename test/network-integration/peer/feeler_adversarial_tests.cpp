/**
 * Feeler Connection Adversarial Tests
 *
 * These tests verify Bitcoin Core-compatible behavior for feeler connections
 * under adversarial conditions. Feelers are short-lived connections used to
 * validate addresses in the "new" table before promoting them to "tried".
 *
 * Key invariants tested:
 * 1. Address should only be marked Good() after successful handshake (not on TCP connect)
 *    Note: For feelers, handshake completes at VERSION (they disconnect before VERACK).
 *    For regular connections, Good() is called after VERACK.
 * 2. Failed feeler connections should call Failed() to trigger backoff
 * 3. Feelers that timeout without VERSION should not promote the address
 * 4. Malicious peers that accept TCP but don't complete handshake shouldn't pollute tried table
 */

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

/**
 * Transport that simulates TCP connect success but allows control over
 * whether the connection stays open (simulating stuck handshake)
 */
class AdversarialTransport : public Transport {
public:
    explicit AdversarialTransport(asio::io_context& io) : io_(io) {}

    void SetNextConnectResult(bool success) { next_success_ = success; }

    // If true, callback is posted async (more realistic)
    void SetAsyncCallback(bool async) { async_callback_ = async; }

    TransportConnectionPtr connect(const std::string& address, uint16_t port, ConnectCallback callback) override {
        if (!next_success_) {
            // Realistic behavior: either return nullptr (sync failure) OR call callback async (async failure)
            // Real transports typically return a connection object and call callback later with result
            // For sync failure simulation, we return nullptr and DON'T call callback
            // (the caller handles nullptr as immediate failure)
            return nullptr;
        }

        auto conn = std::make_shared<MockTransportConnection>();
        conn->set_inbound(false);
        conn->set_id(++next_id_);
        last_connection_ = conn;

        if (async_callback_) {
            asio::post(io_, [callback]() { if (callback) callback(true); });
        } else {
            if (callback) callback(true);
        }
        return conn;
    }

    // Get last connection for test manipulation
    std::shared_ptr<MockTransportConnection> GetLastConnection() { return last_connection_; }

    bool listen(uint16_t, std::function<void(TransportConnectionPtr)>) override { return true; }
    void stop_listening() override {}
    void run() override {}
    void stop() override {}
    bool is_running() const override { return true; }

private:
    asio::io_context& io_;
    bool next_success_{true};
    bool async_callback_{false};
    uint64_t next_id_{0};
    std::shared_ptr<MockTransportConnection> last_connection_;
};

static protocol::NetworkAddress MakeAddr(const std::string& ip, uint16_t port) {
    return protocol::NetworkAddress::from_string(ip, port);
}

} // namespace

TEST_CASE("Feeler should not mark address Good on TCP connect (before VERACK)", "[network][feeler][adversarial]") {
    asio::io_context io;
    PeerLifecycleManager::Config cfg;
    PeerLifecycleManager plm(io, cfg);
    PeerDiscoveryManager pdm(&plm);

    // Seed address into NEW table
    auto addr = MakeAddr("93.184.216.34", protocol::ports::REGTEST);
    REQUIRE(pdm.addr_manager_for_test().add(addr));

    // Verify address is in NEW table (not tried)
    size_t new_before = pdm.NewCount();
    size_t tried_before = pdm.TriedCount();
    REQUIRE(new_before >= 1);
    REQUIRE(tried_before == 0);

    auto transport = std::make_shared<AdversarialTransport>(io);
    transport->SetNextConnectResult(true);  // TCP will succeed

    auto is_running = [](){ return true; };
    auto get_transport = [transport](){ return std::static_pointer_cast<Transport>(transport); };
    auto setup_handler = [](Peer*){};

    // Attempt feeler - TCP connects but VERACK never happens
    plm.AttemptFeelerConnection(is_running, get_transport, setup_handler,
                                protocol::magic::REGTEST, /*height=*/0, /*nonce=*/12345);
    io.poll();
    io.restart();

    // Peer should be created (feeler connected at TCP level)
    REQUIRE(plm.peer_count() == 1);

    // BUG DETECTION: Check if address was prematurely moved to tried table
    // Bitcoin Core: Address should NOT be in tried table yet (VERACK hasn't happened)
    // Current buggy behavior: Address IS moved to tried immediately on TCP connect
    size_t new_after = pdm.NewCount();
    size_t tried_after = pdm.TriedCount();

    // This is what SHOULD happen (Bitcoin Core behavior):
    // CHECK(new_after == new_before);   // Address still in NEW
    // CHECK(tried_after == tried_before); // Nothing moved to TRIED

    // This check will FAIL with current buggy code, proving the bug:
    INFO("new_before=" << new_before << " new_after=" << new_after);
    INFO("tried_before=" << tried_before << " tried_after=" << tried_after);

    // The correct behavior: address should still be in NEW table
    // Good() should only be called after VERACK completes
    CHECK(tried_after == tried_before);  // FAILS: proves premature Good() bug
}

TEST_CASE("Feeler TCP failure should call Failed() not Attempt()", "[network][feeler][adversarial]") {
    asio::io_context io;
    PeerLifecycleManager::Config cfg;
    PeerLifecycleManager plm(io, cfg);
    PeerDiscoveryManager pdm(&plm);

    // Seed address into NEW table
    auto addr = MakeAddr("93.184.216.35", protocol::ports::REGTEST);
    REQUIRE(pdm.addr_manager_for_test().add(addr));

    auto transport = std::make_shared<AdversarialTransport>(io);
    transport->SetNextConnectResult(false);  // TCP will fail

    auto is_running = [](){ return true; };
    auto get_transport = [transport](){ return std::static_pointer_cast<Transport>(transport); };
    auto setup_handler = [](Peer*){};

    // Record metrics before
    uint64_t failures_before = plm.GetFeelerFailures();

    // Attempt feeler - TCP fails
    plm.AttemptFeelerConnection(is_running, get_transport, setup_handler,
                                protocol::magic::REGTEST, /*height=*/0, /*nonce=*/12345);
    io.poll();
    io.restart();

    // No peer should be created
    REQUIRE(plm.peer_count() == 0);

    // Failure should be recorded
    uint64_t failures_after = plm.GetFeelerFailures();
    CHECK(failures_after == failures_before + 1);

    // BUG: Current code calls Attempt() instead of Failed()
    // This means the address won't get proper backoff treatment
    // We can't easily verify this without exposing AddressManager internals,
    // but the fix is to change Attempt() -> Failed() in the failure path
}

TEST_CASE("Feeler to peer that accepts TCP but never completes handshake", "[network][feeler][adversarial]") {
    // This simulates a malicious peer that:
    // 1. Accepts TCP connections (SYN-ACK)
    // 2. Never sends VERSION message
    // 3. Holds the connection open
    //
    // Expected behavior: Address should NOT be promoted to tried table
    // Current buggy behavior: Address IS promoted on TCP connect

    asio::io_context io;
    PeerLifecycleManager::Config cfg;
    PeerLifecycleManager plm(io, cfg);
    PeerDiscoveryManager pdm(&plm);

    // Seed address - use routable IP (93.184.216.x = example.com range)
    auto addr = MakeAddr("93.184.216.100", protocol::ports::REGTEST);
    REQUIRE(pdm.addr_manager_for_test().add(addr));

    size_t tried_before = pdm.TriedCount();

    auto transport = std::make_shared<AdversarialTransport>(io);
    transport->SetNextConnectResult(true);

    auto is_running = [](){ return true; };
    auto get_transport = [transport](){ return std::static_pointer_cast<Transport>(transport); };
    auto setup_handler = [](Peer*){};

    plm.AttemptFeelerConnection(is_running, get_transport, setup_handler,
                                protocol::magic::REGTEST, /*height=*/0, /*nonce=*/12345);
    io.poll();

    // Feeler peer exists but handshake never completes
    REQUIRE(plm.peer_count() == 1);

    // Simulate time passing (but no VERACK arrives)
    // In real code, the feeler would timeout after FEELER_MAX_LIFETIME_SEC

    size_t tried_after = pdm.TriedCount();

    // BUG: Address was promoted to tried table WITHOUT completing handshake
    // This allows attackers to pollute the tried table with addresses that
    // don't actually speak the protocol
    INFO("tried_before=" << tried_before << " tried_after=" << tried_after);
    CHECK(tried_after == tried_before);  // FAILS: proves the bug
}

TEST_CASE("Multiple failed feelers should trigger address backoff", "[network][feeler][adversarial]") {
    // If we fail to connect to an address multiple times via feeler,
    // it should be marked as bad and get exponential backoff

    asio::io_context io;
    PeerLifecycleManager::Config cfg;
    PeerLifecycleManager plm(io, cfg);
    PeerDiscoveryManager pdm(&plm);

    // Seed addresses - use routable IPs (93.184.216.x = example.com range)
    auto transport = std::make_shared<AdversarialTransport>(io);
    transport->SetNextConnectResult(false);  // All attempts will fail

    auto is_running = [](){ return true; };
    auto get_transport = [transport](){ return std::static_pointer_cast<Transport>(transport); };
    auto setup_handler = [](Peer*){};

    // Attempt multiple feelers - use different addresses to avoid dedup
    // Each one fails, testing that failures are properly tracked
    for (int i = 0; i < 5; i++) {
        auto addr_i = MakeAddr("93.184.216." + std::to_string(200 + i), protocol::ports::REGTEST);
        pdm.addr_manager_for_test().add(addr_i);
        plm.AttemptFeelerConnection(is_running, get_transport, setup_handler,
                                    protocol::magic::REGTEST, /*height=*/0, /*nonce=*/12345 + i);
        io.poll();
        io.restart();
    }

    // All attempts should have failed
    REQUIRE(plm.peer_count() == 0);
    CHECK(plm.GetFeelerFailures() >= 5);

    // With proper Failed() calls, the address would have accumulated
    // failure count and backoff. Current buggy Attempt() calls don't
    // properly track failures for backoff purposes.
}

TEST_CASE("Feeler timeout without VERACK should not mark address good", "[network][feeler][adversarial]") {
    // This tests the scenario where a feeler connects at TCP level,
    // peer sends VERSION but never VERACK, and the feeler times out.
    // The address should NOT be promoted to tried table.

    asio::io_context io;
    PeerLifecycleManager::Config cfg;
    PeerLifecycleManager plm(io, cfg);
    PeerDiscoveryManager pdm(&plm);

    // Use short timeouts for test
    using unicity::network::Peer;
    Peer::SetTimeoutsForTest(std::chrono::milliseconds(50), std::chrono::milliseconds(100));
    struct ResetTimeoutsGuard { ~ResetTimeoutsGuard() { Peer::ResetTimeoutsForTest(); } } _guard;

    // Seed address
    auto addr = MakeAddr("93.184.216.150", protocol::ports::REGTEST);
    REQUIRE(pdm.addr_manager_for_test().add(addr));

    size_t tried_before = pdm.TriedCount();

    auto transport = std::make_shared<AdversarialTransport>(io);
    transport->SetNextConnectResult(true);  // TCP succeeds

    auto is_running = [](){ return true; };
    auto get_transport = [transport](){ return std::static_pointer_cast<Transport>(transport); };
    auto setup_handler = [](Peer*){};

    // Start feeler
    plm.AttemptFeelerConnection(is_running, get_transport, setup_handler,
                                protocol::magic::REGTEST, /*height=*/0, /*nonce=*/12345);
    io.poll();

    // Feeler peer should be created
    REQUIRE(plm.peer_count() == 1);

    // At this point, TCP connected but VERACK hasn't happened
    // Address should NOT be in tried table yet
    size_t tried_after_connect = pdm.TriedCount();
    CHECK(tried_after_connect == tried_before);  // No premature promotion

    // Simulate handshake timeout by running io_context
    // The peer will timeout and be removed
    for (int i = 0; i < 10; i++) {
        io.run_for(std::chrono::milliseconds(50));
        plm.process_periodic();
    }

    // After timeout, peer should be removed
    // Address should still NOT be in tried table (VERACK never happened)
    size_t tried_after_timeout = pdm.TriedCount();
    CHECK(tried_after_timeout == tried_before);
}

TEST_CASE("Feeler success increments metrics only after VERACK", "[network][feeler][adversarial]") {
    // Verify that feeler success metrics are only incremented after VERACK,
    // not on TCP connect

    asio::io_context io;
    PeerLifecycleManager::Config cfg;
    PeerLifecycleManager plm(io, cfg);
    PeerDiscoveryManager pdm(&plm);

    // Seed address
    auto addr = MakeAddr("93.184.216.160", protocol::ports::REGTEST);
    REQUIRE(pdm.addr_manager_for_test().add(addr));

    uint64_t successes_before = plm.GetFeelerSuccesses();

    auto transport = std::make_shared<AdversarialTransport>(io);
    transport->SetNextConnectResult(true);

    auto is_running = [](){ return true; };
    auto get_transport = [transport](){ return std::static_pointer_cast<Transport>(transport); };
    auto setup_handler = [](Peer*){};

    plm.AttemptFeelerConnection(is_running, get_transport, setup_handler,
                                protocol::magic::REGTEST, /*height=*/0, /*nonce=*/12345);
    io.poll();

    // Peer created but VERACK not received
    REQUIRE(plm.peer_count() == 1);

    // Success should NOT be incremented yet (only incremented after VERACK)
    uint64_t successes_after_connect = plm.GetFeelerSuccesses();
    CHECK(successes_after_connect == successes_before);

    // Note: To fully test this, we'd need to simulate VERACK and verify
    // the success counter increments. That requires more infrastructure.
}
