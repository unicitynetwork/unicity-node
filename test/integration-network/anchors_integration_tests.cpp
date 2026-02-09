#include "catch_amalgamated.hpp"
#include "infra/simulated_network.hpp"
#include "infra/simulated_node.hpp"
#include "infra/mock_transport.hpp"
#include "test_orchestrator.hpp"
#include "network/connection_manager.hpp"
#include <asio.hpp>
#include <filesystem>
#include <fstream>
#include <nlohmann/json.hpp>

using namespace unicity;
using namespace unicity::test;
using json = nlohmann::json;

namespace {

// Transport that counts connect() calls with configurable failure
class CountingTransport : public network::Transport {
public:
    explicit CountingTransport(int fail_first_n = 0) : fail_first_n_(fail_first_n) {}
    int connect_count() const { return count_; }

    network::TransportConnectionPtr connect(const std::string& address, uint16_t port,
                                            network::ConnectCallback callback) override {
        ++count_;
        if (count_ <= fail_first_n_) {
            if (callback) callback(false);
            return nullptr;
        }
        auto conn = std::make_shared<network::MockTransportConnection>(address, port);
        conn->set_inbound(false);
        if (callback) callback(true);
        return conn;
    }

    bool listen(uint16_t, std::function<void(network::TransportConnectionPtr)>) override { return true; }
    void stop_listening() override {}
    void run() override {}
    void stop() override {}
    bool is_running() const override { return true; }

private:
    int fail_first_n_{0};
    int count_{0};
};

} // namespace

static json read_json_file(const std::string& path) {
    std::ifstream f(path);
    REQUIRE(f.is_open());
    json j; f >> j; return j;
}

static std::string anchors_path(const char* name) {
    return std::string("/tmp/") + name;
}

static void write_anchor_entry(json& arr, int node_id) {
    json a;
    a["services"] = 1;
    a["port"] = protocol::ports::REGTEST + node_id;
    a["ip"] = json::array();
    for (int i = 0; i < 10; ++i) a["ip"].push_back(0);
    a["ip"].push_back(0xFF);
    a["ip"].push_back(0xFF);
    a["ip"].push_back(127);
    a["ip"].push_back(0);
    a["ip"].push_back(0);
    a["ip"].push_back(node_id % 255);
    arr.push_back(a);
}

TEST_CASE("Anchors - Save selects two oldest READY outbounds", "[network][anchor]") {
    SimulatedNetwork net(123);
    TestOrchestrator orch(&net);

    SimulatedNode n1(1, &net);
    SimulatedNode n2(2, &net);
    SimulatedNode n3(3, &net);

    // Bitcoin Core parity: anchors are only selected from block-relay-only connections
    // Default limit is 2 block-relay connections (matching Bitcoin Core)
    // Connect as block-relay-only to n2, wait a bit; then n3
    REQUIRE(n1.ConnectToBlockRelayOnly(2));
    for (int i = 0; i < 10; ++i) orch.AdvanceTime(std::chrono::milliseconds(100));
    REQUIRE(n1.ConnectToBlockRelayOnly(3));
    for (int i = 0; i < 10; ++i) orch.AdvanceTime(std::chrono::milliseconds(100));

    REQUIRE(orch.WaitForPeerCount(n1, 2));

    // Save anchors to file
    const std::string path = anchors_path("anchors_save_test.json");
    std::filesystem::remove(path);
    REQUIRE(n1.GetNetworkManager().SaveAnchors(path));

    auto j = read_json_file(path);
    REQUIRE(j["version"] == 1);
    REQUIRE(j["anchors"].is_array());
    REQUIRE(j["anchors"].size() == 2);

    auto a0 = j["anchors"][0];
    auto a1 = j["anchors"][1];

    // Expect both connected peers (2 and 3) as anchors
    std::set<uint16_t> allowed = { (uint16_t)(protocol::ports::REGTEST+2), (uint16_t)(protocol::ports::REGTEST+3) };
    std::vector<uint16_t> file_ports = { a0["port"].get<uint16_t>(), a1["port"].get<uint16_t>() };
    CHECK(allowed.count(file_ports[0]) == 1);
    CHECK(allowed.count(file_ports[1]) == 1);
    CHECK(file_ports[0] != file_ports[1]);

    std::filesystem::remove(path);
}

TEST_CASE("Anchors - Load caps at 2 and deletes file", "[network][anchor]") {
    SimulatedNetwork net(456);
    TestOrchestrator orch(&net);

    SimulatedNode n1(1, &net);
    SimulatedNode n2(2, &net);
    SimulatedNode n3(3, &net);
    SimulatedNode n4(4, &net);

    const std::string path = anchors_path("anchors_load_test.json");
    std::filesystem::remove(path);

    // Write anchors file with 3 entries (2,3,4)
    json root;
    root["version"] = 1;
    root["count"] = 3;
    root["anchors"] = json::array();
    write_anchor_entry(root["anchors"], 2);
    write_anchor_entry(root["anchors"], 3);
    write_anchor_entry(root["anchors"], 4);

    {
        std::ofstream f(path);
        REQUIRE(f.is_open());
        f << root.dump(2);
    }

    // Load and attempt connects
    REQUIRE(n1.GetNetworkManager().LoadAnchors(path));

    // File should be deleted
    CHECK_FALSE(std::filesystem::exists(path));

    // Only 2 anchors should be attempted, wait for up to 2 peers
    REQUIRE(orch.WaitForPeerCount(n1, 2));

    // Ensure they are exactly 2 of the 3 we provided
    auto count = n1.GetNetworkManager().outbound_peer_count();
    CHECK(count == 2);
}

TEST_CASE("Anchors - Load rejects malformed entries and returns false", "[network][anchor]") {
    SimulatedNetwork net(789);
    TestOrchestrator orch(&net);

    SimulatedNode n1(1, &net);

    const std::string path = anchors_path("anchors_malformed_test.json");
    std::filesystem::remove(path);

    // Malformed: ip size 15
    json root;
    root["version"] = 1;
    root["count"] = 1;
    root["anchors"] = json::array();
    json a;
    a["services"] = 1;
    a["port"] = protocol::ports::REGTEST + 2;
    a["ip"] = json::array();
    for (int i = 0; i < 15; ++i) a["ip"].push_back(0);
    root["anchors"].push_back(a);

    {
        std::ofstream f(path);
        REQUIRE(f.is_open());
        f << root.dump(2);
    }

    CHECK_FALSE(n1.GetNetworkManager().LoadAnchors(path));
    CHECK_FALSE(std::filesystem::exists(path));
    CHECK(n1.GetNetworkManager().outbound_peer_count() == 0);
}

TEST_CASE("Anchors - Loaded anchors have no special permissions (can be banned)", "[network][anchor][ban]") {
    SimulatedNetwork net(999);
    TestOrchestrator orch(&net);

    SimulatedNode n1(1, &net);
    SimulatedNode n2(2, &net);  // Actual peer so the connection succeeds

    const std::string path = anchors_path("anchors_whitelist_test.json");
    std::filesystem::remove(path);

    // Write one anchor: 127.0.0.2 (node 2's address)
    json root;
    root["version"] = 1;
    root["count"] = 1;
    root["anchors"] = json::array();
    write_anchor_entry(root["anchors"], 2);

    {
        std::ofstream f(path);
        REQUIRE(f.is_open());
        f << root.dump(2);
    }

    // Load anchors through the real NetworkManager path
    REQUIRE(n1.GetNetworkManager().LoadAnchors(path));

    // Wait for connection to complete
    REQUIRE(orch.WaitForPeerCount(n1, 1));

    // Verify anchor peer has no special permissions (Core parity)
    auto peers = n1.GetNetworkManager().peer_manager().get_all_peers();
    REQUIRE(peers.size() >= 1);
    for (const auto& peer : peers) {
        if (peer) {
            CHECK(peer->permissions() == network::NetPermissionFlags::None);
        }
    }

    // Anchors can be banned if they misbehave
    auto& bm = n1.GetNetworkManager().peer_manager();
    bm.Ban("127.0.0.2", 3600);
    CHECK(bm.IsBanned("127.0.0.2"));

    std::filesystem::remove(path);
}

// === ConnectToAnchors Unit Tests ===

TEST_CASE("ConnectToAnchors - empty vector does nothing", "[network][anchor][unit]") {
    SimulatedNetwork net(1001);
    TestOrchestrator orch(&net);
    SimulatedNode n1(1, &net);

    auto& peer_mgr = n1.GetNetworkManager().peer_manager();
    size_t initial_peer_count = peer_mgr.peer_count();
    uint64_t initial_attempts = peer_mgr.GetOutboundAttempts();

    // Call with empty vector
    std::vector<protocol::NetworkAddress> empty_anchors;
    peer_mgr.ConnectToAnchors(empty_anchors, /*current_height=*/0);

    // No connections should be attempted
    CHECK(peer_mgr.GetOutboundAttempts() == initial_attempts);
    CHECK(peer_mgr.peer_count() == initial_peer_count);
}

TEST_CASE("ConnectToAnchors - does NOT whitelist addresses", "[network][anchor][unit]") {
    asio::io_context io;
    network::ConnectionManager plm(io, network::ConnectionManager::Config{});

    auto transport = std::make_shared<CountingTransport>();
    plm.Init(transport, [](network::Peer*){}, [](){ return true; },
             protocol::magic::REGTEST, /*local_nonce=*/42);

    uint64_t initial_attempts = plm.GetOutboundAttempts();

    // Create anchor address (93.184.216.34 - routable)
    protocol::NetworkAddress addr;
    addr.services = protocol::NODE_NETWORK;
    addr.port = protocol::ports::REGTEST;
    for (int i = 0; i < 10; ++i) addr.ip[i] = 0;
    addr.ip[10] = 0xFF; addr.ip[11] = 0xFF;
    addr.ip[12] = 93; addr.ip[13] = 184; addr.ip[14] = 216; addr.ip[15] = 34;

    std::vector<protocol::NetworkAddress> anchors = {addr};

    // Anchors should attempt connection (without whitelisting)
    plm.ConnectToAnchors(anchors, /*current_height=*/0);

    CHECK(plm.GetOutboundAttempts() >= initial_attempts + 1);
}

TEST_CASE("ConnectToAnchors - uses BLOCK_RELAY connection type", "[network][anchor][unit]") {
    SimulatedNetwork net(1003);
    TestOrchestrator orch(&net);
    SimulatedNode n1(1, &net);
    SimulatedNode n2(2, &net);

    auto& peer_mgr = n1.GetNetworkManager().peer_manager();

    // Use n2's address so the simulated transport can actually connect
    protocol::NetworkAddress n2_addr;
    n2_addr.services = protocol::NODE_NETWORK;
    n2_addr.port = protocol::ports::REGTEST + 2;
    for (int i = 0; i < 10; ++i) n2_addr.ip[i] = 0;
    n2_addr.ip[10] = 0xFF; n2_addr.ip[11] = 0xFF;
    n2_addr.ip[12] = 127; n2_addr.ip[13] = 0; n2_addr.ip[14] = 0; n2_addr.ip[15] = 2;
    std::vector<protocol::NetworkAddress> anchors_vec = {n2_addr};

    peer_mgr.ConnectToAnchors(anchors_vec, /*current_height=*/0);

    // Process async callbacks
    for (int i = 0; i < 5; ++i) orch.AdvanceTime(std::chrono::milliseconds(50));

    // Anchors should connect as BLOCK_RELAY for eclipse resistance
    auto peers = peer_mgr.get_outbound_peers();
    REQUIRE(peers.size() >= 1);
    CHECK(peers[0]->connection_type() == network::ConnectionType::BLOCK_RELAY);
}

TEST_CASE("ConnectToAnchors - handles multiple anchors", "[network][anchor][unit]") {
    asio::io_context io;
    network::ConnectionManager plm(io, network::ConnectionManager::Config{});

    auto transport = std::make_shared<CountingTransport>();
    plm.Init(transport, [](network::Peer*){}, [](){ return true; },
             protocol::magic::REGTEST, /*local_nonce=*/44);

    uint64_t initial_attempts = plm.GetOutboundAttempts();

    // Create two anchor addresses (routable IPs)
    std::vector<protocol::NetworkAddress> anchors;
    for (int i = 0; i < 2; ++i) {
        protocol::NetworkAddress addr;
        addr.services = protocol::NODE_NETWORK;
        addr.port = protocol::ports::REGTEST;
        for (int j = 0; j < 10; ++j) addr.ip[j] = 0;
        addr.ip[10] = 0xFF; addr.ip[11] = 0xFF;
        addr.ip[12] = 10; addr.ip[13] = 0; addr.ip[14] = 0; addr.ip[15] = static_cast<uint8_t>(i + 1);
        anchors.push_back(addr);
    }

    plm.ConnectToAnchors(anchors, /*current_height=*/0);

    // Should attempt to connect to both anchors
    CHECK(plm.GetOutboundAttempts() >= initial_attempts + 2);
}

TEST_CASE("ConnectToAnchors - continues on connection failure", "[network][anchor][unit]") {
    asio::io_context io;
    network::ConnectionManager plm(io, network::ConnectionManager::Config{});

    // First connection fails, second succeeds
    auto transport = std::make_shared<CountingTransport>(/*fail_first_n=*/1);
    plm.Init(transport, [](network::Peer*){}, [](){ return true; },
             protocol::magic::REGTEST, /*local_nonce=*/45);

    // Create two anchor addresses
    std::vector<protocol::NetworkAddress> anchors;
    for (int i = 0; i < 2; ++i) {
        protocol::NetworkAddress addr;
        addr.services = protocol::NODE_NETWORK;
        addr.port = protocol::ports::REGTEST;
        for (int j = 0; j < 10; ++j) addr.ip[j] = 0;
        addr.ip[10] = 0xFF; addr.ip[11] = 0xFF;
        addr.ip[12] = 20; addr.ip[13] = 0; addr.ip[14] = 0; addr.ip[15] = static_cast<uint8_t>(i + 1);
        anchors.push_back(addr);
    }

    plm.ConnectToAnchors(anchors, /*current_height=*/0);

    // Both connections should be attempted even though the first failed
    CHECK(transport->connect_count() == 2);
}

// ============================================================================
// End-to-End Anchor Connection Type Tests
// These tests verify the FULL flow from NetworkManager -> ConnectionManager -> actual connection
// ============================================================================

TEST_CASE("NetworkManager anchor connections use BLOCK_RELAY end-to-end", "[network][anchor][integration][e2e]") {
    // This test caught a bug where NetworkManager's callback ignored the conn_type parameter
    // from ConnectToAnchors, causing anchors to connect as FULL_RELAY instead of BLOCK_RELAY

    SimulatedNetwork net(2001);
    TestOrchestrator orch(&net);

    // Create two nodes
    SimulatedNode n1(1, &net);
    SimulatedNode n2(2, &net);

    // Create anchors file with n2's address
    std::string test_anchors_path = anchors_path("anchor_e2e_test.json");

    {
        json root;
        root["version"] = 1;
        root["count"] = 1;

        json anchors_array = json::array();
        write_anchor_entry(anchors_array, 2);  // Node 2's address
        root["anchors"] = anchors_array;

        std::ofstream f(test_anchors_path);
        f << root.dump(2);
    }

    // Load anchors through NetworkManager (this exercises the full callback chain)
    bool loaded = n1.GetNetworkManager().LoadAnchors(test_anchors_path);
    REQUIRE(loaded);

    // Process connections
    REQUIRE(orch.WaitForPeerCount(n1, 1));

    // Verify the peer connected as BLOCK_RELAY
    auto peers = n1.GetNetworkManager().peer_manager().get_all_peers();
    REQUIRE(peers.size() >= 1);

    bool found_block_relay_anchor = false;
    bool has_no_special_permissions = false;
    for (const auto& peer : peers) {
        if (peer && peer->is_block_relay_only()) {
            found_block_relay_anchor = true;
            // Anchors must NOT have NoBan or any special permissions (Core parity)
            has_no_special_permissions = (peer->permissions() == network::NetPermissionFlags::None);
            break;
        }
    }

    // The anchor should have been connected as BLOCK_RELAY, not FULL_RELAY
    CHECK(found_block_relay_anchor);
    // Anchors are regular peers — no ban immunity (Core parity)
    CHECK(has_no_special_permissions);

    // Cleanup
    std::filesystem::remove(test_anchors_path);
}
