#include "catch_amalgamated.hpp"
#include "infra/simulated_network.hpp"
#include "infra/simulated_node.hpp"
#include "test_orchestrator.hpp"
#include <filesystem>
#include <fstream>
#include <nlohmann/json.hpp>

using namespace unicity;
using namespace unicity::test;
using json = nlohmann::json;

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

TEST_CASE("Anchors - Loaded anchors are whitelisted (NoBan)", "[network][anchor][whitelist]") {
    SimulatedNetwork net(999);
    TestOrchestrator orch(&net);

    SimulatedNode n1(1, &net);

    const std::string path = anchors_path("anchors_whitelist_test.json");
    std::filesystem::remove(path);

    // Write one anchor: 127.0.0.2
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

    // Load anchors; this should whitelist 127.0.0.2
    REQUIRE(n1.GetNetworkManager().LoadAnchors(path));

    // Give the system a moment to process callbacks
    orch.AdvanceTime(std::chrono::milliseconds(100));

    // Check that anchor address is whitelisted
    auto& bm = n1.GetNetworkManager().peer_manager();
    // 127.0.0.2 should be normal dotted-quad
    CHECK(bm.IsWhitelisted("127.0.0.2"));

    // Note: Like Bitcoin Core, whitelist and ban are independent states
    // Whitelisted addresses CAN be banned; whitelist only affects connection acceptance
    bm.Ban("127.0.0.2", 3600);
    CHECK(bm.IsBanned("127.0.0.2"));  // Ban succeeds
    CHECK(bm.IsWhitelisted("127.0.0.2"));  // Still whitelisted
}

// === ConnectToAnchors Unit Tests ===

TEST_CASE("ConnectToAnchors - empty vector does nothing", "[network][anchor][unit]") {
    SimulatedNetwork net(1001);
    TestOrchestrator orch(&net);
    SimulatedNode n1(1, &net);

    auto& peer_mgr = n1.GetNetworkManager().peer_manager();
    size_t initial_peer_count = peer_mgr.peer_count();

    // Call with empty vector
    std::vector<protocol::NetworkAddress> empty_anchors;
    bool connect_called = false;
    peer_mgr.ConnectToAnchors(empty_anchors, [&](const protocol::NetworkAddress&, network::ConnectionType) {
        connect_called = true;
        return network::ConnectionResult::Success;
    });

    // Connect callback should never be called
    CHECK_FALSE(connect_called);
    CHECK(peer_mgr.peer_count() == initial_peer_count);
}

TEST_CASE("ConnectToAnchors - whitelists addresses before connecting", "[network][anchor][unit]") {
    SimulatedNetwork net(1002);
    TestOrchestrator orch(&net);
    SimulatedNode n1(1, &net);

    auto& peer_mgr = n1.GetNetworkManager().peer_manager();

    // Create anchor address (93.184.216.34 - routable)
    protocol::NetworkAddress addr;
    addr.services = protocol::NODE_NETWORK;
    addr.port = protocol::ports::REGTEST;
    for (int i = 0; i < 10; ++i) addr.ip[i] = 0;
    addr.ip[10] = 0xFF; addr.ip[11] = 0xFF;
    addr.ip[12] = 93; addr.ip[13] = 184; addr.ip[14] = 216; addr.ip[15] = 34;

    std::vector<protocol::NetworkAddress> anchors = {addr};

    // Track if whitelist was set before connect callback
    bool whitelisted_before_connect = false;
    peer_mgr.ConnectToAnchors(anchors, [&](const protocol::NetworkAddress&, network::ConnectionType) {
        // Check whitelist status at the moment connect is called
        whitelisted_before_connect = peer_mgr.IsWhitelisted("93.184.216.34");
        return network::ConnectionResult::Success;
    });

    CHECK(whitelisted_before_connect);
    CHECK(peer_mgr.IsWhitelisted("93.184.216.34"));
}

TEST_CASE("ConnectToAnchors - uses BLOCK_RELAY connection type", "[network][anchor][unit]") {
    SimulatedNetwork net(1003);
    TestOrchestrator orch(&net);
    SimulatedNode n1(1, &net);

    auto& peer_mgr = n1.GetNetworkManager().peer_manager();

    // Create anchor address
    protocol::NetworkAddress addr;
    addr.services = protocol::NODE_NETWORK;
    addr.port = protocol::ports::REGTEST;
    for (int i = 0; i < 10; ++i) addr.ip[i] = 0;
    addr.ip[10] = 0xFF; addr.ip[11] = 0xFF;
    addr.ip[12] = 8; addr.ip[13] = 8; addr.ip[14] = 8; addr.ip[15] = 8;

    std::vector<protocol::NetworkAddress> anchors = {addr};

    network::ConnectionType received_type = network::ConnectionType::INBOUND;
    peer_mgr.ConnectToAnchors(anchors, [&](const protocol::NetworkAddress&, network::ConnectionType type) {
        received_type = type;
        return network::ConnectionResult::Success;
    });

    // Anchors should connect as BLOCK_RELAY for eclipse resistance
    CHECK(received_type == network::ConnectionType::BLOCK_RELAY);
}

TEST_CASE("ConnectToAnchors - handles multiple anchors", "[network][anchor][unit]") {
    SimulatedNetwork net(1004);
    TestOrchestrator orch(&net);
    SimulatedNode n1(1, &net);

    auto& peer_mgr = n1.GetNetworkManager().peer_manager();

    // Create two anchor addresses
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

    int connect_count = 0;
    peer_mgr.ConnectToAnchors(anchors, [&](const protocol::NetworkAddress&, network::ConnectionType) {
        ++connect_count;
        return network::ConnectionResult::Success;
    });

    // Should attempt to connect to both anchors
    CHECK(connect_count == 2);
    CHECK(peer_mgr.IsWhitelisted("10.0.0.1"));
    CHECK(peer_mgr.IsWhitelisted("10.0.0.2"));
}

TEST_CASE("ConnectToAnchors - continues on connection failure", "[network][anchor][unit]") {
    SimulatedNetwork net(1005);
    TestOrchestrator orch(&net);
    SimulatedNode n1(1, &net);

    auto& peer_mgr = n1.GetNetworkManager().peer_manager();

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

    int connect_count = 0;
    peer_mgr.ConnectToAnchors(anchors, [&](const protocol::NetworkAddress&, network::ConnectionType) -> network::ConnectionResult {
        ++connect_count;
        // First connection fails, second succeeds
        if (connect_count == 1) {
            return network::ConnectionResult::TransportFailed;
        }
        return network::ConnectionResult::Success;
    });

    // Should attempt both connections even if first fails
    CHECK(connect_count == 2);
}
