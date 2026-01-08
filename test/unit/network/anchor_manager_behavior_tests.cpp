#include "catch_amalgamated.hpp"
#include "network/anchor_manager.hpp"
#include "network/peer_lifecycle_manager.hpp"
#include "network/protocol.hpp"
#include <asio.hpp>
#include <filesystem>
#include <fstream>
#include <nlohmann/json.hpp>

using namespace unicity;
using namespace unicity::network;
using json = nlohmann::json;

static std::string tmpfile(const char* name) { return std::string("/tmp/") + name; }

TEST_CASE("AnchorManager::SaveAnchors - no peers -> early return, no file", "[unit][anchor]") {
    asio::io_context io;
    PeerLifecycleManager peermgr(io);

    // Phase 2: No callbacks - AnchorManager is passive
    AnchorManager am(peermgr);

    const std::string path = tmpfile("am_save_none.json");
    std::filesystem::remove(path);

    CHECK(am.SaveAnchors(path));
    CHECK_FALSE(std::filesystem::exists(path));
}

TEST_CASE("AnchorManager::LoadAnchors - returns capped at 2 addresses and deletes file", "[unit][anchor]") {
    asio::io_context io;
    PeerLifecycleManager peermgr(io);

    // Phase 2: No callbacks - LoadAnchors returns vector of addresses
    AnchorManager am(peermgr);

    const std::string path = tmpfile("am_load_caps.json");
    std::filesystem::remove(path);

    json root; root["version"] = 1; root["count"] = 3; root["anchors"] = json::array();
    auto add = [&](int node_id){
        json j; j["services"] = 1; j["port"] = protocol::ports::REGTEST + node_id; j["ip"] = json::array();
        for (int i=0;i<10;++i) j["ip"].push_back(0);
        j["ip"].push_back(0xFF); j["ip"].push_back(0xFF);
        j["ip"].push_back(127); j["ip"].push_back(0); j["ip"].push_back(0); j["ip"].push_back(node_id % 255);
        root["anchors"].push_back(j);
    };
    add(2); add(3); add(4);
    {
        std::ofstream f(path);
        REQUIRE(f.is_open());
        f << root.dump(2);
    }

    // Phase 2: LoadAnchors returns vector of addresses (capped at 2)
    auto addresses = am.LoadAnchors(path);
    CHECK(addresses.size() == 2);
    CHECK_FALSE(std::filesystem::exists(path));
}

TEST_CASE("AnchorManager::LoadAnchors - invalid IP array -> reject and delete", "[unit][anchor]") {
    asio::io_context io;
    PeerLifecycleManager peermgr(io);

    // Phase 2: No callbacks
    AnchorManager am(peermgr);

    const std::string path = tmpfile("am_load_invalid.json");
    std::filesystem::remove(path);

    json root; root["version"] = 1; root["count"] = 1; root["anchors"] = json::array();
    json a; a["services"] = 1; a["port"] = protocol::ports::REGTEST + 2; a["ip"] = json::array();
    for (int i=0;i<15;++i) a["ip"].push_back(0); // invalid size
    root["anchors"].push_back(a);
    {
        std::ofstream f(path); REQUIRE(f.is_open()); f << root.dump(2);
    }

    // Phase 2: LoadAnchors returns empty vector for invalid data
    auto addresses = am.LoadAnchors(path);
    CHECK(addresses.empty());
    CHECK_FALSE(std::filesystem::exists(path));
}
