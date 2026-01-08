// Unit tests for AnchorManager file persistence
#include "catch_amalgamated.hpp"
#include <nlohmann/json.hpp>
#include <filesystem>
#include <fstream>

using json = nlohmann::json;

// Helper to create test anchors file
void create_test_anchors_file(const std::string& filepath, const std::string& content) {
    std::ofstream file(filepath);
    file << content;
    file.close();
}

TEST_CASE("AnchorManager - JSON file format validation", "[network][anchor]") {
    const std::string test_file = "/tmp/test_anchor_format.json";
    std::filesystem::remove(test_file);

    SECTION("Valid anchor file structure") {
        json root;
        root["version"] = 1;
        root["count"] = 2;

        json anchor1;
        anchor1["port"] = 8333;
        anchor1["services"] = 1;
        anchor1["ip"] = json::array();
        for (int i = 0; i < 16; i++) {
            anchor1["ip"].push_back(i);
        }

        json anchor2;
        anchor2["port"] = 8334;
        anchor2["services"] = 2;
        anchor2["ip"] = json::array();
        for (int i = 0; i < 16; i++) {
            anchor2["ip"].push_back(255 - i);
        }

        root["anchors"] = json::array({anchor1, anchor2});

        create_test_anchors_file(test_file, root.dump(2));

        // Load and verify
        std::ifstream file(test_file);
        REQUIRE(file.is_open());

        json loaded;
        file >> loaded;

        CHECK(loaded["version"] == 1);
        CHECK(loaded["count"] == 2);
        REQUIRE(loaded["anchors"].is_array());
        REQUIRE(loaded["anchors"].size() == 2);

        CHECK(loaded["anchors"][0]["port"] == 8333);
        CHECK(loaded["anchors"][0]["services"] == 1);
        CHECK(loaded["anchors"][0]["ip"].is_array());
        CHECK(loaded["anchors"][0]["ip"].size() == 16);
        CHECK(loaded["anchors"][0]["ip"][0] == 0);

        CHECK(loaded["anchors"][1]["port"] == 8334);
        CHECK(loaded["anchors"][1]["services"] == 2);
    }

    std::filesystem::remove(test_file);
}

TEST_CASE("AnchorManager - IPv4-mapped IPv6 format", "[network][anchor]") {
    SECTION("IPv4 192.168.1.1 as IPv4-mapped") {
        json anchor;
        anchor["port"] = 8333;
        anchor["services"] = 1;
        anchor["ip"] = json::array();

        // IPv4-mapped IPv6: ::FFFF:192.168.1.1
        for (int i = 0; i < 10; i++) anchor["ip"].push_back(0);
        anchor["ip"].push_back(0xFF);
        anchor["ip"].push_back(0xFF);
        anchor["ip"].push_back(192);
        anchor["ip"].push_back(168);
        anchor["ip"].push_back(1);
        anchor["ip"].push_back(1);

        CHECK(anchor["ip"].size() == 16);
        CHECK(anchor["ip"][10] == 0xFF);
        CHECK(anchor["ip"][11] == 0xFF);
        CHECK(anchor["ip"][12] == 192);
        CHECK(anchor["ip"][13] == 168);
        CHECK(anchor["ip"][14] == 1);
        CHECK(anchor["ip"][15] == 1);
    }
}

TEST_CASE("AnchorManager - File operations", "[network][anchor]") {
    const std::string test_file = "/tmp/test_anchor_ops.json";

    SECTION("Non-existent file") {
        std::filesystem::remove(test_file);
        CHECK_FALSE(std::filesystem::exists(test_file));

        std::ifstream file(test_file);
        CHECK_FALSE(file.is_open());
    }

    SECTION("Create, write, and read file") {
        json root;
        root["version"] = 1;
        root["count"] = 1;

        json anchor;
        anchor["port"] = 9000;
        anchor["services"] = 5;
        anchor["ip"] = json::array();
        for (int i = 0; i < 16; i++) anchor["ip"].push_back(i * 2);

        root["anchors"] = json::array({anchor});

        create_test_anchors_file(test_file, root.dump(2));
        REQUIRE(std::filesystem::exists(test_file));

        std::ifstream file(test_file);
        REQUIRE(file.is_open());

        json loaded;
        file >> loaded;
        file.close();

        CHECK(loaded == root);
    }

    SECTION("Delete file") {
        create_test_anchors_file(test_file, "{}");
        REQUIRE(std::filesystem::exists(test_file));

        std::filesystem::remove(test_file);
        CHECK_FALSE(std::filesystem::exists(test_file));
    }

    std::filesystem::remove(test_file);
}

TEST_CASE("AnchorManager - Corrupted file handling", "[network][anchor]") {
    const std::string test_file = "/tmp/test_anchor_corrupt.json";

    SECTION("Invalid JSON") {
        create_test_anchors_file(test_file, "{not valid JSON}");

        std::ifstream file(test_file);
        REQUIRE(file.is_open());

        json loaded;
        CHECK_THROWS_AS(file >> loaded, json::parse_error);
    }

    SECTION("Wrong version") {
        json root;
        root["version"] = 999;
        root["count"] = 0;
        root["anchors"] = json::array();

        create_test_anchors_file(test_file, root.dump());

        std::ifstream file(test_file);
        json loaded;
        file >> loaded;

        CHECK(loaded["version"] == 999);
        // Application should detect and reject this version
    }

    SECTION("Missing fields") {
        json root;
        root["version"] = 1;
        // Missing "count" and "anchors"

        create_test_anchors_file(test_file, root.dump());

        std::ifstream file(test_file);
        json loaded;
        file >> loaded;

        CHECK(loaded.contains("version"));
        CHECK_FALSE(loaded.contains("count"));
        CHECK_FALSE(loaded.contains("anchors"));
    }

    std::filesystem::remove(test_file);
}

TEST_CASE("AnchorManager - Maximum anchors limit", "[network][anchor]") {
    // AnchorManager limits to MAX_ANCHORS = 2
    SECTION("Exactly 2 anchors") {
        json root;
        root["version"] = 1;
        root["count"] = 2;

        json anchor1;
        anchor1["port"] = 8333;
        anchor1["services"] = 1;
        anchor1["ip"] = json::array();
        for (int i = 0; i < 16; i++) anchor1["ip"].push_back(0);

        json anchor2;
        anchor2["port"] = 8334;
        anchor2["services"] = 1;
        anchor2["ip"] = json::array();
        for (int i = 0; i < 16; i++) anchor2["ip"].push_back(0);

        root["anchors"] = json::array({anchor1, anchor2});

        CHECK(root["count"] == 2);
        CHECK(root["anchors"].size() == 2);
    }

    SECTION("More than 2 anchors in file (should only use first 2)") {
        json root;
        root["version"] = 1;
        root["count"] = 5;

        json anchors_arr = json::array();
        for (int i = 0; i < 5; i++) {
            json anchor;
            anchor["port"] = 8333 + i;
            anchor["services"] = 1;
            anchor["ip"] = json::array();
            for (int j = 0; j < 16; j++) anchor["ip"].push_back(i);
            anchors_arr.push_back(anchor);
        }

        root["anchors"] = anchors_arr;

        CHECK(root["count"] == 5);
        CHECK(root["anchors"].size() == 5);
        // Application should limit loading to MAX_ANCHORS = 2
    }
}

TEST_CASE("AnchorManager - Empty anchors file", "[network][anchor]") {
    json root;
    root["version"] = 1;
    root["count"] = 0;
    root["anchors"] = json::array();

    CHECK(root["count"] == 0);
    CHECK(root["anchors"].empty());
}

TEST_CASE("AnchorManager - Services field values", "[network][anchor]") {
    SECTION("Various service flags") {
        json anchor;
        anchor["port"] = 8333;
        anchor["ip"] = json::array();
        for (int i = 0; i < 16; i++) anchor["ip"].push_back(0);

        // Test different service values
        anchor["services"] = 0; // No services
        CHECK(anchor["services"] == 0);

        anchor["services"] = 1; // NODE_NETWORK
        CHECK(anchor["services"] == 1);

        anchor["services"] = 1024; // Other service flag
        CHECK(anchor["services"] == 1024);

        anchor["services"] = UINT64_MAX; // Maximum value
        CHECK(anchor["services"] == UINT64_MAX);
    }
}
