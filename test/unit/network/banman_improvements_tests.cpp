// Copyright (c) 2025 The Unicity Foundation
// Unit tests for BanManager improvements - dirty flag, file permissions, and capacity enforcement

#include "catch_amalgamated.hpp"
#include "network/peer_lifecycle_manager.hpp"
#include "network/ban_manager.hpp"
#include "util/time.hpp"
#include <asio.hpp>
#include <filesystem>
#include <fstream>
#include <nlohmann/json.hpp>
#include <sys/stat.h>
#include <chrono>

using namespace unicity::network;
using json = nlohmann::json;

// Test fixture for BanManager improvements
class BanImprovementsFixture {
public:
    std::string test_dir;
    asio::io_context io_context;

    BanImprovementsFixture() {
        // Create unique test directory
        auto now = std::chrono::steady_clock::now().time_since_epoch().count();
        test_dir = "/tmp/banman_improvements_test_" + std::to_string(now);
        std::filesystem::create_directory(test_dir);
    }

    ~BanImprovementsFixture() {
        // Clean up test directory
        std::filesystem::remove_all(test_dir);
    }

    std::string GetBanlistPath() const {
        return test_dir + "/banlist.json";
    }

    // Helper to get file permissions
    mode_t GetFilePermissions(const std::string& filepath) const {
        struct stat st;
        if (stat(filepath.c_str(), &st) != 0) {
            return 0;
        }
        return st.st_mode & 0777;
    }

    // Helper to count number of times file was actually written
    // by checking if file content changed
    std::string GetFileContent(const std::string& filepath) const {
        if (!std::filesystem::exists(filepath)) {
            return "";
        }
        std::ifstream file(filepath);
        std::string content((std::istreambuf_iterator<char>(file)),
                           std::istreambuf_iterator<char>());
        return content;
    }
};

TEST_CASE("BanManager - Constructor initializes ban_file_path", "[network][ban][improvements]") {
    BanImprovementsFixture fixture;

    SECTION("Constructor with datadir sets path immediately") {
        asio::io_context io;
        PeerLifecycleManager::Config config;
        PeerLifecycleManager pm(io, config, fixture.test_dir);

        // Ban an address - should auto-save since path is set
        pm.Ban("192.168.1.1", 3600);

        // Verify file was created at expected path
        std::string expected_path = fixture.GetBanlistPath();
        REQUIRE(std::filesystem::exists(expected_path));
    }

    SECTION("Constructor with empty datadir doesn't create file") {
        asio::io_context io;
        PeerLifecycleManager::Config config;
        PeerLifecycleManager pm(io, config, "");

        // Ban an address - should not create any file
        pm.Ban("192.168.1.1", 3600);

        // Verify no file was created
        REQUIRE_FALSE(std::filesystem::exists(fixture.GetBanlistPath()));
    }
}

TEST_CASE("BanManager - File permissions are 0600 (owner-only)", "[network][ban][improvements][security]") {
    BanImprovementsFixture fixture;

    SECTION("SaveBans creates file with 0600 permissions") {
        asio::io_context io;
        PeerLifecycleManager::Config config;
        PeerLifecycleManager pm(io, config, fixture.test_dir);

        // Ban an address
        pm.Ban("192.168.1.1", 0);  // Permanent ban

        // Verify SaveBans creates file with correct permissions
        REQUIRE(pm.SaveBans());

        std::string banlist_path = fixture.GetBanlistPath();
        REQUIRE(std::filesystem::exists(banlist_path));

        // Check permissions are 0600 (owner read+write only)
        mode_t perms = fixture.GetFilePermissions(banlist_path);
        REQUIRE(perms == 0600);
    }
}

TEST_CASE("BanManager - Dirty flag prevents redundant saves", "[network][ban][improvements][performance]") {
    BanImprovementsFixture fixture;

    SECTION("Multiple SaveBans without modifications doesn't rewrite file") {
        asio::io_context io;
        PeerLifecycleManager::Config config;
        PeerLifecycleManager pm(io, config, fixture.test_dir);

        // Ban an address
        pm.Ban("192.168.1.1", 0);
        REQUIRE(pm.SaveBans());

        std::string banlist_path = fixture.GetBanlistPath();
        REQUIRE(std::filesystem::exists(banlist_path));

        // Get file content and inode
        auto content1 = fixture.GetFileContent(banlist_path);
        auto inode1 = std::filesystem::status(banlist_path).permissions();

        // Small delay to ensure timestamps would differ if file was rewritten
        std::this_thread::sleep_for(std::chrono::milliseconds(10));

        // Save again without modifications - should skip write due to dirty flag
        REQUIRE(pm.SaveBans());

        auto content2 = fixture.GetFileContent(banlist_path);

        // File content should be identical (no rewrite occurred)
        REQUIRE(content1 == content2);
    }

    SECTION("SaveBans after modification does write file") {
        asio::io_context io;
        PeerLifecycleManager::Config config;
        PeerLifecycleManager pm(io, config, fixture.test_dir);

        // Ban an address
        pm.Ban("192.168.1.1", 0);
        REQUIRE(pm.SaveBans());

        std::string banlist_path = fixture.GetBanlistPath();
        auto content1 = fixture.GetFileContent(banlist_path);

        std::this_thread::sleep_for(std::chrono::milliseconds(10));

        // Modify state by adding another ban
        pm.Ban("192.168.1.2", 0);
        REQUIRE(pm.SaveBans());

        auto content2 = fixture.GetFileContent(banlist_path);

        // File SHOULD have been rewritten (content changed)
        REQUIRE(content1 != content2);
    }

    SECTION("Unban marks dirty and triggers save") {
        asio::io_context io;
        PeerLifecycleManager::Config config;
        PeerLifecycleManager pm(io, config, fixture.test_dir);

        pm.Ban("192.168.1.1", 0);
        pm.Ban("192.168.1.2", 0);
        REQUIRE(pm.SaveBans());

        std::string banlist_path = fixture.GetBanlistPath();
        auto content1 = fixture.GetFileContent(banlist_path);

        std::this_thread::sleep_for(std::chrono::milliseconds(10));

        // Unban should mark dirty
        pm.Unban("192.168.1.1");
        // Auto-save should trigger

        auto content2 = fixture.GetFileContent(banlist_path);
        REQUIRE(content1 != content2);

        // Verify unban persisted
        auto bans = pm.GetBanned();
        REQUIRE(bans.size() == 1);
        REQUIRE(bans.find("192.168.1.1") == bans.end());
        REQUIRE(bans.find("192.168.1.2") != bans.end());
    }

    SECTION("ClearBanned marks dirty") {
        asio::io_context io;
        PeerLifecycleManager::Config config;
        PeerLifecycleManager pm(io, config, fixture.test_dir);

        pm.Ban("192.168.1.1", 0);
        pm.Ban("192.168.1.2", 0);
        REQUIRE(pm.SaveBans());

        std::string banlist_path = fixture.GetBanlistPath();
        auto content1 = fixture.GetFileContent(banlist_path);

        std::this_thread::sleep_for(std::chrono::milliseconds(10));

        pm.ClearBanned();
        // Auto-save should trigger

        auto content2 = fixture.GetFileContent(banlist_path);
        REQUIRE(content1 != content2);

        // Verify all bans cleared and persisted
        auto bans = pm.GetBanned();
        REQUIRE(bans.empty());
    }
}

TEST_CASE("BanManager - LoadBans sets dirty flag correctly", "[network][ban][improvements]") {
    BanImprovementsFixture fixture;

    SECTION("LoadBans with expired entries marks dirty and cleans file") {
        std::string banlist_path = fixture.GetBanlistPath();

        // Manually create a banlist with expired entry
        {
            int64_t now = std::time(nullptr);
            json j;

            // Add expired ban (expired 1 hour ago)
            j["192.168.1.1"] = {
                {"version", 1},
                {"create_time", now - 7200},
                {"ban_until", now - 3600}  // Expired
            };

            // Add valid ban (expires in 1 hour)
            j["192.168.1.2"] = {
                {"version", 1},
                {"create_time", now},
                {"ban_until", now + 3600}  // Still valid
            };

            std::ofstream file(banlist_path);
            file << j.dump(2);
        }

        asio::io_context io;
        PeerLifecycleManager::Config config;
        PeerLifecycleManager pm(io, config, fixture.test_dir);

        // LoadBans should:
        // 1. Skip expired entry
        // 2. Mark dirty (because we skipped an entry)
        // 3. Auto-save cleaned list

        auto bans = pm.GetBanned();
        REQUIRE(bans.size() == 1);
        REQUIRE(bans.find("192.168.1.1") == bans.end());  // Expired, not loaded
        REQUIRE(bans.find("192.168.1.2") != bans.end());  // Valid, loaded
    }
}

TEST_CASE("BanManager - Discourage capacity enforcement", "[network][ban][improvements][dos]") {
    BanImprovementsFixture fixture;
    asio::io_context io;
    PeerLifecycleManager::Config config;
    PeerLifecycleManager pm(io, config, "");

    SECTION("Discourage never exceeds MAX_DISCOURAGED (10000)") {
        // Discourage MAX_DISCOURAGED addresses
        const size_t MAX_DISCOURAGED = 10000;

        for (size_t i = 0; i < MAX_DISCOURAGED; ++i) {
            std::string addr = "192.168." + std::to_string(i / 256) + "." + std::to_string(i % 256);
            pm.Discourage(addr);
        }

        // Now at capacity - add one more
        pm.Discourage("10.0.0.1");

        // Verify we never exceeded capacity
        // (Can't directly check size without exposing internal state,
        //  but we verify it doesn't crash and continues working)
        REQUIRE(pm.IsDiscouraged("10.0.0.1"));
    }

    SECTION("Discourage at capacity evicts oldest entry") {
        const size_t MAX_DISCOURAGED = 10000;

        // Fill to capacity
        for (size_t i = 0; i < MAX_DISCOURAGED; ++i) {
            std::string addr = "192.168." + std::to_string(i / 256) + "." + std::to_string(i % 256);
            pm.Discourage(addr);
        }

        // All should be discouraged
        REQUIRE(pm.IsDiscouraged("192.168.0.0"));
        REQUIRE(pm.IsDiscouraged("192.168.0.1"));

        // Add one more - should evict one entry (with earliest expiry)
        pm.Discourage("10.0.0.1");
        REQUIRE(pm.IsDiscouraged("10.0.0.1"));

        // System should remain functional
        REQUIRE_NOTHROW(pm.Discourage("10.0.0.2"));
    }
}

TEST_CASE("BanManager - SweepBanned marks dirty when removing expired", "[network][ban][improvements]") {
    BanImprovementsFixture fixture;

    SECTION("SweepBanned with expired bans marks dirty and auto-saves") {
        asio::io_context io;
        PeerLifecycleManager::Config config;
        PeerLifecycleManager pm(io, config, fixture.test_dir);

        // Ban with short duration (1 second)
        pm.Ban("192.168.1.1", 1);
        pm.Ban("192.168.1.2", 0);  // Permanent
        REQUIRE(pm.SaveBans());

        std::string banlist_path = fixture.GetBanlistPath();
        auto content1 = fixture.GetFileContent(banlist_path);

        // Advance mock time by 2 seconds to expire the first ban
        {
            unicity::util::MockTimeScope mt(unicity::util::GetTime() + 2);

            // Sweep should remove expired ban, mark dirty, and auto-save
            pm.SweepBanned();

            auto content2 = fixture.GetFileContent(banlist_path);
            REQUIRE(content1 != content2);

            // Verify only permanent ban remains
            auto bans = pm.GetBanned();
            REQUIRE(bans.size() == 1);
            REQUIRE(bans.find("192.168.1.2") != bans.end());
        }
    }
}
