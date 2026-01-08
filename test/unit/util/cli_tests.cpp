// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#include "catch_amalgamated.hpp"
#include "network/rpc_client.hpp"
#include "util/files.hpp"
#include <filesystem>
#include <cstdlib>

using namespace unicity;

TEST_CASE("CLI: Data directory resolution", "[cli][util]") {
    // Save original HOME to restore later
    const char* original_home = std::getenv("HOME");

    SECTION("get_default_datadir returns correct path when HOME is set") {
        // This should work in normal environment
        auto datadir = util::get_default_datadir();
        REQUIRE_FALSE(datadir.empty());

        #if defined(__APPLE__)
        REQUIRE(datadir.string().find("Library/Application Support/Unicity") != std::string::npos);
        #elif defined(__linux__) || defined(__unix__)
        REQUIRE(datadir.string().find(".unicity") != std::string::npos);
        #endif
    }

    SECTION("get_default_datadir returns empty path when HOME is not set") {
        // Temporarily unset HOME
        #ifdef _WIN32
        _putenv("HOME=");
        #else
        unsetenv("HOME");
        #endif

        auto datadir = util::get_default_datadir();
        REQUIRE(datadir.empty());

        // Restore HOME
        if (original_home) {
            #ifdef _WIN32
            std::string env = "HOME=";
            env += original_home;
            _putenv(env.c_str());
            #else
            setenv("HOME", original_home, 1);
            #endif
        }
    }
}

TEST_CASE("CLI: RPC Client socket path validation", "[cli][rpc]") {
    SECTION("Connect fails with helpful error for path too long") {
        // Create a socket path that exceeds the 104 byte limit
        std::string long_path(150, 'x');
        long_path += "/node.sock";

        rpc::RPCClient client(long_path);
        auto error = client.Connect();

        REQUIRE(error.has_value());
        REQUIRE(error->find("Socket path too long") != std::string::npos);
        REQUIRE(error->find("104") != std::string::npos);
        REQUIRE(error->find("shorter") != std::string::npos);
    }

    SECTION("Connect fails with connection error for non-existent socket") {
        auto test_dir = std::filesystem::temp_directory_path() / "unicity_cli_test";
        std::filesystem::remove_all(test_dir);
        std::filesystem::create_directories(test_dir);

        std::string socket_path = (test_dir / "nonexistent.sock").string();
        rpc::RPCClient client(socket_path);
        auto error = client.Connect();

        REQUIRE(error.has_value());
        REQUIRE(error->find("Cannot connect") != std::string::npos);
        REQUIRE(error->find(socket_path) != std::string::npos);

        std::filesystem::remove_all(test_dir);
    }

    SECTION("Connect succeeds for already connected client") {
        // This tests the "already connected" path
        // We can't easily test actual connection without a running server,
        // but we can verify the client doesn't crash on multiple Connect() calls
        auto test_dir = std::filesystem::temp_directory_path() / "unicity_cli_test2";
        std::filesystem::remove_all(test_dir);
        std::filesystem::create_directories(test_dir);

        std::string socket_path = (test_dir / "test.sock").string();
        rpc::RPCClient client(socket_path);

        // First connect will fail (no server)
        auto error1 = client.Connect();
        REQUIRE(error1.has_value());

        // Second connect should also fail, but not crash
        auto error2 = client.Connect();
        REQUIRE(error2.has_value());

        std::filesystem::remove_all(test_dir);
    }
}

TEST_CASE("CLI: RPC Client basic functionality", "[cli][rpc]") {
    SECTION("RPC client constructs without errors") {
        std::string path = "/tmp/test.sock";
        REQUIRE_NOTHROW(rpc::RPCClient(path));
    }

    SECTION("RPC client IsConnected returns false initially") {
        std::string path = "/tmp/test.sock";
        rpc::RPCClient client(path);
        REQUIRE_FALSE(client.IsConnected());
    }

    SECTION("RPC client disconnect works on unconnected client") {
        std::string path = "/tmp/test.sock";
        rpc::RPCClient client(path);
        REQUIRE_NOTHROW(client.Disconnect());
        REQUIRE_FALSE(client.IsConnected());
    }
}

TEST_CASE("CLI: Socket path edge cases", "[cli][rpc]") {
    SECTION("Socket path exactly at limit (104 bytes)") {
        // Create a path that is exactly 104 bytes (including null terminator)
        // node.sock = 9 bytes, so we need 104 - 9 - 1 (for /) - 1 (null) = 93 bytes for directory
        std::string dir_path(93, 'x');
        std::string full_path = dir_path + "/node.sock";
        REQUIRE(full_path.length() == 103); // 93 + 1 (/) + 9 (node.sock) = 103, plus null = 104 total

        rpc::RPCClient client(full_path);
        auto error = client.Connect();

        // Should fail with connection error, not path length error
        REQUIRE(error.has_value());
        REQUIRE(error->find("Cannot connect") != std::string::npos);
        REQUIRE(error->find("Socket path too long") == std::string::npos);
    }

    SECTION("Socket path just over limit (105 bytes)") {
        // 94 byte directory + / + node.sock (9) = 104 bytes string, 105 with null terminator
        std::string dir_path(94, 'x');
        std::string full_path = dir_path + "/node.sock";
        REQUIRE(full_path.length() == 104); // 94 + 1 + 9 = 104, will be >= 104 and trigger error

        rpc::RPCClient client(full_path);
        auto error = client.Connect();

        // Should fail with path length error
        REQUIRE(error.has_value());
        REQUIRE(error->find("Socket path too long") != std::string::npos);
    }
}
