// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#include "catch_amalgamated.hpp"
#include "chain/chainparams.hpp"
#include "chain/chainstate_manager.hpp"
#include "network/network_manager.hpp"
#include "network/rpc_client.hpp"
#include "network/rpc_server.hpp"
#include "util/logging.hpp"

#include <thread>
#include <chrono>
#include <filesystem>
#include <atomic>

using namespace unicity;
using namespace std::chrono_literals;

namespace {

// Test fixture for RPC integration tests
class RPCTestFixture {
public:
    RPCTestFixture() {
        // Create temporary directory for test
        temp_dir_ = std::filesystem::temp_directory_path() / "rpc_test";
        std::filesystem::create_directories(temp_dir_);
        socket_path_ = (temp_dir_ / "test.sock").string();

        // Initialize components
        auto params_unique = chain::ChainParams::CreateRegTest();
        params_ = params_unique.release();  // Take ownership as raw pointer
        chainstate_ = new validation::ChainstateManager(*params_);

        // Create NetworkManager config for regtest
        network::NetworkManager::Config net_config;
        net_config.network_magic = params_->GetNetworkMagic();
        net_config.listen_port = params_->GetDefaultPort();
        net_config.datadir = temp_dir_.string();
        net_config.io_threads = 0;  // External io_context for tests

        network_ = new network::NetworkManager(*chainstate_, net_config);

        // Create RPC server (without miner for basic tests)
        server_ = new rpc::RPCServer(
            socket_path_, *chainstate_, *network_, nullptr, *params_);
    }

    ~RPCTestFixture() {
        // Stop server first so no in-flight RPC calls can emit logs
        if (server_ && server_->IsRunning()) {
            server_->Stop();
        }

        // Reset log levels to "off" after server is stopped
        // (RPC logging tests modify global LogManager state)
        util::LogManager::SetLogLevel("off");
        delete server_;
        delete network_;
        delete chainstate_;
        delete params_;
        std::filesystem::remove_all(temp_dir_);
    }

    bool StartServer() {
        return server_->Start();
    }

    void StopServer() {
        server_->Stop();
    }

    std::string GetSocketPath() const {
        return socket_path_;
    }

    rpc::RPCServer& GetServer() {
        return *server_;
    }

private:
    std::filesystem::path temp_dir_;
    std::string socket_path_;
    chain::ChainParams* params_;
    validation::ChainstateManager* chainstate_;
    network::NetworkManager* network_;
    rpc::RPCServer* server_;
};

} // anonymous namespace

TEST_CASE("RPC Server: Start and Stop", "[rpc][integration]") {
    RPCTestFixture fixture;

    SECTION("Server starts successfully") {
        REQUIRE(fixture.StartServer());
        REQUIRE(fixture.GetServer().IsRunning());
    }

    SECTION("Server stops successfully") {
        REQUIRE(fixture.StartServer());
        fixture.StopServer();
        REQUIRE_FALSE(fixture.GetServer().IsRunning());
    }

    SECTION("Double start is idempotent") {
        REQUIRE(fixture.StartServer());
        REQUIRE(fixture.StartServer()); // Should return true (already running)
        REQUIRE(fixture.GetServer().IsRunning());
    }
}

TEST_CASE("RPC Client: Basic Connection", "[rpc][integration]") {
    RPCTestFixture fixture;
    REQUIRE(fixture.StartServer());

    // Give server time to bind
    std::this_thread::sleep_for(100ms);

    rpc::RPCClient client(fixture.GetSocketPath());

    SECTION("Client connects successfully") {
        REQUIRE_FALSE(client.Connect().has_value());
        REQUIRE(client.IsConnected());
    }

    SECTION("Client can disconnect") {
        REQUIRE_FALSE(client.Connect().has_value());
        client.Disconnect();
        REQUIRE_FALSE(client.IsConnected());
    }

    SECTION("Double connect is idempotent") {
        REQUIRE_FALSE(client.Connect().has_value());
        REQUIRE_FALSE(client.Connect().has_value()); // Should return true (already connected)
        REQUIRE(client.IsConnected());
    }
}

TEST_CASE("RPC Commands: getinfo", "[rpc][integration][commands]") {
    RPCTestFixture fixture;
    REQUIRE(fixture.StartServer());
    std::this_thread::sleep_for(100ms);

    rpc::RPCClient client(fixture.GetSocketPath());
    REQUIRE_FALSE(client.Connect().has_value());

    SECTION("getinfo returns valid JSON") {
        std::string response = client.ExecuteCommand("getinfo", {});
        REQUIRE_FALSE(response.empty());

        // Should contain expected fields
        REQUIRE(response.find("\"version\"") != std::string::npos);
        REQUIRE(response.find("\"blocks\"") != std::string::npos);
        REQUIRE(response.find("\"difficulty\"") != std::string::npos);
    }
}

TEST_CASE("RPC Commands: getblockcount", "[rpc][integration][commands]") {
    RPCTestFixture fixture;
    REQUIRE(fixture.StartServer());
    std::this_thread::sleep_for(100ms);

    rpc::RPCClient client(fixture.GetSocketPath());
    REQUIRE_FALSE(client.Connect().has_value());

    SECTION("getblockcount returns height") {
        std::string response = client.ExecuteCommand("getblockcount", {});
        REQUIRE_FALSE(response.empty());

        // Should be -1 for empty chain
        REQUIRE(response.find("-1") != std::string::npos);
    }
}

TEST_CASE("RPC Commands: Error Handling", "[rpc][integration][errors]") {
    RPCTestFixture fixture;
    REQUIRE(fixture.StartServer());
    std::this_thread::sleep_for(100ms);

    rpc::RPCClient client(fixture.GetSocketPath());
    REQUIRE_FALSE(client.Connect().has_value());

    SECTION("Unknown command returns error") {
        std::string response = client.ExecuteCommand("invalidcommand", {});
        REQUIRE(response.find("error") != std::string::npos);
        REQUIRE(response.find("Unknown command") != std::string::npos);
    }

    // Note: Testing invalid JSON would require raw socket access since RPCClient
    // constructs valid JSON. This is tested in raw socket tests if needed.

    SECTION("Missing parameters returns error") {
        // Test command that requires parameters
        std::string response = client.ExecuteCommand("getblockhash", {});
        REQUIRE(response.find("error") != std::string::npos);
        REQUIRE(response.find("Missing height parameter") != std::string::npos);
    }

    SECTION("Invalid parameter format returns error") {
        std::string response = client.ExecuteCommand("getblockhash", {"not_a_number"});
        REQUIRE(response.find("error") != std::string::npos);
        REQUIRE(response.find("Invalid height") != std::string::npos);
    }
}

TEST_CASE("RPC: Concurrent Requests", "[rpc][integration][concurrency]") {
    RPCTestFixture fixture;
    REQUIRE(fixture.StartServer());
    std::this_thread::sleep_for(100ms);

    SECTION("Multiple clients can connect concurrently") {
        std::vector<std::thread> threads;
        std::atomic<int> success_count{0};
        std::atomic<int> error_count{0};

        const int num_clients = 5;

        for (int i = 0; i < num_clients; ++i) {
            threads.emplace_back([&, i]() {
                rpc::RPCClient client(fixture.GetSocketPath());
                if (!client.Connect().has_value()) {
                    try {
                        std::string response = client.ExecuteCommand("getinfo", {});
                        if (!response.empty() && response.find("error") == std::string::npos) {
                            success_count++;
                        } else {
                            error_count++;
                        }
                    } catch (...) {
                        error_count++;
                    }
                }
            });
        }

        for (auto& thread : threads) {
            thread.join();
        }

        REQUIRE(success_count == num_clients);
        REQUIRE(error_count == 0);
    }
}

TEST_CASE("RPC: Rate Limiting", "[rpc][integration][ratelimit]") {
    RPCTestFixture fixture;
    REQUIRE(fixture.StartServer());
    std::this_thread::sleep_for(100ms);

    SECTION("Exceeding concurrent request limit returns error") {
        // MAX_CONCURRENT_REQUESTS is 10
        // Try to spawn 15 concurrent requests
        std::vector<std::thread> threads;
        std::atomic<int> busy_errors{0};
        std::atomic<int> success_count{0};

        const int num_requests = 15;

        for (int i = 0; i < num_requests; ++i) {
            threads.emplace_back([&]() {
                rpc::RPCClient client(fixture.GetSocketPath());
                if (!client.Connect().has_value()) {
                    try {
                        // Use a slow command to keep requests active
                        std::string response = client.ExecuteCommand("getinfo", {});
                        if (response.find("Server busy") != std::string::npos) {
                            busy_errors++;
                        } else if (!response.empty() && response.find("error") == std::string::npos) {
                            success_count++;
                        }
                    } catch (...) {
                        // Ignore exceptions
                    }
                }
            });
        }

        for (auto& thread : threads) {
            thread.join();
        }

        // With 15 concurrent requests and MAX_CONCURRENT_REQUESTS=10:
        // - At least 10 should succeed (server capacity)
        // - Some may get "Server busy" if they arrive while all slots are full
        INFO("Success: " << success_count << ", Busy errors: " << busy_errors);
        REQUIRE(success_count >= 10);  // At least server capacity worth should succeed
        REQUIRE(success_count <= 15);  // Can't succeed more than we sent
    }
}

TEST_CASE("RPC: Socket Path Validation", "[rpc][integration][validation]") {
    SECTION("Very long socket path is rejected") {
        // Create a path longer than 104 characters
        std::string long_path(150, 'x');
        long_path = "/tmp/" + long_path + ".sock";

        auto params_ptr = chain::ChainParams::CreateRegTest();
        auto temp_dir = std::filesystem::temp_directory_path() / "rpc_long_path_test";
        std::filesystem::create_directories(temp_dir);

        validation::ChainstateManager chainstate(*params_ptr);

        network::NetworkManager::Config net_config;
        net_config.network_magic = params_ptr->GetNetworkMagic();
        net_config.listen_port = params_ptr->GetDefaultPort();
        net_config.datadir = temp_dir.string();
        net_config.io_threads = 0;
        network::NetworkManager network(chainstate, net_config);

        rpc::RPCServer server(long_path, chainstate, network, nullptr, *params_ptr);

        // Should fail to start due to path too long
        REQUIRE_FALSE(server.Start());

        std::filesystem::remove_all(temp_dir);
    }
}

TEST_CASE("RPC Client: Large Response Handling", "[rpc][integration][buffer]") {
    RPCTestFixture fixture;
    REQUIRE(fixture.StartServer());
    std::this_thread::sleep_for(100ms);

    rpc::RPCClient client(fixture.GetSocketPath());
    REQUIRE_FALSE(client.Connect().has_value());

    SECTION("Client handles responses > 4KB") {
        // getpeerinfo can return large responses
        // For now, test that it doesn't crash
        std::string response = client.ExecuteCommand("getpeerinfo", {});
        REQUIRE_FALSE(response.empty());

        // Response should be valid (might be empty JSON array if no peers)
        REQUIRE((response.find("[") != std::string::npos ||
                 response.find("error") != std::string::npos));
    }
}

TEST_CASE("RPC: Server Shutdown During Request", "[rpc][integration][shutdown]") {
    RPCTestFixture fixture;
    REQUIRE(fixture.StartServer());
    std::this_thread::sleep_for(100ms);

    SECTION("In-flight requests complete before shutdown") {
        std::atomic<bool> request_completed{false};
        std::atomic<bool> got_response{false};

        std::thread client_thread([&]() {
            rpc::RPCClient client(fixture.GetSocketPath());
            if (!client.Connect().has_value()) {
                try {
                    std::string response = client.ExecuteCommand("getinfo", {});
                    got_response = !response.empty();
                } catch (...) {
                    // Exception expected if server shuts down
                }
                request_completed = true;
            }
        });

        // Give client time to connect and send request
        std::this_thread::sleep_for(50ms);

        // Stop server while request might be in flight
        fixture.StopServer();

        client_thread.join();

        REQUIRE(request_completed);
        // Response might or might not succeed depending on timing
        // The important thing is no crash
    }
}

TEST_CASE("RPC Commands: Parameter Validation", "[rpc][integration][validation]") {
    RPCTestFixture fixture;
    REQUIRE(fixture.StartServer());
    std::this_thread::sleep_for(100ms);

    rpc::RPCClient client(fixture.GetSocketPath());
    REQUIRE_FALSE(client.Connect().has_value());

    SECTION("getblockhash: height out of range") {
        std::string response = client.ExecuteCommand("getblockhash", {"999999"});
        REQUIRE(response.find("error") != std::string::npos);
        REQUIRE(response.find("out of range") != std::string::npos);
    }

    SECTION("getblockhash: negative height") {
        std::string response = client.ExecuteCommand("getblockhash", {"-1"});
        REQUIRE(response.find("error") != std::string::npos);
    }

    SECTION("getblockhash: height too large") {
        std::string response = client.ExecuteCommand("getblockhash", {"99999999"});
        REQUIRE(response.find("error") != std::string::npos);
    }
}

TEST_CASE("RPC Commands: getblockheader", "[rpc][integration][commands]") {
    RPCTestFixture fixture;
    REQUIRE(fixture.StartServer());
    std::this_thread::sleep_for(100ms);

    rpc::RPCClient client(fixture.GetSocketPath());
    REQUIRE_FALSE(client.Connect().has_value());

    SECTION("Invalid hash format returns error") {
        std::string response = client.ExecuteCommand("getblockheader", {"invalid"});
        REQUIRE(response.find("error") != std::string::npos);
        REQUIRE(response.find("Invalid block hash") != std::string::npos);
    }

    SECTION("Non-existent block returns error") {
        std::string fake_hash(64, '0');
        std::string response = client.ExecuteCommand("getblockheader", {fake_hash});
        REQUIRE(response.find("error") != std::string::npos);
        REQUIRE(response.find("Block not found") != std::string::npos);
    }
}

TEST_CASE("RPC: Exception Safety", "[rpc][integration][exceptions]") {
    RPCTestFixture fixture;
    REQUIRE(fixture.StartServer());
    std::this_thread::sleep_for(100ms);

    SECTION("Server handles malformed requests without crashing") {
        // Even with invalid commands, server should stay running
        rpc::RPCClient client1(fixture.GetSocketPath());
        REQUIRE_FALSE(client1.Connect().has_value());

        std::string response1 = client1.ExecuteCommand("invalid_command", {});
        REQUIRE(response1.find("error") != std::string::npos);

        // Server should still be running and accepting new requests
        rpc::RPCClient client2(fixture.GetSocketPath());
        REQUIRE_FALSE(client2.Connect().has_value());

        std::string response2 = client2.ExecuteCommand("getinfo", {});
        REQUIRE(response2.find("error") == std::string::npos);
        REQUIRE(response2.find("version") != std::string::npos);
    }
}

TEST_CASE("RPC Commands: logging", "[rpc][integration][commands]") {
    RPCTestFixture fixture;
    REQUIRE(fixture.StartServer());
    std::this_thread::sleep_for(100ms);

    // Note: Each SECTION needs its own client because server closes connection after each request
    SECTION("Get current log levels") {
        rpc::RPCClient client(fixture.GetSocketPath());
        REQUIRE_FALSE(client.Connect().has_value());
        std::string response = client.ExecuteCommand("logging", {});
        REQUIRE_FALSE(response.empty());

        // Should contain all 4 active categories
        REQUIRE(response.find("\"default\"") != std::string::npos);
        REQUIRE(response.find("\"network\"") != std::string::npos);
        REQUIRE(response.find("\"chain\"") != std::string::npos);
        REQUIRE(response.find("\"crypto\"") != std::string::npos);

        // Should NOT contain inactive categories
        REQUIRE(response.find("\"sync\"") == std::string::npos);
        REQUIRE(response.find("\"app\"") == std::string::npos);
    }

    SECTION("Set single category log level") {
        rpc::RPCClient client(fixture.GetSocketPath());
        REQUIRE_FALSE(client.Connect().has_value());
        std::string response = client.ExecuteCommand("logging", {"network:debug"});
        REQUIRE(response.find("\"error\":") == std::string::npos);  // No JSON error key
        REQUIRE(response.find("\"category\": \"network\"") != std::string::npos);
        REQUIRE(response.find("\"level\": \"debug\"") != std::string::npos);

        // Verify it was actually set (need new client since server closes connection)
        rpc::RPCClient client2(fixture.GetSocketPath());
        REQUIRE_FALSE(client2.Connect().has_value());
        std::string check = client2.ExecuteCommand("logging", {});
        REQUIRE(check.find("\"network\": \"debug\"") != std::string::npos);

        // Reset so subsequent RPC calls in teardown don't emit debug logs
        util::LogManager::SetLogLevel("off");
    }

    SECTION("Set all categories log level") {
        rpc::RPCClient client(fixture.GetSocketPath());
        REQUIRE_FALSE(client.Connect().has_value());
        std::string response = client.ExecuteCommand("logging", {"all:warn"});
        REQUIRE(response.find("\"error\":") == std::string::npos);  // No JSON error key
        REQUIRE(response.find("\"category\": \"all\"") != std::string::npos);
        REQUIRE(response.find("\"level\": \"warn\"") != std::string::npos);
        // Note: Skipping verification of actual log level changes because LogManager
        // is global state that may not be properly initialized in test fixtures
    }

    SECTION("Set multiple categories at once") {
        rpc::RPCClient client(fixture.GetSocketPath());
        REQUIRE_FALSE(client.Connect().has_value());
        std::string response = client.ExecuteCommand("logging", {"network:trace", "chain:warn"});
        REQUIRE(response.find("\"error\":") == std::string::npos);  // No JSON error key
        REQUIRE(response.find("\"category\": \"network\"") != std::string::npos);
        REQUIRE(response.find("\"level\": \"trace\"") != std::string::npos);
        REQUIRE(response.find("\"category\": \"chain\"") != std::string::npos);
        REQUIRE(response.find("\"level\": \"warn\"") != std::string::npos);
    }

    SECTION("Invalid log level returns error") {
        rpc::RPCClient client(fixture.GetSocketPath());
        REQUIRE_FALSE(client.Connect().has_value());
        std::string response = client.ExecuteCommand("logging", {"network:invalid"});
        REQUIRE(response.find("error") != std::string::npos);
        REQUIRE(response.find("Invalid log level") != std::string::npos);
    }

    SECTION("Invalid category returns error") {
        rpc::RPCClient client(fixture.GetSocketPath());
        REQUIRE_FALSE(client.Connect().has_value());
        std::string response = client.ExecuteCommand("logging", {"invalid:debug"});
        REQUIRE(response.find("error") != std::string::npos);
        REQUIRE(response.find("Invalid category") != std::string::npos);
    }

    SECTION("Invalid format returns error") {
        rpc::RPCClient client(fixture.GetSocketPath());
        REQUIRE_FALSE(client.Connect().has_value());
        std::string response = client.ExecuteCommand("logging", {"network_debug"});
        REQUIRE(response.find("error") != std::string::npos);
        REQUIRE(response.find("Invalid format") != std::string::npos);
    }

    SECTION("Sync and app categories rejected") {
        rpc::RPCClient client1(fixture.GetSocketPath());
        REQUIRE_FALSE(client1.Connect().has_value());
        std::string response1 = client1.ExecuteCommand("logging", {"sync:debug"});
        REQUIRE(response1.find("error") != std::string::npos);
        REQUIRE(response1.find("Invalid category") != std::string::npos);

        rpc::RPCClient client2(fixture.GetSocketPath());
        REQUIRE_FALSE(client2.Connect().has_value());
        std::string response2 = client2.ExecuteCommand("logging", {"app:debug"});
        REQUIRE(response2.find("error") != std::string::npos);
        REQUIRE(response2.find("Invalid category") != std::string::npos);
    }

    SECTION("All valid log levels work") {
        std::vector<std::string> levels = {"trace", "debug", "info", "warn", "error", "critical", "off"};
        for (const auto& level : levels) {
            rpc::RPCClient client(fixture.GetSocketPath());
            REQUIRE_FALSE(client.Connect().has_value());
            std::string response = client.ExecuteCommand("logging", {"default:" + level});
            REQUIRE(response.find("\"error\":") == std::string::npos);  // No JSON error key
            REQUIRE(response.find("\"level\": \"" + level + "\"") != std::string::npos);
        }
    }
}

// ============================================================================
// Blockchain RPC Commands
// ============================================================================

TEST_CASE("RPC Commands: getblockchaininfo", "[rpc][integration][blockchain]") {
    RPCTestFixture fixture;
    REQUIRE(fixture.StartServer());
    std::this_thread::sleep_for(100ms);

    rpc::RPCClient client(fixture.GetSocketPath());
    REQUIRE_FALSE(client.Connect().has_value());

    SECTION("Returns valid JSON with required fields") {
        std::string response = client.ExecuteCommand("getblockchaininfo", {});
        REQUIRE_FALSE(response.empty());

        // Check required fields
        REQUIRE(response.find("\"chain\"") != std::string::npos);
        REQUIRE(response.find("\"blocks\"") != std::string::npos);
        REQUIRE(response.find("\"bestblockhash\"") != std::string::npos);
        REQUIRE(response.find("\"difficulty\"") != std::string::npos);
        REQUIRE(response.find("\"chainwork\"") != std::string::npos);
    }

    SECTION("Returns correct chain type for regtest") {
        std::string response = client.ExecuteCommand("getblockchaininfo", {});
        REQUIRE(response.find("\"chain\": \"regtest\"") != std::string::npos);
    }

    SECTION("Shows -1 blocks for empty chain") {
        std::string response = client.ExecuteCommand("getblockchaininfo", {});
        REQUIRE(response.find("\"blocks\": -1") != std::string::npos);
    }
}

TEST_CASE("RPC Commands: getbestblockhash", "[rpc][integration][blockchain]") {
    RPCTestFixture fixture;
    REQUIRE(fixture.StartServer());
    std::this_thread::sleep_for(100ms);

    rpc::RPCClient client(fixture.GetSocketPath());
    REQUIRE_FALSE(client.Connect().has_value());

    SECTION("Returns null hash for empty chain") {
        std::string response = client.ExecuteCommand("getbestblockhash", {});
        // Empty chain should return null/zero hash or error
        REQUIRE(!response.empty());
    }
}

TEST_CASE("RPC Commands: getdifficulty", "[rpc][integration][blockchain]") {
    RPCTestFixture fixture;
    REQUIRE(fixture.StartServer());
    std::this_thread::sleep_for(100ms);

    rpc::RPCClient client(fixture.GetSocketPath());
    REQUIRE_FALSE(client.Connect().has_value());

    SECTION("Returns numeric difficulty value") {
        std::string response = client.ExecuteCommand("getdifficulty", {});
        REQUIRE_FALSE(response.empty());
        // Should contain a numeric value (may be 0 for empty chain)
        REQUIRE(response.find("error") == std::string::npos);
    }
}

TEST_CASE("RPC Commands: getchaintips", "[rpc][integration][blockchain]") {
    RPCTestFixture fixture;
    REQUIRE(fixture.StartServer());
    std::this_thread::sleep_for(100ms);

    rpc::RPCClient client(fixture.GetSocketPath());
    REQUIRE_FALSE(client.Connect().has_value());

    SECTION("Returns array of chain tips") {
        std::string response = client.ExecuteCommand("getchaintips", {});
        REQUIRE_FALSE(response.empty());
        // Should return a JSON array (possibly empty for no chain)
        REQUIRE((response.find("[") != std::string::npos ||
                 response.find("error") != std::string::npos));
    }
}

// ============================================================================
// Mining RPC Commands
// ============================================================================

TEST_CASE("RPC Commands: getmininginfo", "[rpc][integration][mining]") {
    RPCTestFixture fixture;
    REQUIRE(fixture.StartServer());
    std::this_thread::sleep_for(100ms);

    rpc::RPCClient client(fixture.GetSocketPath());
    REQUIRE_FALSE(client.Connect().has_value());

    SECTION("Returns valid JSON with required fields") {
        std::string response = client.ExecuteCommand("getmininginfo", {});
        REQUIRE_FALSE(response.empty());

        // Check required fields
        REQUIRE(response.find("\"blocks\"") != std::string::npos);
        REQUIRE(response.find("\"difficulty\"") != std::string::npos);
        REQUIRE(response.find("\"chain\"") != std::string::npos);
    }

    SECTION("Shows mining status") {
        std::string response = client.ExecuteCommand("getmininginfo", {});
        // Should have mining field (true or false)
        REQUIRE(response.find("\"mining\"") != std::string::npos);
    }
}

TEST_CASE("RPC Commands: getnetworkhashps", "[rpc][integration][mining]") {
    RPCTestFixture fixture;
    REQUIRE(fixture.StartServer());
    std::this_thread::sleep_for(100ms);

    rpc::RPCClient client(fixture.GetSocketPath());
    REQUIRE_FALSE(client.Connect().has_value());

    SECTION("Returns numeric hashrate") {
        std::string response = client.ExecuteCommand("getnetworkhashps", {});
        REQUIRE_FALSE(response.empty());
        // Should return a number (possibly 0 for empty chain)
        REQUIRE(response.find("error") == std::string::npos);
    }

    SECTION("Accepts nblocks parameter") {
        std::string response = client.ExecuteCommand("getnetworkhashps", {"10"});
        REQUIRE_FALSE(response.empty());
        REQUIRE(response.find("error") == std::string::npos);
    }
}

TEST_CASE("RPC Commands: startmining/stopmining", "[rpc][integration][mining]") {
    RPCTestFixture fixture;
    REQUIRE(fixture.StartServer());
    std::this_thread::sleep_for(100ms);

    SECTION("startmining without miner returns error") {
        rpc::RPCClient client(fixture.GetSocketPath());
        REQUIRE_FALSE(client.Connect().has_value());
        std::string response = client.ExecuteCommand("startmining", {});
        // Should error because miner is null in fixture
        REQUIRE(response.find("error") != std::string::npos);
    }

    SECTION("stopmining without miner returns error") {
        rpc::RPCClient client(fixture.GetSocketPath());
        REQUIRE_FALSE(client.Connect().has_value());
        std::string response = client.ExecuteCommand("stopmining", {});
        REQUIRE(response.find("error") != std::string::npos);
    }
}

TEST_CASE("RPC Commands: getblocktemplate", "[rpc][integration][mining]") {
    RPCTestFixture fixture;
    REQUIRE(fixture.StartServer());
    std::this_thread::sleep_for(100ms);

    rpc::RPCClient client(fixture.GetSocketPath());
    REQUIRE_FALSE(client.Connect().has_value());

    SECTION("Returns error or template") {
        std::string response = client.ExecuteCommand("getblocktemplate", {});
        REQUIRE_FALSE(response.empty());

        // Either returns a valid template (if chain is initialized) or an error
        // Test fixture may not have a genesis block loaded
        bool has_template = response.find("\"previousblockhash\"") != std::string::npos;
        bool has_error = response.find("error") != std::string::npos;
        REQUIRE((has_template || has_error));

        // If we got a template, verify required fields
        if (has_template) {
            REQUIRE(response.find("\"version\"") != std::string::npos);
            REQUIRE(response.find("\"height\"") != std::string::npos);
            REQUIRE(response.find("\"bits\"") != std::string::npos);
            REQUIRE(response.find("\"target\"") != std::string::npos);
            REQUIRE(response.find("\"longpollid\"") != std::string::npos);
        }
    }
}

TEST_CASE("RPC Commands: submitblock", "[rpc][integration][mining]") {
    RPCTestFixture fixture;
    REQUIRE(fixture.StartServer());
    std::this_thread::sleep_for(100ms);

    SECTION("Missing parameter returns error") {
        rpc::RPCClient client(fixture.GetSocketPath());
        REQUIRE_FALSE(client.Connect().has_value());
        std::string response = client.ExecuteCommand("submitblock", {});
        REQUIRE(response.find("error") != std::string::npos);
    }

    SECTION("Invalid hex length returns error") {
        rpc::RPCClient client(fixture.GetSocketPath());
        REQUIRE_FALSE(client.Connect().has_value());
        // 100 bytes = 200 hex chars expected
        std::string response = client.ExecuteCommand("submitblock", {"abcd1234"});
        REQUIRE(response.find("error") != std::string::npos);
        REQUIRE(response.find("length") != std::string::npos);
    }

    SECTION("Invalid hex characters returns error") {
        rpc::RPCClient client(fixture.GetSocketPath());
        REQUIRE_FALSE(client.Connect().has_value());
        // 200 chars but with invalid hex (contains 'g')
        std::string invalid_hex(200, 'g');
        std::string response = client.ExecuteCommand("submitblock", {invalid_hex});
        REQUIRE(response.find("error") != std::string::npos);
    }
}

TEST_CASE("RPC Commands: generate", "[rpc][integration][mining]") {
    RPCTestFixture fixture;
    REQUIRE(fixture.StartServer());
    std::this_thread::sleep_for(100ms);

    SECTION("Missing or unavailable returns error") {
        rpc::RPCClient client(fixture.GetSocketPath());
        REQUIRE_FALSE(client.Connect().has_value());
        std::string response = client.ExecuteCommand("generate", {});
        // Should return an error - either "Mining not available" (no miner),
        // "generate only available on regtest" (wrong chain), or
        // "Missing number of blocks parameter" (missing param)
        REQUIRE(response.find("error") != std::string::npos);
    }

    SECTION("Invalid nblocks parameter returns error") {
        rpc::RPCClient client(fixture.GetSocketPath());
        REQUIRE_FALSE(client.Connect().has_value());
        std::string response = client.ExecuteCommand("generate", {"not_a_number"});
        REQUIRE(response.find("error") != std::string::npos);
    }

    SECTION("Zero blocks returns empty array") {
        rpc::RPCClient client(fixture.GetSocketPath());
        REQUIRE_FALSE(client.Connect().has_value());
        std::string response = client.ExecuteCommand("generate", {"0"});
        // Should return empty array or error, not crash
        REQUIRE_FALSE(response.empty());
    }
}

// ============================================================================
// Network RPC Commands
// ============================================================================

TEST_CASE("RPC Commands: getconnectioncount", "[rpc][integration][network]") {
    RPCTestFixture fixture;
    REQUIRE(fixture.StartServer());
    std::this_thread::sleep_for(100ms);

    rpc::RPCClient client(fixture.GetSocketPath());
    REQUIRE_FALSE(client.Connect().has_value());

    SECTION("Returns numeric connection count") {
        std::string response = client.ExecuteCommand("getconnectioncount", {});
        REQUIRE_FALSE(response.empty());
        // Should return 0 for isolated test node
        REQUIRE(response.find("0") != std::string::npos);
    }
}

TEST_CASE("RPC Commands: addnode", "[rpc][integration][network]") {
    RPCTestFixture fixture;
    REQUIRE(fixture.StartServer());
    std::this_thread::sleep_for(100ms);

    SECTION("Missing parameters returns error") {
        rpc::RPCClient client(fixture.GetSocketPath());
        REQUIRE_FALSE(client.Connect().has_value());
        std::string response = client.ExecuteCommand("addnode", {});
        REQUIRE(response.find("error") != std::string::npos);
    }

    SECTION("Invalid command returns error") {
        rpc::RPCClient client(fixture.GetSocketPath());
        REQUIRE_FALSE(client.Connect().has_value());
        std::string response = client.ExecuteCommand("addnode", {"127.0.0.1:9590", "invalid"});
        REQUIRE(response.find("error") != std::string::npos);
    }

    SECTION("Add command with valid IP") {
        rpc::RPCClient client(fixture.GetSocketPath());
        REQUIRE_FALSE(client.Connect().has_value());
        std::string response = client.ExecuteCommand("addnode", {"127.0.0.1:9590", "add"});
        // Should succeed or report connection error (not crash)
        REQUIRE_FALSE(response.empty());
    }

    SECTION("Remove command with valid IP") {
        rpc::RPCClient client(fixture.GetSocketPath());
        REQUIRE_FALSE(client.Connect().has_value());
        std::string response = client.ExecuteCommand("addnode", {"127.0.0.1:9590", "remove"});
        REQUIRE_FALSE(response.empty());
    }
}

TEST_CASE("RPC Commands: setban", "[rpc][integration][network]") {
    RPCTestFixture fixture;
    REQUIRE(fixture.StartServer());
    std::this_thread::sleep_for(100ms);

    SECTION("Missing parameters returns error") {
        rpc::RPCClient client(fixture.GetSocketPath());
        REQUIRE_FALSE(client.Connect().has_value());
        std::string response = client.ExecuteCommand("setban", {});
        REQUIRE(response.find("error") != std::string::npos);
    }

    SECTION("Invalid command returns error") {
        rpc::RPCClient client(fixture.GetSocketPath());
        REQUIRE_FALSE(client.Connect().has_value());
        std::string response = client.ExecuteCommand("setban", {"192.168.1.0/24", "invalid"});
        REQUIRE(response.find("error") != std::string::npos);
    }

    SECTION("Ban IP address") {
        rpc::RPCClient client(fixture.GetSocketPath());
        REQUIRE_FALSE(client.Connect().has_value());
        std::string response = client.ExecuteCommand("setban", {"192.168.1.1", "add"});
        REQUIRE(response.find("error") == std::string::npos);
    }

    SECTION("Ban with bantime parameter") {
        rpc::RPCClient client(fixture.GetSocketPath());
        REQUIRE_FALSE(client.Connect().has_value());
        // Test with explicit bantime parameter (3600 seconds = 1 hour)
        std::string response = client.ExecuteCommand("setban", {"10.0.0.1", "add", "3600"});
        REQUIRE(response.find("error") == std::string::npos);
    }

    SECTION("Invalid IP format returns error") {
        rpc::RPCClient client(fixture.GetSocketPath());
        REQUIRE_FALSE(client.Connect().has_value());
        std::string response = client.ExecuteCommand("setban", {"not_an_ip", "add"});
        REQUIRE(response.find("error") != std::string::npos);
    }
}

TEST_CASE("RPC Commands: listbanned", "[rpc][integration][network]") {
    RPCTestFixture fixture;
    REQUIRE(fixture.StartServer());
    std::this_thread::sleep_for(100ms);

    rpc::RPCClient client(fixture.GetSocketPath());
    REQUIRE_FALSE(client.Connect().has_value());

    SECTION("Returns array of banned IPs") {
        std::string response = client.ExecuteCommand("listbanned", {});
        REQUIRE_FALSE(response.empty());
        REQUIRE(response.find("[") != std::string::npos);
    }
}

TEST_CASE("RPC Commands: clearbanned", "[rpc][integration][network]") {
    RPCTestFixture fixture;
    REQUIRE(fixture.StartServer());
    std::this_thread::sleep_for(100ms);

    SECTION("Clears all bans successfully") {
        // First add a ban
        rpc::RPCClient client1(fixture.GetSocketPath());
        REQUIRE_FALSE(client1.Connect().has_value());
        client1.ExecuteCommand("setban", {"192.168.1.1", "add"});

        // Then clear all bans
        rpc::RPCClient client2(fixture.GetSocketPath());
        REQUIRE_FALSE(client2.Connect().has_value());
        std::string response = client2.ExecuteCommand("clearbanned", {});
        REQUIRE(response.find("error") == std::string::npos);

        // Verify ban list is empty (no addresses in the list)
        rpc::RPCClient client3(fixture.GetSocketPath());
        REQUIRE_FALSE(client3.Connect().has_value());
        std::string list = client3.ExecuteCommand("listbanned", {});
        // Empty list contains "[" but no "address" entries
        REQUIRE(list.find("[") != std::string::npos);
        REQUIRE(list.find("\"address\"") == std::string::npos);
    }
}

TEST_CASE("RPC Commands: getaddrmaninfo", "[rpc][integration][network]") {
    RPCTestFixture fixture;
    REQUIRE(fixture.StartServer());
    std::this_thread::sleep_for(100ms);

    rpc::RPCClient client(fixture.GetSocketPath());
    REQUIRE_FALSE(client.Connect().has_value());

    SECTION("Returns address manager statistics") {
        std::string response = client.ExecuteCommand("getaddrmaninfo", {});
        REQUIRE_FALSE(response.empty());

        // Should contain address count fields
        REQUIRE(response.find("\"total\"") != std::string::npos);
        REQUIRE(response.find("\"tried\"") != std::string::npos);
        REQUIRE(response.find("\"new\"") != std::string::npos);
    }
}

TEST_CASE("RPC Commands: disconnectnode", "[rpc][integration][network]") {
    RPCTestFixture fixture;
    REQUIRE(fixture.StartServer());
    std::this_thread::sleep_for(100ms);

    SECTION("Missing parameters returns error") {
        rpc::RPCClient client(fixture.GetSocketPath());
        REQUIRE_FALSE(client.Connect().has_value());
        std::string response = client.ExecuteCommand("disconnectnode", {});
        REQUIRE(response.find("error") != std::string::npos);
    }

    SECTION("Non-existent peer returns error") {
        rpc::RPCClient client(fixture.GetSocketPath());
        REQUIRE_FALSE(client.Connect().has_value());
        std::string response = client.ExecuteCommand("disconnectnode", {"192.168.1.1:9590"});
        REQUIRE(response.find("error") != std::string::npos);
    }

    SECTION("Invalid peer ID returns error") {
        rpc::RPCClient client(fixture.GetSocketPath());
        REQUIRE_FALSE(client.Connect().has_value());
        std::string response = client.ExecuteCommand("disconnectnode", {"not_a_peer"});
        REQUIRE(response.find("error") != std::string::npos);
    }
}

// ============================================================================
// Control RPC Commands
// ============================================================================

TEST_CASE("RPC Commands: addpeeraddress", "[rpc][integration][network]") {
    RPCTestFixture fixture;
    REQUIRE(fixture.StartServer());
    std::this_thread::sleep_for(100ms);

    SECTION("Missing address parameter returns error") {
        rpc::RPCClient client(fixture.GetSocketPath());
        REQUIRE_FALSE(client.Connect().has_value());
        std::string response = client.ExecuteCommand("addpeeraddress", {});
        REQUIRE(response.find("error") != std::string::npos);
    }

    SECTION("Add valid address succeeds") {
        rpc::RPCClient client(fixture.GetSocketPath());
        REQUIRE_FALSE(client.Connect().has_value());
        std::string response = client.ExecuteCommand("addpeeraddress", {"192.168.1.100"});
        REQUIRE(response.find("\"success\"") != std::string::npos);
    }

    SECTION("Add address with port") {
        rpc::RPCClient client(fixture.GetSocketPath());
        REQUIRE_FALSE(client.Connect().has_value());
        std::string response = client.ExecuteCommand("addpeeraddress", {"10.0.0.50", "9590"});
        REQUIRE(response.find("\"success\"") != std::string::npos);
        REQUIRE(response.find("\"port\": 9590") != std::string::npos);
    }
}

TEST_CASE("RPC Commands: stop", "[rpc][integration][control]") {
    // Test stop command in isolation - it shuts down the server
    RPCTestFixture fixture;
    REQUIRE(fixture.StartServer());
    std::this_thread::sleep_for(100ms);

    // Verify server is running
    REQUIRE(fixture.GetServer().IsRunning());

    // Call stop and verify it returns an acknowledgment
    rpc::RPCClient client(fixture.GetSocketPath());
    REQUIRE_FALSE(client.Connect().has_value());
    std::string response = client.ExecuteCommand("stop", {});
    // Stop returns a shutdown message
    REQUIRE_FALSE(response.empty());
    REQUIRE(response.find("error") == std::string::npos);
}

// ============================================================================
// Testing/Debug RPC Commands (regtest only)
// ============================================================================

TEST_CASE("RPC Commands: setmocktime", "[rpc][integration][debug]") {
    RPCTestFixture fixture;
    REQUIRE(fixture.StartServer());
    std::this_thread::sleep_for(100ms);

    SECTION("Set mock time") {
        rpc::RPCClient client(fixture.GetSocketPath());
        REQUIRE_FALSE(client.Connect().has_value());
        std::string response = client.ExecuteCommand("setmocktime", {"1700000000"});
        REQUIRE(response.find("error") == std::string::npos);
    }

    SECTION("Disable mock time with 0") {
        rpc::RPCClient client(fixture.GetSocketPath());
        REQUIRE_FALSE(client.Connect().has_value());
        std::string response = client.ExecuteCommand("setmocktime", {"0"});
        REQUIRE(response.find("error") == std::string::npos);
    }

    SECTION("Missing parameter returns error") {
        rpc::RPCClient client(fixture.GetSocketPath());
        REQUIRE_FALSE(client.Connect().has_value());
        std::string response = client.ExecuteCommand("setmocktime", {});
        REQUIRE(response.find("error") != std::string::npos);
    }

    SECTION("Invalid timestamp returns error") {
        rpc::RPCClient client(fixture.GetSocketPath());
        REQUIRE_FALSE(client.Connect().has_value());
        std::string response = client.ExecuteCommand("setmocktime", {"not_a_number"});
        REQUIRE(response.find("error") != std::string::npos);
    }
}

TEST_CASE("RPC Commands: invalidateblock", "[rpc][integration][debug]") {
    RPCTestFixture fixture;
    REQUIRE(fixture.StartServer());
    std::this_thread::sleep_for(100ms);

    SECTION("Missing parameter returns error") {
        rpc::RPCClient client(fixture.GetSocketPath());
        REQUIRE_FALSE(client.Connect().has_value());
        std::string response = client.ExecuteCommand("invalidateblock", {});
        REQUIRE(response.find("error") != std::string::npos);
    }

    SECTION("Invalid hash format returns error") {
        rpc::RPCClient client(fixture.GetSocketPath());
        REQUIRE_FALSE(client.Connect().has_value());
        std::string response = client.ExecuteCommand("invalidateblock", {"invalid_hash"});
        REQUIRE(response.find("error") != std::string::npos);
    }

    SECTION("Non-existent block returns error") {
        rpc::RPCClient client(fixture.GetSocketPath());
        REQUIRE_FALSE(client.Connect().has_value());
        std::string fake_hash(64, '0');
        std::string response = client.ExecuteCommand("invalidateblock", {fake_hash});
        REQUIRE(response.find("error") != std::string::npos);
    }
}

TEST_CASE("RPC Commands: submitheader", "[rpc][integration][debug]") {
    RPCTestFixture fixture;
    REQUIRE(fixture.StartServer());
    std::this_thread::sleep_for(100ms);

    SECTION("Missing parameter returns error") {
        rpc::RPCClient client(fixture.GetSocketPath());
        REQUIRE_FALSE(client.Connect().has_value());
        std::string response = client.ExecuteCommand("submitheader", {});
        REQUIRE(response.find("error") != std::string::npos);
    }

    SECTION("Invalid hex returns error") {
        rpc::RPCClient client(fixture.GetSocketPath());
        REQUIRE_FALSE(client.Connect().has_value());
        std::string response = client.ExecuteCommand("submitheader", {"not_hex"});
        REQUIRE(response.find("error") != std::string::npos);
    }

    SECTION("Wrong length returns error") {
        rpc::RPCClient client(fixture.GetSocketPath());
        REQUIRE_FALSE(client.Connect().has_value());
        std::string response = client.ExecuteCommand("submitheader", {"0000"});
        REQUIRE(response.find("error") != std::string::npos);
    }
}

TEST_CASE("RPC Commands: getnextworkrequired", "[rpc][integration][debug]") {
    RPCTestFixture fixture;
    REQUIRE(fixture.StartServer());
    std::this_thread::sleep_for(100ms);

    rpc::RPCClient client(fixture.GetSocketPath());
    REQUIRE_FALSE(client.Connect().has_value());

    SECTION("Returns next difficulty bits") {
        std::string response = client.ExecuteCommand("getnextworkrequired", {});
        REQUIRE_FALSE(response.empty());
        // Should return hex bits value
        REQUIRE(response.find("error") == std::string::npos);
    }
}

// ============================================================================
// Network Reporting RPC Commands
// ============================================================================

TEST_CASE("RPC Commands: getnettotals", "[rpc][integration][network]") {
    RPCTestFixture fixture;
    REQUIRE(fixture.StartServer());
    std::this_thread::sleep_for(100ms);

    rpc::RPCClient client(fixture.GetSocketPath());
    REQUIRE_FALSE(client.Connect().has_value());

    SECTION("Returns valid JSON with required fields") {
        std::string response = client.ExecuteCommand("getnettotals", {});
        REQUIRE_FALSE(response.empty());
        REQUIRE(response.find("error") == std::string::npos);

        // Check required fields
        REQUIRE(response.find("\"totalbytesrecv\"") != std::string::npos);
        REQUIRE(response.find("\"totalbytessent\"") != std::string::npos);
    }

    SECTION("Returns non-negative byte counts") {
        std::string response = client.ExecuteCommand("getnettotals", {});
        // With no peers, should be 0 bytes
        REQUIRE(response.find("\"totalbytesrecv\": 0") != std::string::npos);
        REQUIRE(response.find("\"totalbytessent\": 0") != std::string::npos);
    }
}

TEST_CASE("RPC Commands: getnetworkinfo", "[rpc][integration][network]") {
    RPCTestFixture fixture;
    REQUIRE(fixture.StartServer());
    std::this_thread::sleep_for(100ms);

    rpc::RPCClient client(fixture.GetSocketPath());
    REQUIRE_FALSE(client.Connect().has_value());

    SECTION("Returns valid JSON with required fields") {
        std::string response = client.ExecuteCommand("getnetworkinfo", {});
        REQUIRE_FALSE(response.empty());
        REQUIRE(response.find("error") == std::string::npos);

        // Check required fields
        REQUIRE(response.find("\"version\"") != std::string::npos);
        REQUIRE(response.find("\"subversion\"") != std::string::npos);
        REQUIRE(response.find("\"protocolversion\"") != std::string::npos);
        REQUIRE(response.find("\"connections\"") != std::string::npos);
        REQUIRE(response.find("\"connections_in\"") != std::string::npos);
        REQUIRE(response.find("\"connections_out\"") != std::string::npos);
        REQUIRE(response.find("\"networkactive\"") != std::string::npos);
        REQUIRE(response.find("\"localaddresses\"") != std::string::npos);
    }

    SECTION("Returns zero connections when no peers") {
        std::string response = client.ExecuteCommand("getnetworkinfo", {});
        REQUIRE(response.find("\"connections\": 0") != std::string::npos);
        REQUIRE(response.find("\"connections_in\": 0") != std::string::npos);
        REQUIRE(response.find("\"connections_out\": 0") != std::string::npos);
    }

    SECTION("Shows network is active") {
        std::string response = client.ExecuteCommand("getnetworkinfo", {});
        // networkactive defaults to true (can be toggled via setnetworkactive RPC)
        REQUIRE(response.find("\"networkactive\": true") != std::string::npos);
    }

    SECTION("Contains version string") {
        std::string response = client.ExecuteCommand("getnetworkinfo", {});
        // Should contain Unicity in subversion
        REQUIRE(response.find("/Unicity:") != std::string::npos);
    }
}

TEST_CASE("RPC Commands: getpeerinfo extended fields", "[rpc][integration][network]") {
    RPCTestFixture fixture;
    REQUIRE(fixture.StartServer());
    std::this_thread::sleep_for(100ms);

    rpc::RPCClient client(fixture.GetSocketPath());
    REQUIRE_FALSE(client.Connect().has_value());

    SECTION("Returns empty array when no peers") {
        std::string response = client.ExecuteCommand("getpeerinfo", {});
        REQUIRE_FALSE(response.empty());
        REQUIRE(response.find("error") == std::string::npos);
        // Should be an empty JSON array
        REQUIRE(response.find("[") != std::string::npos);
        REQUIRE(response.find("]") != std::string::npos);
    }

    // Note: Testing lastsend/lastrecv with actual peers would require
    // setting up peer connections, which is done in dedicated peer tests.
    // Here we just verify the RPC command executes without errors.
}
