// Copyright (c) 2025 The Unicity Foundation
// DoS: Unknown command rate limiting tests
//
// Tests the protection against excessive unknown command spam.
// Attack: Send >20 unknown commands in 60s to overwhelm logs/node
// Defense: Rate limit unknown commands, disconnect after threshold

#include "catch_amalgamated.hpp"
#include "infra/simulated_network.hpp"
#include "infra/simulated_node.hpp"
#include "test_orchestrator.hpp"
#include "network/message.hpp"
#include "network/protocol.hpp"
#include "util/hash.hpp"
#include "chain/chainparams.hpp"

using namespace unicity;
using namespace unicity::test;

static struct TestSetup {
    TestSetup() { chain::GlobalChainParams::Select(chain::ChainType::REGTEST); }
} test_setup_unknown_cmd;

namespace {

// Send a message with unknown command
void SendUnknownCommand(SimulatedNetwork& network, int from_id, int to_id,
                        const std::string& command = "foobar99") {
    // Empty payload for unknown command
    std::vector<uint8_t> payload;

    protocol::MessageHeader header(protocol::magic::REGTEST, command,
        static_cast<uint32_t>(payload.size()));

    // Compute checksum (empty payload hash)
    uint256 hash = Hash(payload);
    std::memcpy(header.checksum.data(), hash.begin(), 4);

    auto header_bytes = message::serialize_header(header);

    std::vector<uint8_t> full;
    full.reserve(header_bytes.size() + payload.size());
    full.insert(full.end(), header_bytes.begin(), header_bytes.end());
    full.insert(full.end(), payload.begin(), payload.end());

    network.SendMessage(from_id, to_id, full);
}

} // namespace

TEST_CASE("DoS: Unknown command rate limit - constants verification", "[dos][network][unknown-cmd][unit]") {
    SECTION("Verify rate limit constants") {
        REQUIRE(protocol::MAX_UNKNOWN_COMMANDS_PER_MINUTE == 20);
        INFO("Unknown command rate limit: 20 per 60 seconds");
    }
}

TEST_CASE("DoS: Unknown command rate limit - under threshold accepted", "[dos][network][unknown-cmd]") {
    SimulatedNetwork network(5000);
    TestOrchestrator orch(&network);

    SimulatedNode victim(1, &network);
    SimulatedNode attacker(2, &network);

    REQUIRE(attacker.ConnectTo(1));
    REQUIRE(orch.WaitForConnection(victim, attacker));

    SECTION("Few unknown commands - remains connected") {
        // Send 5 unknown commands (well under threshold of 20)
        for (int i = 0; i < 5; i++) {
            SendUnknownCommand(network, 2, 1, "unknwn" + std::to_string(i));
            orch.AdvanceTime(std::chrono::milliseconds(50));
        }

        orch.AdvanceTime(std::chrono::seconds(1));

        // Should still be connected
        CHECK(victim.GetPeerCount() >= 1);
    }
}

TEST_CASE("DoS: Unknown command rate limit - at threshold boundary", "[dos][network][unknown-cmd]") {
    SimulatedNetwork network(5001);
    TestOrchestrator orch(&network);

    SimulatedNode victim(1, &network);
    SimulatedNode attacker(2, &network);

    REQUIRE(attacker.ConnectTo(1));
    REQUIRE(orch.WaitForConnection(victim, attacker));

    SECTION("Exactly at threshold - still connected") {
        // Send exactly 20 unknown commands (at threshold)
        for (int i = 0; i < 20; i++) {
            SendUnknownCommand(network, 2, 1, "unk" + std::to_string(i));
            orch.AdvanceTime(std::chrono::milliseconds(10));
        }

        orch.AdvanceTime(std::chrono::seconds(1));

        // At threshold should still be connected (>20 disconnects)
        CHECK(victim.GetPeerCount() >= 1);
    }
}

TEST_CASE("DoS: Unknown command rate limit - exceeds threshold disconnects", "[dos][network][unknown-cmd]") {
    SimulatedNetwork network(5002);
    TestOrchestrator orch(&network);

    SimulatedNode victim(1, &network);
    SimulatedNode attacker(2, &network);

    REQUIRE(attacker.ConnectTo(1));
    REQUIRE(orch.WaitForConnection(victim, attacker));

    SECTION("Over threshold - disconnected") {
        // Send 25 unknown commands (over threshold of 20)
        for (int i = 0; i < 25; i++) {
            SendUnknownCommand(network, 2, 1, "spam" + std::to_string(i % 10));
            orch.AdvanceTime(std::chrono::milliseconds(10));
        }

        orch.AdvanceTime(std::chrono::seconds(1));

        // Should be disconnected
        CHECK(orch.WaitForPeerCount(victim, 0, std::chrono::seconds(2)));
    }
}

TEST_CASE("DoS: Unknown command rate limit - rapid spam triggers disconnect", "[dos][network][unknown-cmd]") {
    SimulatedNetwork network(5003);
    TestOrchestrator orch(&network);

    SimulatedNode victim(1, &network);
    SimulatedNode attacker(2, &network);

    REQUIRE(attacker.ConnectTo(1));
    REQUIRE(orch.WaitForConnection(victim, attacker));

    SECTION("Rapid unknown command spam - disconnect") {
        // Send 50 unknown commands rapidly
        for (int i = 0; i < 50; i++) {
            SendUnknownCommand(network, 2, 1, "attack" + std::to_string(i % 5));
        }

        orch.AdvanceTime(std::chrono::seconds(2));

        // Should be disconnected after exceeding threshold
        CHECK(victim.GetPeerCount() == 0);
    }
}

TEST_CASE("DoS: Unknown command rate limit - window reset", "[dos][network][unknown-cmd]") {
    SimulatedNetwork network(5004);
    TestOrchestrator orch(&network);

    SimulatedNode victim(1, &network);
    SimulatedNode attacker(2, &network);

    REQUIRE(attacker.ConnectTo(1));
    REQUIRE(orch.WaitForConnection(victim, attacker));

    SECTION("Counter resets after 60 seconds") {
        // Send 15 unknown commands (under threshold)
        for (int i = 0; i < 15; i++) {
            SendUnknownCommand(network, 2, 1, "cmd" + std::to_string(i));
            orch.AdvanceTime(std::chrono::milliseconds(10));
        }

        // Should still be connected
        orch.AdvanceTime(std::chrono::seconds(1));
        REQUIRE(victim.GetPeerCount() >= 1);

        // Advance past 60 second window
        orch.AdvanceTime(std::chrono::seconds(61));

        // Send another 15 - counter should have reset
        for (int i = 0; i < 15; i++) {
            SendUnknownCommand(network, 2, 1, "new" + std::to_string(i));
            orch.AdvanceTime(std::chrono::milliseconds(10));
        }

        orch.AdvanceTime(std::chrono::seconds(1));

        // Should still be connected (counter reset)
        CHECK(victim.GetPeerCount() >= 1);
    }
}

TEST_CASE("DoS: Unknown command rate limit - multiple attackers", "[dos][network][unknown-cmd]") {
    SimulatedNetwork network(5005);
    TestOrchestrator orch(&network);

    SimulatedNode victim(1, &network);
    SimulatedNode attacker1(2, &network);
    SimulatedNode attacker2(3, &network);

    REQUIRE(attacker1.ConnectTo(1));
    REQUIRE(attacker2.ConnectTo(1));
    REQUIRE(orch.WaitForPeerCount(victim, 2));

    SECTION("Each peer has independent counter") {
        // Attacker1 sends 10 unknown commands
        for (int i = 0; i < 10; i++) {
            SendUnknownCommand(network, 2, 1, "atk1_" + std::to_string(i));
            orch.AdvanceTime(std::chrono::milliseconds(10));
        }

        // Attacker2 sends 10 unknown commands
        for (int i = 0; i < 10; i++) {
            SendUnknownCommand(network, 3, 1, "atk2_" + std::to_string(i));
            orch.AdvanceTime(std::chrono::milliseconds(10));
        }

        orch.AdvanceTime(std::chrono::seconds(1));

        // Both should still be connected (each under threshold)
        CHECK(victim.GetPeerCount() == 2);

        // Now attacker1 exceeds threshold
        for (int i = 0; i < 15; i++) {
            SendUnknownCommand(network, 2, 1, "spam_" + std::to_string(i));
            orch.AdvanceTime(std::chrono::milliseconds(10));
        }

        orch.AdvanceTime(std::chrono::seconds(1));

        // Attacker1 disconnected, attacker2 still connected
        CHECK(victim.GetPeerCount() == 1);
    }
}

TEST_CASE("DoS: Unknown command rate limit - mixed valid/unknown", "[dos][network][unknown-cmd]") {
    SimulatedNetwork network(5006);
    TestOrchestrator orch(&network);

    SimulatedNode victim(1, &network);
    SimulatedNode attacker(2, &network);

    REQUIRE(attacker.ConnectTo(1));
    REQUIRE(orch.WaitForConnection(victim, attacker));

    SECTION("Valid commands don't affect unknown counter") {
        // Send 15 unknown commands
        for (int i = 0; i < 15; i++) {
            SendUnknownCommand(network, 2, 1, "unk" + std::to_string(i));
            orch.AdvanceTime(std::chrono::milliseconds(10));
        }

        // Send valid PING messages
        for (int i = 0; i < 10; i++) {
            auto ping = std::make_unique<message::PingMessage>(i);
            auto payload = ping->serialize();

            protocol::MessageHeader header(protocol::magic::REGTEST,
                protocol::commands::PING, static_cast<uint32_t>(payload.size()));
            uint256 hash = Hash(payload);
            std::memcpy(header.checksum.data(), hash.begin(), 4);
            auto header_bytes = message::serialize_header(header);

            std::vector<uint8_t> full;
            full.insert(full.end(), header_bytes.begin(), header_bytes.end());
            full.insert(full.end(), payload.begin(), payload.end());

            network.SendMessage(2, 1, full);
            orch.AdvanceTime(std::chrono::milliseconds(10));
        }

        orch.AdvanceTime(std::chrono::seconds(1));

        // Should still be connected (15 unknown + 10 valid = still under 20 unknown)
        CHECK(victim.GetPeerCount() >= 1);

        // Now exceed unknown threshold
        for (int i = 0; i < 10; i++) {
            SendUnknownCommand(network, 2, 1, "more" + std::to_string(i));
            orch.AdvanceTime(std::chrono::milliseconds(10));
        }

        orch.AdvanceTime(std::chrono::seconds(1));

        // Now should be disconnected (25 unknown > 20)
        CHECK(victim.GetPeerCount() == 0);
    }
}
