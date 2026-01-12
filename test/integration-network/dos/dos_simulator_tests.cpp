// DoS Attack Simulator Tests
// Verifies the unified DoS attack testing infrastructure works correctly

#include "catch_amalgamated.hpp"
#include "infra/dos_attack_simulator.hpp"
#include "infra/simulated_network.hpp"
#include "infra/simulated_node.hpp"
#include "infra/node_simulator.hpp"
#include "infra/peer_factory.hpp"
#include "chain/chainparams.hpp"

using namespace unicity;
using namespace unicity::test;

static struct TestSetup {
    TestSetup() { chain::GlobalChainParams::Select(chain::ChainType::REGTEST); }
} test_setup_dos_sim;

TEST_CASE("DoSAttackSimulator - Message flood triggers buffer overflow", "[dos][simulator]") {
    SimulatedNetwork network(42);

    // Fast network for quicker tests
    SimulatedNetwork::NetworkConditions fast;
    fast.latency_min = std::chrono::milliseconds(0);
    fast.latency_max = std::chrono::milliseconds(1);
    fast.bandwidth_bytes_per_sec = 0;  // unlimited
    network.SetNetworkConditions(fast);

    SimulatedNode victim(1, &network);
    SimulatedNode attacker(2, &network);

    DoSAttackSimulator sim(&network, &victim);

    // Connect attacker
    REQUIRE(attacker.ConnectTo(1));
    TestOrchestrator orch(&network);
    REQUIRE(orch.WaitForConnection(victim, attacker));

    // Execute message flood attack
    auto result = sim.SendMessageFlood(attacker, 30, 256 * 1024, 1024 * 1024);

    INFO(sim.GenerateReport());

    // Buffer overflow should trigger disconnect
    CHECK(result.triggered_disconnect);
    CHECK(result.defense_triggered == "recv_buffer_overflow");
    CHECK(result.messages_sent == 30);
}

TEST_CASE("DoSAttackSimulator - Invalid PoW triggers discourage", "[dos][simulator]") {
    SimulatedNetwork network(43);
    SimulatedNode victim(1, &network);
    NodeSimulator attacker(2, &network);

    DoSAttackSimulator sim(&network, &victim);

    // Build victim chain
    sim.BuildVictimChain(10);

    // Connect and sync
    REQUIRE(sim.ConnectAndSync(attacker));

    // Send invalid PoW headers
    auto result = sim.SendInvalidPoWHeaders(attacker, 1);

    INFO(sim.GenerateReport());

    // Invalid PoW should trigger discourage and disconnect
    CHECK(result.peer_discouraged);
    CHECK(result.triggered_disconnect);
    CHECK(result.victim_chain_intact);
    CHECK(result.victim_height_before == 10);
    CHECK(result.victim_height_after == 10);
}

TEST_CASE("DoSAttackSimulator - Low work headers silently ignored", "[dos][simulator]") {
    SimulatedNetwork network(44);
    SimulatedNode victim(1, &network);
    NodeSimulator attacker(2, &network);

    DoSAttackSimulator sim(&network, &victim);

    // Build victim chain
    sim.BuildVictimChain(10);

    // Connect and sync
    REQUIRE(sim.ConnectAndSync(attacker));

    // Send low-work headers (should be ignored, not penalized)
    auto result = sim.SendLowWorkHeaders(attacker, 20, 10);

    INFO(sim.GenerateReport());

    // Low-work headers should be silently ignored
    CHECK_FALSE(result.triggered_disconnect);
    CHECK_FALSE(result.peer_discouraged);
    CHECK(result.defense_triggered == "silent_ignore");
    CHECK(result.victim_chain_intact);
}

TEST_CASE("DoSAttackSimulator - Report generation", "[dos][simulator]") {
    SimulatedNetwork network(45);
    SimulatedNode victim(1, &network);
    SimulatedNode attacker(2, &network);

    DoSAttackSimulator sim(&network, &victim);

    // Connect
    REQUIRE(attacker.ConnectTo(1));
    TestOrchestrator orch(&network);
    REQUIRE(orch.WaitForConnection(victim, attacker));

    // Small flood (won't trigger disconnect but will generate report)
    sim.SendMessageFlood(attacker, 5, 1024);

    std::string report = sim.GenerateReport();

    // Verify report contains key sections
    CHECK(report.find("DoS ATTACK SIMULATION REPORT") != std::string::npos);
    CHECK(report.find("Attack Type:") != std::string::npos);
    CHECK(report.find("Defense Response") != std::string::npos);
    CHECK(report.find("Victim State") != std::string::npos);
    CHECK(report.find("Verdict") != std::string::npos);

    INFO(report);
}

TEST_CASE("DoSAttackSimulator - Pre-built profiles", "[dos][simulator]") {
    SimulatedNetwork network(46);

    SimulatedNetwork::NetworkConditions fast;
    fast.latency_min = std::chrono::milliseconds(0);
    fast.latency_max = std::chrono::milliseconds(1);
    fast.bandwidth_bytes_per_sec = 0;
    network.SetNetworkConditions(fast);

    SimulatedNode victim(1, &network);

    SECTION("Buffer overflow profile") {
        SimulatedNode attacker(2, &network);
        DoSAttackSimulator sim(&network, &victim);

        REQUIRE(attacker.ConnectTo(1));
        TestOrchestrator orch(&network);
        REQUIRE(orch.WaitForConnection(victim, attacker));

        auto result = DoSProfiles::TestBufferOverflow(sim, attacker);

        INFO(sim.GenerateReport());
        CHECK(result.triggered_disconnect);
    }

    SECTION("Invalid PoW profile") {
        NodeSimulator attacker(2, &network);
        DoSAttackSimulator sim(&network, &victim);

        sim.BuildVictimChain(10);
        REQUIRE(sim.ConnectAndSync(attacker));

        auto result = DoSProfiles::TestInvalidPoW(sim, attacker);

        INFO(sim.GenerateReport());
        CHECK(result.peer_discouraged);
    }
}
