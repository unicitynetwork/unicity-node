// Connection metrics tests: verify attempt/success/failure counting

#include "catch_amalgamated.hpp"
#include "infra/simulated_network.hpp"
#include "infra/simulated_node.hpp"
#include "test_orchestrator.hpp"
#include "chain/chainparams.hpp"

using namespace unicity;
using namespace unicity::chain;
using namespace unicity::test;

static struct TestSetup {
    TestSetup() { chain::GlobalChainParams::Select(chain::ChainType::REGTEST); }
} test_setup_metrics;

TEST_CASE("Connection metrics: successful outbound connection", "[network][peer][metrics]") {
    SimulatedNetwork network(5001);
    TestOrchestrator orch(&network);

    SimulatedNode node1(1, &network);
    SimulatedNode node2(2, &network);

    auto& manager = node1.GetNetworkManager().peer_manager();

    // Record initial metrics
    uint64_t initial_attempts = manager.GetOutboundAttempts();
    uint64_t initial_successes = manager.GetOutboundSuccesses();
    uint64_t initial_failures = manager.GetOutboundFailures();

    // Connect node1 -> node2
    REQUIRE(node1.ConnectTo(node2.GetId()));

    // Wait for connection (peer objects exist)
    REQUIRE(orch.WaitForConnection(node1, node2));

    // Advance time to allow VERACK handshake to complete
    // (Success counter is incremented AFTER VERACK, not when peer object is created)
    for (int i = 0; i < 50; ++i) {
        orch.AdvanceTime(std::chrono::milliseconds(100));
    }

    // Verify metrics: 1 attempt, 1 success, 0 failures
    CHECK(manager.GetOutboundAttempts() == initial_attempts + 1);
    CHECK(manager.GetOutboundSuccesses() == initial_successes + 1);
    CHECK(manager.GetOutboundFailures() == initial_failures);

    // Verify invariant: attempts == successes + failures
    CHECK(manager.GetOutboundAttempts() ==
          manager.GetOutboundSuccesses() + manager.GetOutboundFailures());
}

TEST_CASE("Connection metrics: multiple successful connections", "[network][peer][metrics]") {
    SimulatedNetwork network(5002);
    TestOrchestrator orch(&network);

    SimulatedNode node1(1, &network);
    SimulatedNode node2(2, &network);
    SimulatedNode node3(3, &network);
    SimulatedNode node4(4, &network);

    auto& manager = node1.GetNetworkManager().peer_manager();

    // Record initial metrics
    uint64_t initial_attempts = manager.GetOutboundAttempts();
    uint64_t initial_successes = manager.GetOutboundSuccesses();

    // Connect to 3 peers
    REQUIRE(node1.ConnectTo(node2.GetId()));
    REQUIRE(node1.ConnectTo(node3.GetId()));
    REQUIRE(node1.ConnectTo(node4.GetId()));

    // Wait for all connections
    REQUIRE(orch.WaitForConnection(node1, node2));
    REQUIRE(orch.WaitForConnection(node1, node3));
    REQUIRE(orch.WaitForConnection(node1, node4));

    // Advance time to allow all VERACK handshakes to complete
    for (int i = 0; i < 100; ++i) {
        orch.AdvanceTime(std::chrono::milliseconds(100));
    }

    // Verify metrics: 3 attempts, 3 successes
    CHECK(manager.GetOutboundAttempts() == initial_attempts + 3);
    CHECK(manager.GetOutboundSuccesses() == initial_successes + 3);

    // Verify invariant
    CHECK(manager.GetOutboundAttempts() ==
          manager.GetOutboundSuccesses() + manager.GetOutboundFailures());
}

TEST_CASE("Connection metrics: invariant holds", "[network][peer][metrics]") {
    // Regression test for bug where attempts < successes due to double-counting
    SimulatedNetwork network(5003);
    TestOrchestrator orch(&network);

    SimulatedNode node1(1, &network);
    SimulatedNode node2(2, &network);
    SimulatedNode node3(3, &network);

    auto& manager = node1.GetNetworkManager().peer_manager();

    // Make several connections
    for (int i = 0; i < 5; ++i) {
        if (i % 2 == 0) {
            node1.ConnectTo(node2.GetId());
            orch.WaitForConnection(node1, node2);
        } else {
            node1.ConnectTo(node3.GetId());
            orch.WaitForConnection(node1, node3);
        }

        // Advance time for VERACK
        for (int j = 0; j < 50; ++j) {
            orch.AdvanceTime(std::chrono::milliseconds(10));
        }

        // Check invariant after each connection
        uint64_t attempts = manager.GetOutboundAttempts();
        uint64_t successes = manager.GetOutboundSuccesses();
        uint64_t failures = manager.GetOutboundFailures();

        // The bug manifested as successes > attempts
        REQUIRE(successes <= attempts);
        REQUIRE(attempts == successes + failures);
    }
}
