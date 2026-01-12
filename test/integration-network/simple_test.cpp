// Simple test to verify test2 framework builds and runs

#include "test_helper.hpp"
#include "test_orchestrator.hpp"
#include "network_observer.hpp"

using namespace unicity;
using namespace unicity::test;

TEST_CASE("Simple connectivity test", "[simple][network]") {
    SimulatedNetwork network(42);
    TestOrchestrator orchestrator(&network);
    
    SimulatedNode node1(1, &network);
    SimulatedNode node2(2, &network);
    
    // Connect nodes
    node2.ConnectTo(1);
    
    // Wait for connection
    REQUIRE(orchestrator.WaitForConnection(node1, node2, std::chrono::seconds(3)));
    
    // Verify peer counts
    orchestrator.AssertPeerCount(node1, 1);
    orchestrator.AssertPeerCount(node2, 1);
}

TEST_CASE("Simple mining and sync test", "[simple][network]") {
    SimulatedNetwork network(123);
    TestOrchestrator orchestrator(&network);
    
    SimulatedNode node1(1, &network);
    SimulatedNode node2(2, &network);
    
    // Mine some blocks on node1
    for (int i = 0; i < 5; i++) {
        node1.MineBlock();
    }
    
    orchestrator.AssertHeight(node1, 5);
    
    // Connect and sync
    node2.ConnectTo(1);
    REQUIRE(orchestrator.WaitForConnection(node1, node2));
    REQUIRE(orchestrator.WaitForSync(node1, node2, std::chrono::seconds(5)));
    
    // Both should have same height
    orchestrator.AssertHeight(node2, 5);
}
