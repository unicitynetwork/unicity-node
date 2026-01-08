// Debug version of scale test to diagnose failures
#include "catch_amalgamated.hpp"
#include "infra/simulated_network.hpp"
#include "infra/simulated_node.hpp"
#include <memory>
#include <iostream>
#include <map>

using namespace unicity;
using namespace unicity::test;

static void SetZeroLatency(SimulatedNetwork& network) {
    SimulatedNetwork::NetworkConditions c;
    c.latency_min = c.latency_max = std::chrono::milliseconds(0);
    c.jitter_max = std::chrono::milliseconds(0);
    network.SetNetworkConditions(c);
}

TEST_CASE("ScaleTest - Debug Small Network", "[scale_debug]") {
    std::cout << "\n=== Testing with 10 nodes first ===" << std::endl;

    SimulatedNetwork network(28003);
    SetZeroLatency(network);
    std::vector<std::unique_ptr<SimulatedNode>> nodes;

    // Create 10 nodes
    for (int i = 0; i < 10; i++) {
        nodes.push_back(std::make_unique<SimulatedNode>(i+1, &network));
    }

    // Connect each node to 3-4 random peers
    for (size_t i = 0; i < nodes.size(); i++) {
        for (int j = 0; j < 3; j++) {
            int peer_id = 1 + (rand() % 10);
            if (peer_id != static_cast<int>(i+1)) {
                nodes[i]->ConnectTo(peer_id);
            }
        }
    }

    std::cout << "Waiting for connections to establish..." << std::endl;
    uint64_t t = 5000;
    network.AdvanceTime(t);

    // Check connections
    std::cout << "\n=== Initial Connection State ===" << std::endl;
    for (size_t i = 0; i < nodes.size(); i++) {
        std::cout << "Node " << (i+1) << " has " << nodes[i]->GetPeerCount() << " peers, height=" << nodes[i]->GetTipHeight() << std::endl;
    }

    // Node 0 mines a block
    std::cout << "\n=== Node 1 mining block ===" << std::endl;
    auto block = nodes[0]->MineBlock();
    std::cout << "Block hash: " << block.ToString().substr(0, 16) << std::endl;
    std::cout << "Node 1 height after mining: " << nodes[0]->GetTipHeight() << std::endl;

    // Propagate
    std::cout << "\n=== Advancing time for propagation ===" << std::endl;
    t += 10000;
    network.AdvanceTime(t);

    // Check results
    std::cout << "\n=== Final Heights ===" << std::endl;
    int synced = 0;
    for (size_t i = 0; i < nodes.size(); i++) {
        int height = nodes[i]->GetTipHeight();
        std::cout << "Node " << (i+1) << ": height=" << height << ", peers=" << nodes[i]->GetPeerCount() << std::endl;
        if (height >= 1) synced++;
    }

    std::cout << "\nSynced: " << synced << " / 10" << std::endl;
    std::cout << "Expected: > 8" << std::endl;

    CHECK(synced > 8);
}

TEST_CASE("ScaleTest - Debug Propagation Path", "[scale_debug]") {
    std::cout << "\n=== Testing linear propagation (5 nodes in chain) ===" << std::endl;

    SimulatedNetwork network(28004);
    SetZeroLatency(network);
    std::vector<std::unique_ptr<SimulatedNode>> nodes;

    // Create 5 nodes
    for (int i = 0; i < 5; i++) {
        nodes.push_back(std::make_unique<SimulatedNode>(i+1, &network));
    }

    // Connect in a chain: 1->2->3->4->5
    std::cout << "Connecting in chain: 1->2->3->4->5" << std::endl;
    nodes[0]->ConnectTo(2); // 1 -> 2
    nodes[1]->ConnectTo(3); // 2 -> 3
    nodes[2]->ConnectTo(4); // 3 -> 4
    nodes[3]->ConnectTo(5); // 4 -> 5

    uint64_t t = 5000;
    network.AdvanceTime(t);

    // Check initial state
    std::cout << "\n=== Initial State ===" << std::endl;
    for (size_t i = 0; i < nodes.size(); i++) {
        std::cout << "Node " << (i+1) << " has " << nodes[i]->GetPeerCount() << " peers" << std::endl;
    }

    // Node 1 mines
    std::cout << "\n=== Node 1 mining ===" << std::endl;
    nodes[0]->MineBlock();
    std::cout << "Node 1 height: " << nodes[0]->GetTipHeight() << std::endl;

    // Propagate step by step
    for (int step = 0; step < 5; step++) {
        t += 2000;
        network.AdvanceTime(t);
        std::cout << "\n=== After " << ((step+1)*2) << "s ===" << std::endl;
        for (size_t i = 0; i < nodes.size(); i++) {
            std::cout << "Node " << (i+1) << " height=" << nodes[i]->GetTipHeight() << std::endl;
        }
    }

    int synced = 0;
    for (const auto& n : nodes) {
        if (n->GetTipHeight() >= 1) synced++;
    }

    std::cout << "\nFinal: " << synced << " / 5 synced" << std::endl;
    CHECK(synced == 5);
}
