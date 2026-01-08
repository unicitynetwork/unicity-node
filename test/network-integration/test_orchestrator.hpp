#ifndef UNICITY_TEST_TEST_ORCHESTRATOR_HPP
#define UNICITY_TEST_TEST_ORCHESTRATOR_HPP

#include <chrono>
#include <functional>
#include <iostream>
#include <string>
#include "catch_amalgamated.hpp"
#include "infra/simulated_network.hpp"
#include "infra/simulated_node.hpp"

namespace unicity {
namespace test {

/**
 * TestOrchestrator - High-level coordinator for network tests
 * 
 * Solves common brittleness issues:
 * - Abstracts away AdvanceTime() loops
 * - Handles node_id → peer_id mapping automatically
 * - Provides readable assertions with helpful error messages
 * - Built-in retry logic for async operations
 * 
 * Usage:
 *   TestOrchestrator orchestrator(&network);
 *   orchestrator.WaitForConnection(victim, attacker);
 *   orchestrator.WaitForSync(victim, attacker, expected_height);
 *   orchestrator.AssertPeerDiscouraged(victim, attacker);
 */
class TestOrchestrator {
public:
    explicit TestOrchestrator(SimulatedNetwork* network)
        : network_(network), time_ms_(1) {
        // Align orchestrator clock with the network to avoid time going backwards
        if (network_) {
            uint64_t now = network_->GetCurrentTime();
            // Ensure we never use 0 (SetMockTime(0) disables mocking)
            time_ms_ = now > 0 ? now : 1;
        }
    }
    
    // ============= Connection Management =============
    
    /**
     * Wait for peer connection to complete
     * Handles async handshake, checks both sides
     */
    bool WaitForConnection(
        SimulatedNode& node_a,
        SimulatedNode& node_b,
        std::chrono::milliseconds timeout = std::chrono::seconds(5)
    );
    
    /**
     * Wait for specific peer count
     * Useful for checking disconnections
     */
    bool WaitForPeerCount(
        SimulatedNode& node,
        size_t expected_count,
        std::chrono::milliseconds timeout = std::chrono::seconds(5)
    );
    
    /**
     * Wait for peer to disconnect
     */
    bool WaitForDisconnect(
        SimulatedNode& victim,
        SimulatedNode& attacker,
        std::chrono::milliseconds timeout = std::chrono::seconds(5)
    );
    
    // ============= Synchronization =============
    
    /**
     * Wait for nodes to sync to same chain tip
     */
    bool WaitForSync(
        SimulatedNode& node_a,
        SimulatedNode& node_b,
        std::chrono::milliseconds timeout = std::chrono::seconds(10)
    );
    
    /**
     * Wait for node to reach specific height
     */
    bool WaitForHeight(
        SimulatedNode& node,
        int expected_height,
        std::chrono::milliseconds timeout = std::chrono::seconds(10)
    );
    
    /**
     * Wait for node to reach specific tip hash
     */
    bool WaitForTip(
        SimulatedNode& node,
        const uint256& expected_tip,
        std::chrono::milliseconds timeout = std::chrono::seconds(10)
    );
    
    // ============= Assertions =============
    
    /**
     * Assert peer is discouraged (with helpful error message)
     */
    void AssertPeerDiscouraged(SimulatedNode& victim, SimulatedNode& attacker);
    
    /**
     * Assert peer is NOT discouraged
     */
    void AssertPeerNotDiscouraged(SimulatedNode& victim, SimulatedNode& attacker);
    
    /**
     * Assert peer has minimum misbehavior score
     */
    void AssertMisbehaviorScore(
        SimulatedNode& victim,
        SimulatedNode& attacker,
        int min_score
    );
    
    /**
     * Assert connection count
     */
    void AssertPeerCount(SimulatedNode& node, size_t expected_count);
    
    /**
     * Assert chain height
     */
    void AssertHeight(SimulatedNode& node, int expected_height);
    
    /**
     * Assert chain tip
     */
    
    // ============= Helper Utilities =============
    
    /**
     * Get peer_id from ConnectionManager for a connected node
     * Returns -1 if not found
     */
    int GetPeerId(SimulatedNode& node, SimulatedNode& peer_node);
    
    /**
     * Advance time by specified duration
     * Automatically handles message processing
     */
    void AdvanceTime(std::chrono::milliseconds duration);
    
    /**
     * Get current simulation time
     */
    uint64_t GetCurrentTimeMs() const { return time_ms_; }
    
    /**
     * Run a condition check repeatedly until timeout
     * Returns true if condition met, false if timeout
     */
    bool WaitForCondition(
        std::function<bool()> condition,
        std::chrono::milliseconds timeout,
        std::chrono::milliseconds check_interval = std::chrono::milliseconds(100)
    );
    
    /**
     * Enable verbose logging for debugging
     */
    void SetVerbose(bool enabled) { verbose_ = enabled; }

private:
    SimulatedNetwork* network_;
    uint64_t time_ms_;
    bool verbose_ = false;
    
    // Helper: Log message if verbose enabled
    void Log(const std::string& message);
};

// ============= Implementation =============

inline bool TestOrchestrator::WaitForConnection(
    SimulatedNode& node_a,
    SimulatedNode& node_b,
    std::chrono::milliseconds timeout
) {
    Log("Waiting for connection between node " + std::to_string(node_a.GetId()) +
        " and node " + std::to_string(node_b.GetId()));
    
    return WaitForCondition(
        [&]() {
            // Check if both nodes see each other as connected
            return node_a.GetPeerCount() > 0 && node_b.GetPeerCount() > 0;
        },
        timeout
    );
}

inline bool TestOrchestrator::WaitForPeerCount(
    SimulatedNode& node,
    size_t expected_count,
    std::chrono::milliseconds timeout
) {
    Log("Waiting for node " + std::to_string(node.GetId()) +
        " to have " + std::to_string(expected_count) + " peers");
    
    return WaitForCondition(
        [&]() { return node.GetPeerCount() == expected_count; },
        timeout
    );
}

inline bool TestOrchestrator::WaitForDisconnect(
    SimulatedNode& victim,
    SimulatedNode& attacker,
    std::chrono::milliseconds timeout
) {
    Log("Waiting for node " + std::to_string(attacker.GetId()) +
        " to disconnect from node " + std::to_string(victim.GetId()));
    
    size_t initial_count = victim.GetPeerCount();
    
    return WaitForCondition(
        [&]() { return victim.GetPeerCount() < initial_count; },
        timeout
    );
}

inline bool TestOrchestrator::WaitForSync(
    SimulatedNode& node_a,
    SimulatedNode& node_b,
    std::chrono::milliseconds timeout
) {
    Log("Waiting for sync between node " + std::to_string(node_a.GetId()) +
        " and node " + std::to_string(node_b.GetId()));
    
    return WaitForCondition(
        [&]() {
            return node_a.GetTipHash() == node_b.GetTipHash() &&
                   node_a.GetTipHeight() == node_b.GetTipHeight();
        },
        timeout
    );
}

inline bool TestOrchestrator::WaitForHeight(
    SimulatedNode& node,
    int expected_height,
    std::chrono::milliseconds timeout
) {
    Log("Waiting for node " + std::to_string(node.GetId()) +
        " to reach height " + std::to_string(expected_height));
    
    return WaitForCondition(
        [&]() { return node.GetTipHeight() == expected_height; },
        timeout
    );
}

inline bool TestOrchestrator::WaitForTip(
    SimulatedNode& node,
    const uint256& expected_tip,
    std::chrono::milliseconds timeout
) {
    Log("Waiting for node " + std::to_string(node.GetId()) +
        " to reach specific tip");
    
    return WaitForCondition(
        [&]() { return node.GetTipHash() == expected_tip; },
        timeout
    );
}

inline void TestOrchestrator::AssertPeerDiscouraged(
    SimulatedNode& victim,
    SimulatedNode& attacker
) {
    bool discouraged = victim.GetNetworkManager().peer_manager().IsDiscouraged(attacker.GetAddress());

    INFO("Node " << victim.GetId() << " should discourage node " << attacker.GetId());
    INFO("Attacker address: " << attacker.GetAddress());
    INFO("Discouraged: " << (discouraged ? "YES" : "NO"));

    REQUIRE(discouraged);
}

inline void TestOrchestrator::AssertPeerNotDiscouraged(
    SimulatedNode& victim,
    SimulatedNode& attacker
) {
    bool discouraged = victim.GetNetworkManager().peer_manager().IsDiscouraged(attacker.GetAddress());

    INFO("Node " << victim.GetId() << " should NOT discourage node " << attacker.GetId());
    INFO("Attacker address: " << attacker.GetAddress());
    INFO("Discouraged: " << (discouraged ? "YES" : "NO"));

    REQUIRE_FALSE(discouraged);
}

inline void TestOrchestrator::AssertMisbehaviorScore(
    SimulatedNode& victim,
    SimulatedNode& attacker,
    int /* min_score - ignored, kept for API compatibility */
) {
    int peer_id = GetPeerId(victim, attacker);

    INFO("Checking misbehavior status for node " << attacker.GetId() <<
         " (peer_id=" << peer_id << ") on node " << victim.GetId());

    if (peer_id < 0) {
        FAIL("Could not find peer_id for attacker node " << attacker.GetId() <<
             " in victim node " << victim.GetId() << " peer list");
    }

    auto& peer_manager = victim.GetNetworkManager().peer_manager();
    bool misbehaving = peer_manager.ShouldDisconnect(peer_id);

    INFO("Misbehaving: " << (misbehaving ? "YES" : "NO"));

    // With modern Core parity, any misbehavior = instant discourage
    // So if the test expected a score, it should now expect misbehaving=true
    REQUIRE(misbehaving);
}

inline void TestOrchestrator::AssertPeerCount(
    SimulatedNode& node,
    size_t expected_count
) {
    size_t actual_count = node.GetPeerCount();
    
    INFO("Node " << node.GetId() << " peer count");
    INFO("Expected: " << expected_count);
    INFO("Actual: " << actual_count);
    
    REQUIRE(actual_count == expected_count);
}

inline void TestOrchestrator::AssertHeight(
    SimulatedNode& node,
    int expected_height
) {
    int actual_height = node.GetTipHeight();
    
    INFO("Node " << node.GetId() << " chain height");
    INFO("Expected: " << expected_height);
    INFO("Actual: " << actual_height);
    
    REQUIRE(actual_height == expected_height);
}

inline int TestOrchestrator::GetPeerId(SimulatedNode& node, SimulatedNode& peer_node) {
    auto& peer_manager = node.GetNetworkManager().peer_manager();
    auto peers = peer_manager.get_all_peers();
    
    // Find peer by matching address
    for (const auto& peer : peers) {
        if (peer->address() == peer_node.GetAddress()) {
            return peer->id();
        }
    }
    
    return -1; // Not found
}

inline void TestOrchestrator::AdvanceTime(std::chrono::milliseconds duration) {
    // Prevent time from going backwards relative to the network's clock.
    // Also ensure we always advance at least by 1ms beyond the current network time.
    uint64_t target = time_ms_ + static_cast<uint64_t>(duration.count());
    uint64_t net_now = network_ ? network_->GetCurrentTime() : 0;
    if (target <= net_now) {
        target = net_now + 1;
    }
    time_ms_ = target;
    network_->AdvanceTime(time_ms_);
}

inline bool TestOrchestrator::WaitForCondition(
    std::function<bool()> condition,
    std::chrono::milliseconds timeout,
    std::chrono::milliseconds check_interval
) {
    auto start_time = time_ms_;
    auto timeout_ms = timeout.count();
    
    while (time_ms_ - start_time < static_cast<uint64_t>(timeout_ms)) {
        if (condition()) {
            Log("Condition met after " + std::to_string(time_ms_ - start_time) + "ms");
            return true;
        }
        
        AdvanceTime(check_interval);
    }
    
    Log("Condition NOT met after timeout " + std::to_string(timeout_ms) + "ms");
    return false;
}

inline void TestOrchestrator::Log(const std::string& message) {
    if (verbose_) {
        std::cout << "[TestOrchestrator @ " << time_ms_ << "ms] " << message << std::endl;
    }
}

} // namespace test
} // namespace unicity

#endif // UNICITY_TEST_TEST_ORCHESTRATOR_HPP
