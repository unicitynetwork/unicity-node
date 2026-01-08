#ifndef UNICITY_TEST_SIMULATED_NETWORK_HPP
#define UNICITY_TEST_SIMULATED_NETWORK_HPP

#include <vector>
#include <queue>
#include <map>
#include <set>
#include <memory>
#include <chrono>
#include <functional>
#include <random>
#include <tuple>
#include <sstream>
#include "network/message.hpp"

namespace unicity {
namespace test {

// Forward declaration
class NetworkBridgedTransport;

/**
 * SimulatedNetwork - In-memory P2P network simulator
 *
 * Replaces TCP sockets with in-memory message passing.
 * Supports:
 * - Simulated latency
 * - Packet loss
 * - Bandwidth limits
 * - Network partitions
 * - Deterministic delivery
 *
 * IMPORTANT: Time Advancement Best Practices
 * ===========================================
 * When using simulated latency, advance time in SMALL, GRADUAL increments
 * (e.g., 200ms steps in a loop), NOT in large jumps.
 *
 * Messages are queued with: delivery_time = current_time_ms + latency
 *
 * If you skip ahead (e.g., AdvanceTime(5000)), response messages sent during
 * processing will be queued relative to the NEW current time, potentially
 * placing them far in the future and breaking message chains.
 *
 * Example:
 *   // WRONG - skips ahead, breaks message chains
 *   network.AdvanceTime(5000);
 *
 *   // CORRECT - gradual advancement allows natural message flow
 *   for (int i = 0; i < 25; i++) {
 *       time_ms += 200;
 *       network.AdvanceTime(time_ms);
 *   }
 */
class SimulatedNetwork {
public:
    struct NetworkConditions {
        // Latency range (uniform random between min/max)
        std::chrono::milliseconds latency_min{1};
        std::chrono::milliseconds latency_max{50};

        // Packet loss rate (0.0 to 1.0)
        double packet_loss_rate{0.0};

        // Bandwidth limit (bytes per second, 0 = unlimited)
        size_t bandwidth_bytes_per_sec{0};

        // Jitter (additional random delay)
        std::chrono::milliseconds jitter_max{10};
    };

    struct PendingMessage {
        int from_node;
        int to_node;
        std::vector<uint8_t> data;
        uint64_t delivery_time_ms;  // When to deliver this message
        size_t bytes;
        uint64_t sequence_number;   // For stable ordering when delivery_time is equal
    };

    SimulatedNetwork(uint64_t seed = 0);
    ~SimulatedNetwork();

    // Set network conditions (applies to all nodes)
    void SetNetworkConditions(const NetworkConditions& conditions);

    // Set per-link conditions (from_node -> to_node)
    void SetLinkConditions(int from_node, int to_node, const NetworkConditions& conditions);

    // Send a message (posts to delivery queue)
    void SendMessage(int from_node, int to_node, const std::vector<uint8_t>& data);

    // Track a new connection
    void RegisterConnection(int from_node, int to_node);

    // Notify a node that a peer has disconnected
    // This will also purge all queued messages between these nodes
    void NotifyDisconnect(int from_node, int to_node);

    // Process all messages ready for delivery at current_time_ms
    // Returns number of messages delivered
    size_t ProcessMessages(uint64_t current_time_ms);

    // Advance time and process all messages up to new_time_ms
    size_t AdvanceTime(uint64_t new_time_ms);

    // Network partitioning
    void CreatePartition(const std::vector<int>& group_a, const std::vector<int>& group_b);
    void HealPartition();
    bool IsPartitioned(int node_a, int node_b) const;

    // Statistics
    struct Stats {
        size_t total_messages_sent = 0;
        size_t total_messages_delivered = 0;
        size_t total_messages_dropped = 0;
        size_t total_bytes_sent = 0;
        size_t total_bytes_delivered = 0;
        std::map<int, size_t> messages_per_node;
    };
    Stats GetStats() const { return stats_; }

    // Test instrumentation: enable command tracking and query
    void EnableCommandTracking(bool enabled) { track_commands_ = enabled; }
    int CountCommandSent(int from_node, int to_node, const std::string& command) const;
    int CountDistinctPeersSent(int from_node, const std::string& command) const;
    std::vector<std::vector<uint8_t>> GetCommandPayloads(int from_node, int to_node, const std::string& command) const;

    // Forward declaration for node processing
    class ISimulatedNode {
    public:
        virtual ~ISimulatedNode() = default;
        virtual void ProcessEvents() = 0;
        virtual void ProcessPeriodic() = 0;
        virtual std::string GetAddress() const = 0;  // For netgroup-based connection limits
    };

    // Register callback for message delivery to a specific node
    // Callback receives (from_node_id, data)
    using MessageCallback = std::function<void(int, const std::vector<uint8_t>&)>;
    void RegisterNode(int node_id, MessageCallback callback, ISimulatedNode* node = nullptr, NetworkBridgedTransport* transport = nullptr) {
        node_callbacks_[node_id] = callback;
        if (node) {
            nodes_[node_id] = node;
        }
        if (transport) {
            transports_[node_id] = transport;
        }
    }
    void UnregisterNode(int node_id) {
        node_callbacks_.erase(node_id);
        nodes_.erase(node_id);
        transports_.erase(node_id);
    }

    /**
     * Get a node's IP address by node ID
     * Used by BridgedConnection to return the actual peer address for netgroup checks
     */
    std::string GetNodeAddress(int node_id) const {
        auto it = nodes_.find(node_id);
        if (it != nodes_.end() && it->second) {
            return it->second->GetAddress();
        }
        // Fallback to default 127.0.0.X if node not found
        std::ostringstream oss;
        oss << "127.0.0." << (node_id % 255);
        return oss.str();
    }

    // Get current simulation time
    uint64_t GetCurrentTime() const { return current_time_ms_; }

    // Reset simulation
    void Reset();

private:
    // RNG for deterministic simulation
    std::mt19937_64 rng_;

    // Current simulation time
    uint64_t current_time_ms_ = 0;

    // Message sequence counter (for stable ordering when delivery_time is equal)
    uint64_t message_sequence_ = 0;

    // Global network conditions
    NetworkConditions global_conditions_;

    // Per-link conditions (from_node -> to_node)
    std::map<std::pair<int, int>, NetworkConditions> link_conditions_;

    // Pending messages (sorted by delivery_time_ms)
    std::priority_queue<
        PendingMessage,
        std::vector<PendingMessage>,
        std::function<bool(const PendingMessage&, const PendingMessage&)>
    > message_queue_;

    // Per-link last scheduled delivery time (ms) to preserve send order under jitter
    std::map<std::pair<int,int>, uint64_t> last_delivery_time_;

    // Network partition state
    struct Partition {
        std::vector<int> group_a;
        std::vector<int> group_b;
        bool active = false;
    };
    Partition partition_;

    // Statistics
    Stats stats_;

    // Command tracking (from_node,to_node) -> command -> count
    bool track_commands_ = false;
    std::map<std::pair<int,int>, std::map<std::string,int>> command_counts_;
    std::map<std::tuple<int,int,std::string>, std::vector<std::vector<uint8_t>>> command_payloads_;

    // Per-node message delivery callbacks
    std::map<int, MessageCallback> node_callbacks_;

    // Per-node references (for processing events)
    std::map<int, ISimulatedNode*> nodes_;

    // Per-node transport references (for disconnect notifications)
    std::map<int, NetworkBridgedTransport*> transports_;

    // Track active connections (from_node, to_node)
    // When a disconnect occurs, queued messages should be dropped
    std::set<std::pair<int, int>> active_connections_;

    // Helper: Calculate delivery time for a message
    uint64_t CalculateDeliveryTime(int from_node, int to_node, size_t bytes);

    // Helper: Should drop this message? (packet loss simulation)
    bool ShouldDropMessage(int from_node, int to_node);

    // Helper: Get effective conditions for a link
    const NetworkConditions& GetLinkConditions(int from_node, int to_node) const;
};

} // namespace test
} // namespace unicity

#endif // UNICITY_TEST_SIMULATED_NETWORK_HPP
