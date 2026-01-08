#ifndef UNICITY_TEST_PEER_FACTORY_HPP
#define UNICITY_TEST_PEER_FACTORY_HPP

#include "address_factory.hpp"
#include "simulated_node.hpp"
#include "simulated_network.hpp"
#include <memory>
#include <vector>
#include <string>
#include <functional>

namespace unicity {
namespace test {

/**
 * PeerFactory - Create configured peers for testing eviction, bucketing, and attacks
 *
 * Provides convenient methods to create peers with specific properties:
 * - Address/netgroup configuration (via AddressFactory)
 * - Connection type (inbound/outbound)
 * - Timing characteristics (connection age, ping latency)
 *
 * Use cases:
 * - Eviction testing: Create peers with specific protection properties
 * - Sybil attacks: Create many peers in same /16 subnet
 * - Eclipse attacks: Create attacker-controlled peer sets
 * - Netgroup diversity: Create peers in different /16 subnets
 *
 * Example usage:
 *   SimulatedNetwork network;
 *   PeerFactory factory(&network);
 *
 *   // Create a victim node
 *   auto victim = factory.CreateNode(0);
 *
 *   // Create diverse honest peers (different /16 subnets)
 *   auto honest = factory.CreateDiversePeers(8, 1);  // IDs 1-8
 *
 *   // Create Sybil attacker cluster (same /16)
 *   auto attackers = factory.CreateSybilCluster(50, 100, "192.168.0.0");  // IDs 100-149
 *
 *   // Connect attackers to victim
 *   factory.ConnectAllTo(attackers, *victim);
 */
class PeerFactory {
public:
    /**
     * Configuration for peer creation
     */
    struct PeerConfig {
        std::string address;                  // IP address (empty = auto-generate)
        bool diverse_subnet = true;           // If auto-generating, use diverse subnets
        std::string subnet_base;              // If not diverse, use this subnet base

        // For future eviction improvements (when we add netgroup protection)
        // These don't affect current eviction but document intent
        bool should_be_protected = false;     // Intent: peer should survive eviction
        std::string protection_reason;        // Why: "netgroup", "ping", "uptime", etc.
    };

    /**
     * Result of peer creation with metadata
     */
    struct PeerResult {
        std::unique_ptr<SimulatedNode> node;
        std::string address;
        std::string netgroup;                 // /16 prefix (e.g., "192.168")
        int node_id;
    };

    /**
     * Create factory bound to a SimulatedNetwork
     */
    explicit PeerFactory(SimulatedNetwork* network)
        : network_(network), address_factory_() {}

    /**
     * Reset address generation counters (for test isolation)
     */
    void Reset() {
        address_factory_.Reset();
    }

    // =========================================================================
    // Single Node Creation
    // =========================================================================

    /**
     * Create a single node with auto-generated diverse address
     */
    std::unique_ptr<SimulatedNode> CreateNode(int node_id) {
        std::string addr = address_factory_.NextDiverseAddress();
        return std::make_unique<SimulatedNode>(node_id, network_, addr);
    }

    /**
     * Create a node with specific address
     */
    std::unique_ptr<SimulatedNode> CreateNodeWithAddress(int node_id, const std::string& address) {
        return std::make_unique<SimulatedNode>(node_id, network_, address);
    }

    /**
     * Create a node in a specific subnet (for Sybil simulation)
     */
    std::unique_ptr<SimulatedNode> CreateNodeInSubnet(int node_id, const std::string& subnet_base) {
        std::string addr = address_factory_.NextInSubnet(subnet_base);
        return std::make_unique<SimulatedNode>(node_id, network_, addr);
    }

    /**
     * Create a node with full configuration
     */
    PeerResult CreateConfiguredNode(int node_id, const PeerConfig& config) {
        std::string addr;
        if (!config.address.empty()) {
            addr = config.address;
        } else if (config.diverse_subnet) {
            addr = address_factory_.NextDiverseAddress();
        } else {
            addr = address_factory_.NextInSubnet(config.subnet_base);
        }

        PeerResult result;
        result.node = std::make_unique<SimulatedNode>(node_id, network_, addr);
        result.address = addr;
        result.netgroup = AddressFactory::GetNetgroupKey(addr);
        result.node_id = node_id;
        return result;
    }

    // =========================================================================
    // Batch Node Creation
    // =========================================================================

    /**
     * Create multiple nodes with diverse addresses (different /16 subnets)
     * Ideal for honest peer simulation
     *
     * @param count Number of nodes to create
     * @param start_id Starting node ID
     * @return Vector of created nodes
     */
    std::vector<std::unique_ptr<SimulatedNode>> CreateDiversePeers(size_t count, int start_id) {
        std::vector<std::unique_ptr<SimulatedNode>> nodes;
        nodes.reserve(count);

        for (size_t i = 0; i < count; i++) {
            std::string addr = address_factory_.NextDiverseAddress();
            nodes.push_back(std::make_unique<SimulatedNode>(
                start_id + static_cast<int>(i), network_, addr));
        }

        return nodes;
    }

    /**
     * Create multiple nodes in the same /16 subnet (Sybil cluster)
     * Ideal for Sybil attack simulation
     *
     * @param count Number of nodes to create
     * @param start_id Starting node ID
     * @param subnet_base Base subnet like "192.168.0.0"
     * @return Vector of created nodes (all in same /16)
     */
    std::vector<std::unique_ptr<SimulatedNode>> CreateSybilCluster(
            size_t count, int start_id, const std::string& subnet_base) {
        std::vector<std::unique_ptr<SimulatedNode>> nodes;
        nodes.reserve(count);

        for (size_t i = 0; i < count; i++) {
            std::string addr = address_factory_.NextInSubnet(subnet_base);
            nodes.push_back(std::make_unique<SimulatedNode>(
                start_id + static_cast<int>(i), network_, addr));
        }

        return nodes;
    }

    /**
     * Create a mixed set of honest and attacker nodes
     * Honest nodes get diverse addresses, attackers share a subnet
     *
     * @param honest_count Number of honest nodes
     * @param attacker_count Number of attacker nodes
     * @param honest_start_id Starting ID for honest nodes
     * @param attacker_start_id Starting ID for attacker nodes
     * @param attacker_subnet Subnet for attacker cluster
     * @return Pair of (honest_nodes, attacker_nodes)
     */
    std::pair<std::vector<std::unique_ptr<SimulatedNode>>,
              std::vector<std::unique_ptr<SimulatedNode>>>
    CreateMixedPeers(size_t honest_count, size_t attacker_count,
                     int honest_start_id, int attacker_start_id,
                     const std::string& attacker_subnet = "192.168.0.0") {
        auto honest = CreateDiversePeers(honest_count, honest_start_id);
        auto attackers = CreateSybilCluster(attacker_count, attacker_start_id, attacker_subnet);
        return {std::move(honest), std::move(attackers)};
    }

    // =========================================================================
    // Connection Helpers
    // =========================================================================

    /**
     * Connect all nodes in a vector to a target node
     * Each node in 'from_nodes' connects TO 'to_node'
     */
    void ConnectAllTo(std::vector<std::unique_ptr<SimulatedNode>>& from_nodes,
                      SimulatedNode& to_node) {
        for (auto& node : from_nodes) {
            node->ConnectTo(to_node.GetId(), to_node.GetAddress());
        }
    }

    /**
     * Connect a target node to all nodes in a vector
     * 'from_node' connects TO each node in 'to_nodes'
     */
    void ConnectToAll(SimulatedNode& from_node,
                      std::vector<std::unique_ptr<SimulatedNode>>& to_nodes) {
        for (auto& node : to_nodes) {
            from_node.ConnectTo(node->GetId(), node->GetAddress());
        }
    }

    /**
     * Create a fully connected mesh between all nodes
     */
    void CreateMesh(std::vector<std::unique_ptr<SimulatedNode>>& nodes) {
        for (size_t i = 0; i < nodes.size(); i++) {
            for (size_t j = i + 1; j < nodes.size(); j++) {
                nodes[i]->ConnectTo(nodes[j]->GetId(), nodes[j]->GetAddress());
            }
        }
    }

    // =========================================================================
    // Attack Scenario Setups
    // =========================================================================

    /**
     * Eclipse attack setup:
     * - One victim node
     * - Multiple honest peers (diverse subnets)
     * - Many attacker nodes (same subnet)
     *
     * Returns tuple of (victim, honest_peers, attackers)
     */
    struct EclipseScenario {
        std::unique_ptr<SimulatedNode> victim;
        std::vector<std::unique_ptr<SimulatedNode>> honest_peers;
        std::vector<std::unique_ptr<SimulatedNode>> attackers;
    };

    EclipseScenario CreateEclipseScenario(
            size_t honest_count,
            size_t attacker_count,
            const std::string& attacker_subnet = "192.168.0.0") {
        EclipseScenario scenario;

        // Victim gets ID 0 with unique subnet
        scenario.victim = CreateNode(0);

        // Honest peers get IDs 1..honest_count with diverse subnets
        scenario.honest_peers = CreateDiversePeers(honest_count, 1);

        // Attackers get IDs 1000+ with shared subnet
        scenario.attackers = CreateSybilCluster(attacker_count, 1000, attacker_subnet);

        return scenario;
    }

    /**
     * Eviction pressure test setup:
     * - One victim node with limited inbound slots
     * - Enough peers to exceed the limit and trigger eviction
     *
     * @param slot_limit Maximum inbound connections (will be set on victim)
     * @param peer_count Total peers to create (should exceed slot_limit)
     * @param diverse If true, peers have diverse subnets; if false, all same subnet
     */
    struct EvictionScenario {
        std::unique_ptr<SimulatedNode> victim;
        std::vector<std::unique_ptr<SimulatedNode>> peers;
    };

    EvictionScenario CreateEvictionScenario(
            size_t slot_limit,
            size_t peer_count,
            bool diverse = true,
            const std::string& subnet = "172.16.0.0") {
        EvictionScenario scenario;

        // Create victim
        scenario.victim = CreateNode(0);

        // Create peers
        if (diverse) {
            scenario.peers = CreateDiversePeers(peer_count, 1);
        } else {
            scenario.peers = CreateSybilCluster(peer_count, 1, subnet);
        }

        return scenario;
    }

    // =========================================================================
    // Verification Helpers
    // =========================================================================

    /**
     * Check that all nodes in a vector have diverse netgroups
     */
    static bool AllDiverseNetgroups(const std::vector<std::unique_ptr<SimulatedNode>>& nodes) {
        std::set<std::string> netgroups;
        for (const auto& node : nodes) {
            std::string ng = AddressFactory::GetNetgroupKey(node->GetAddress());
            if (netgroups.count(ng) > 0) {
                return false;  // Duplicate netgroup
            }
            netgroups.insert(ng);
        }
        return true;
    }

    /**
     * Check that all nodes in a vector share the same netgroup
     */
    static bool AllSameNetgroup(const std::vector<std::unique_ptr<SimulatedNode>>& nodes) {
        if (nodes.empty()) return true;

        std::string first_ng = AddressFactory::GetNetgroupKey(nodes[0]->GetAddress());
        for (const auto& node : nodes) {
            if (AddressFactory::GetNetgroupKey(node->GetAddress()) != first_ng) {
                return false;
            }
        }
        return true;
    }

    /**
     * Count unique netgroups in a vector of nodes
     */
    static size_t CountUniqueNetgroups(const std::vector<std::unique_ptr<SimulatedNode>>& nodes) {
        std::set<std::string> netgroups;
        for (const auto& node : nodes) {
            netgroups.insert(AddressFactory::GetNetgroupKey(node->GetAddress()));
        }
        return netgroups.size();
    }

    /**
     * Get the netgroup for a node
     */
    static std::string GetNetgroup(const SimulatedNode& node) {
        return AddressFactory::GetNetgroupKey(node.GetAddress());
    }

    // =========================================================================
    // Access to underlying factories
    // =========================================================================

    AddressFactory& GetAddressFactory() { return address_factory_; }
    SimulatedNetwork* GetNetwork() { return network_; }

private:
    SimulatedNetwork* network_;
    AddressFactory address_factory_;
};

} // namespace test
} // namespace unicity

#endif // UNICITY_TEST_PEER_FACTORY_HPP
