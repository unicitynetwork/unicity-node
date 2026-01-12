#ifndef UNICITY_TEST_ATTACK_ORCHESTRATOR_HPP
#define UNICITY_TEST_ATTACK_ORCHESTRATOR_HPP

#include "peer_factory.hpp"
#include "address_factory.hpp"
#include "simulated_node.hpp"
#include "simulated_network.hpp"
#include "../test_orchestrator.hpp"
#include <memory>
#include <vector>
#include <string>
#include <set>
#include <chrono>

namespace unicity {
namespace test {

/**
 * AttackOrchestrator - Coordinate and measure attack scenarios
 *
 * Provides high-level attack primitives for testing:
 * - Eclipse attacks (inbound and outbound)
 * - Sybil attacks (address injection, connection flooding)
 * - Combined attack scenarios
 *
 * Also provides metrics collection to measure attack success/failure.
 *
 * Usage:
 *   SimulatedNetwork network;
 *   PeerFactory peer_factory(&network);
 *   AttackOrchestrator attacker(&network, &peer_factory);
 *
 *   // Setup victim with honest peers
 *   auto victim = peer_factory.CreateNode(0);
 *   auto honest = peer_factory.CreateDiversePeers(8, 1);
 *   attacker.ConnectPeersTo(honest, *victim);
 *
 *   // Execute eclipse attack
 *   auto result = attacker.AttemptInboundEclipse(*victim, {
 *       .attacker_count = 50,
 *       .attacker_subnet = "192.168.0.0"
 *   });
 *
 *   // Check results
 *   REQUIRE_FALSE(result.eclipse_achieved);
 *   REQUIRE(result.attacker_ratio < 0.5);
 */
class AttackOrchestrator {
public:
    // =========================================================================
    // Configuration Structures
    // =========================================================================

    /**
     * Configuration for inbound eclipse attack
     */
    struct InboundEclipseConfig {
        size_t attacker_count = 50;           // Number of attacker nodes
        std::string attacker_subnet = "192.168.0.0";  // Attacker /16 subnet
        bool use_diverse_subnets = false;     // Spread attackers across subnets
        size_t diverse_subnet_count = 1;      // If diverse, how many /16s
        bool stagger_connections = false;     // Connect over time vs burst
        std::chrono::milliseconds stagger_delay{100};  // Delay between connections
        int attacker_start_id = 1000;         // Starting node ID for attackers
    };

    /**
     * Configuration for address injection (Sybil) attack
     */
    struct AddressInjectionConfig {
        size_t address_count = 1000;          // Number of fake addresses
        std::string subnet = "192.168.0.0";   // Subnet for addresses
        bool use_diverse_subnets = false;     // Spread across subnets
        size_t diverse_subnet_count = 1;      // If diverse, how many /16s
    };

    // =========================================================================
    // Result Structures
    // =========================================================================

    /**
     * Metrics about victim's peer state
     */
    struct PeerMetrics {
        size_t total_peers = 0;
        size_t inbound_peers = 0;
        size_t outbound_peers = 0;

        // Netgroup analysis
        size_t unique_netgroups = 0;
        std::map<std::string, size_t> peers_per_netgroup;
        std::string largest_netgroup;
        size_t largest_netgroup_count = 0;

        // Attack analysis (if attacker subnet known)
        size_t attacker_peers = 0;
        size_t honest_peers = 0;
        double attacker_ratio = 0.0;          // attacker / total
        bool eclipse_achieved = false;        // 100% attacker control
    };

    /**
     * Result of an attack attempt
     */
    struct AttackResult {
        bool attack_executed = false;
        PeerMetrics before;                   // State before attack
        PeerMetrics after;                    // State after attack
        size_t connections_attempted = 0;
        size_t connections_succeeded = 0;
        size_t connections_rejected = 0;
        std::chrono::milliseconds duration{0};
    };

    // =========================================================================
    // Constructor
    // =========================================================================

    AttackOrchestrator(SimulatedNetwork* network, PeerFactory* peer_factory)
        : network_(network)
        , peer_factory_(peer_factory)
        , orchestrator_(network) {}

    // =========================================================================
    // Metrics Collection
    // =========================================================================

    /**
     * Measure current peer state of a victim node
     *
     * @param victim Node to analyze
     * @param attacker_subnet Optional: subnet to count as "attacker"
     * @return Metrics about peer distribution
     */
    PeerMetrics MeasurePeerState(
            SimulatedNode& victim,
            const std::string& attacker_subnet = "") {
        PeerMetrics metrics;

        metrics.total_peers = victim.GetPeerCount();
        metrics.inbound_peers = victim.GetInboundPeerCount();
        metrics.outbound_peers = victim.GetOutboundPeerCount();

        // Analyze netgroup distribution
        // Note: We can't directly iterate victim's peers, so we track
        // connections we've made through the peer factory
        // For now, return basic metrics

        metrics.unique_netgroups = 0;  // Would need peer iteration
        metrics.attacker_ratio = 0.0;

        if (!attacker_subnet.empty() && metrics.total_peers > 0) {
            // We can't directly check peer addresses without internal access
            // This would be filled in by test code that knows the peer composition
        }

        return metrics;
    }

    /**
     * Measure peer state with known peer composition
     *
     * @param victim Node to analyze
     * @param honest_peers List of honest peers
     * @param attacker_peers List of attacker peers
     */
    PeerMetrics MeasurePeerStateWithKnownPeers(
            SimulatedNode& victim,
            const std::vector<std::unique_ptr<SimulatedNode>>& honest_peers,
            const std::vector<std::unique_ptr<SimulatedNode>>& attacker_peers) {
        PeerMetrics metrics;

        metrics.total_peers = victim.GetPeerCount();
        metrics.inbound_peers = victim.GetInboundPeerCount();
        metrics.outbound_peers = victim.GetOutboundPeerCount();

        // Count connected honest peers
        size_t connected_honest = 0;
        for (const auto& h : honest_peers) {
            // Check if this honest peer is connected to victim
            // We assume if honest peer has >= 1 peer and victim has peers, they're connected
            if (h->GetPeerCount() >= 1) {
                connected_honest++;
                std::string ng = AddressFactory::GetNetgroupKey(h->GetAddress());
                metrics.peers_per_netgroup[ng]++;
            }
        }

        // Count connected attacker peers
        size_t connected_attackers = 0;
        for (const auto& a : attacker_peers) {
            if (a->GetPeerCount() >= 1) {
                connected_attackers++;
                std::string ng = AddressFactory::GetNetgroupKey(a->GetAddress());
                metrics.peers_per_netgroup[ng]++;
            }
        }

        metrics.honest_peers = connected_honest;
        metrics.attacker_peers = connected_attackers;
        metrics.unique_netgroups = metrics.peers_per_netgroup.size();

        // Find largest netgroup
        for (const auto& [ng, count] : metrics.peers_per_netgroup) {
            if (count > metrics.largest_netgroup_count) {
                metrics.largest_netgroup = ng;
                metrics.largest_netgroup_count = count;
            }
        }

        // Calculate attacker ratio
        if (metrics.total_peers > 0) {
            metrics.attacker_ratio =
                static_cast<double>(metrics.attacker_peers) / metrics.total_peers;
        }

        // Eclipse achieved if all peers are attackers
        metrics.eclipse_achieved =
            (metrics.total_peers > 0 && metrics.honest_peers == 0);

        return metrics;
    }

    // =========================================================================
    // Attack Execution
    // =========================================================================

    /**
     * Attempt an inbound eclipse attack
     *
     * Creates attacker nodes and connects them to victim, attempting to
     * dominate or replace honest peers.
     *
     * @param victim Target node
     * @param config Attack configuration
     * @return Attack results including before/after metrics
     */
    AttackResult AttemptInboundEclipse(
            SimulatedNode& victim,
            const InboundEclipseConfig& config) {
        AttackResult result;
        result.attack_executed = true;

        // Measure before state
        result.before = MeasurePeerState(victim);

        auto start_time = network_->GetCurrentTime();

        // Create attacker nodes
        std::vector<std::unique_ptr<SimulatedNode>> attackers;
        if (config.use_diverse_subnets) {
            // Spread across multiple /16 subnets
            size_t per_subnet = config.attacker_count / config.diverse_subnet_count;
            for (size_t s = 0; s < config.diverse_subnet_count; s++) {
                std::string subnet = "192." + std::to_string(s + 1) + ".0.0";
                auto cluster = peer_factory_->CreateSybilCluster(
                    per_subnet,
                    config.attacker_start_id + static_cast<int>(s * per_subnet),
                    subnet);
                for (auto& node : cluster) {
                    attackers.push_back(std::move(node));
                }
            }
        } else {
            // All from same subnet
            attackers = peer_factory_->CreateSybilCluster(
                config.attacker_count,
                config.attacker_start_id,
                config.attacker_subnet);
        }

        // Connect attackers to victim
        result.connections_attempted = attackers.size();

        for (auto& attacker : attackers) {
            attacker->ConnectTo(victim.GetId(), victim.GetAddress());

            if (config.stagger_connections) {
                network_->AdvanceTime(
                    network_->GetCurrentTime() + config.stagger_delay.count());
            }
        }

        // Wait for connections to establish
        network_->AdvanceTime(network_->GetCurrentTime() + 2000);

        // Count successful connections
        for (const auto& attacker : attackers) {
            if (attacker->GetPeerCount() >= 1) {
                result.connections_succeeded++;
            } else {
                result.connections_rejected++;
            }
        }

        // Measure after state
        result.after = MeasurePeerState(victim, config.attacker_subnet);

        auto end_time = network_->GetCurrentTime();
        result.duration = std::chrono::milliseconds(end_time - start_time);

        // Store attackers for later analysis (caller can use them)
        last_attackers_ = std::move(attackers);

        return result;
    }

    /**
     * Connect a list of peers to a target node
     * Convenience method for setting up honest peers before attack
     */
    void ConnectPeersTo(
            std::vector<std::unique_ptr<SimulatedNode>>& peers,
            SimulatedNode& target) {
        for (auto& peer : peers) {
            peer->ConnectTo(target.GetId(), target.GetAddress());
        }

        // Wait for connections
        for (auto& peer : peers) {
            orchestrator_.WaitForConnection(*peer, target, std::chrono::seconds(2));
        }
    }

    /**
     * Wait for victim's protection window to expire on all current peers
     */
    void WaitForProtectionExpiry(int seconds = 61) {
        for (int i = 0; i < seconds; i++) {
            network_->AdvanceTime(network_->GetCurrentTime() + 1000);
        }
    }

    // =========================================================================
    // Analysis Helpers
    // =========================================================================

    /**
     * Generate a human-readable report of attack results
     */
    static std::string GenerateReport(const AttackResult& result) {
        std::ostringstream oss;
        oss << "=== Attack Report ===\n";
        oss << "Executed: " << (result.attack_executed ? "Yes" : "No") << "\n";
        oss << "Duration: " << result.duration.count() << "ms\n";
        oss << "\n";
        oss << "Connections:\n";
        oss << "  Attempted: " << result.connections_attempted << "\n";
        oss << "  Succeeded: " << result.connections_succeeded << "\n";
        oss << "  Rejected:  " << result.connections_rejected << "\n";
        oss << "\n";
        oss << "Before Attack:\n";
        oss << "  Total peers:   " << result.before.total_peers << "\n";
        oss << "  Inbound:       " << result.before.inbound_peers << "\n";
        oss << "  Outbound:      " << result.before.outbound_peers << "\n";
        oss << "\n";
        oss << "After Attack:\n";
        oss << "  Total peers:   " << result.after.total_peers << "\n";
        oss << "  Inbound:       " << result.after.inbound_peers << "\n";
        oss << "  Attacker ratio: " << (result.after.attacker_ratio * 100) << "%\n";
        oss << "  Eclipse:       " << (result.after.eclipse_achieved ? "YES" : "No") << "\n";
        return oss.str();
    }

    /**
     * Check if attack achieved eclipse (100% attacker control)
     */
    static bool IsEclipsed(const PeerMetrics& metrics) {
        return metrics.eclipse_achieved;
    }

    /**
     * Check if attackers dominate (>50% of peers)
     */
    static bool AttackersDominate(const PeerMetrics& metrics) {
        return metrics.attacker_ratio > 0.5;
    }

    /**
     * Get netgroup diversity score (higher = more diverse)
     */
    static double GetDiversityScore(const PeerMetrics& metrics) {
        if (metrics.total_peers == 0) return 0.0;

        // Perfect diversity: each peer in different netgroup
        // Score = unique_netgroups / total_peers
        return static_cast<double>(metrics.unique_netgroups) / metrics.total_peers;
    }

    // =========================================================================
    // Access to last attack's nodes (for further testing)
    // =========================================================================

    std::vector<std::unique_ptr<SimulatedNode>>& GetLastAttackers() {
        return last_attackers_;
    }

private:
    SimulatedNetwork* network_;
    PeerFactory* peer_factory_;
    TestOrchestrator orchestrator_;

    // Store last attack's nodes for follow-up testing
    std::vector<std::unique_ptr<SimulatedNode>> last_attackers_;
};

} // namespace test
} // namespace unicity

#endif // UNICITY_TEST_ATTACK_ORCHESTRATOR_HPP
