// Copyright (c) 2025 The Unicity Foundation
// Eclipse Attack Simulator - Reusable framework for testing eclipse attack defenses
//
// This simulator provides high-level APIs for executing and analyzing eclipse attacks:
// 1. Inbound eclipse: Attacker floods victim with connections
// 2. Outbound eclipse: Attacker poisons address table
// 3. Combined: Both simultaneously
//
// Key features:
// - Automatic metrics collection (before/during/after)
// - Support for "silent peer" attacks (connect but don't relay headers)
// - Header relay simulation to test eviction protections
// - Continuous monitoring for time-series analysis
// - Human-readable reports

#pragma once

#include "peer_factory.hpp"
#include "simulated_network.hpp"
#include "simulated_node.hpp"
#include "../test_orchestrator.hpp"
#include <chrono>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

namespace unicity {
namespace test {

class EclipseAttackSimulator {
public:
    // =========== Attack Types ===========
    enum class AttackType {
        INBOUND_FLOOD,      // Flood inbound connections
        SILENT_PEERS,       // Connect but never relay headers (tests eviction)
        ADDRESS_POISON,     // Poison address table for outbound eclipse
        COMBINED            // All of the above
    };

    // =========== Peer Snapshot ===========
    struct PeerSnapshot {
        size_t total_peers{0};
        size_t inbound_peers{0};
        size_t outbound_peers{0};
        size_t attacker_controlled{0};
        size_t honest_peers{0};
        std::map<std::string, size_t> netgroup_distribution;

        double attacker_ratio() const {
            return total_peers > 0 ? static_cast<double>(attacker_controlled) / total_peers : 0.0;
        }
    };

    // =========== Attack Metrics ===========
    struct AttackMetrics {
        // Attack configuration
        AttackType type;
        size_t attacker_budget;
        size_t honest_peer_count;

        // Timing
        std::chrono::steady_clock::time_point start_time;
        std::chrono::steady_clock::time_point end_time;

        // Peer state snapshots
        PeerSnapshot before;
        PeerSnapshot after;

        // Connection results
        size_t attempted_connections{0};
        size_t successful_connections{0};
        size_t rejected_connections{0};

        // Eclipse status
        bool inbound_eclipsed{false};   // All inbound from attacker
        bool outbound_eclipsed{false};  // All outbound to attacker
        bool fully_eclipsed{false};     // Both

        // Defense effectiveness
        size_t evicted_attackers{0};
        size_t evicted_honest{0};

        // Time series (for continuous monitoring)
        std::vector<std::pair<uint64_t, PeerSnapshot>> timeline;
    };

    // =========== Constructor ===========
    EclipseAttackSimulator(
        SimulatedNetwork* network,
        PeerFactory* factory,
        SimulatedNode* victim)
        : network_(network)
        , factory_(factory)
        , victim_(victim)
        , orchestrator_(network) {}

    // =========== High-Level Attack APIs ===========

    /**
     * Execute a "silent peer" eclipse attack to test eviction protections.
     *
     * Silent peers connect and complete handshake but never send headers.
     * With proper eviction protections, these should be evicted before
     * honest peers that relay headers.
     *
     * @param num_attackers Number of attacker nodes to create
     * @param num_honest Number of honest nodes that relay headers
     * @param attacker_subnet Base subnet for attackers (e.g., "192.168.0.0")
     * @param trigger_eviction Whether to trigger eviction after connections
     * @return Attack metrics
     */
    AttackMetrics ExecuteSilentPeerAttack(
        size_t num_attackers,
        size_t num_honest,
        const std::string& attacker_subnet = "192.168.0.0",
        bool trigger_eviction = true);

    /**
     * Execute inbound flooding attack.
     * Tests per-netgroup limits and connection throttling.
     */
    AttackMetrics ExecuteInboundFlood(
        size_t num_attackers,
        size_t num_subnets = 1,
        const std::string& subnet_base = "192.168.0.0");

    /**
     * Setup honest peers that relay headers.
     * These should be protected from eviction.
     */
    void SetupHonestPeers(size_t count);

    /**
     * Simulate header relay from honest peers.
     * Updates their last_headers_received timestamp.
     */
    void SimulateHeaderRelay();

    /**
     * Wait for protection window to expire (60 seconds).
     */
    void WaitForProtectionExpiry();

    /**
     * Trigger eviction and track who gets evicted.
     */
    void TriggerEviction(size_t num_evictions);

    // =========== Analysis ===========

    /**
     * Take a snapshot of current peer state.
     */
    PeerSnapshot SnapshotPeers() const;

    /**
     * Check if defense was effective.
     * @param max_attacker_ratio Maximum acceptable attacker ratio (default 50%)
     */
    bool WasDefenseEffective(double max_attacker_ratio = 0.5) const;

    /**
     * Check if honest peers survived eviction.
     */
    bool HonestPeersSurvived() const;

    /**
     * Generate human-readable report.
     */
    std::string GenerateReport() const;

    /**
     * Get the last attack metrics.
     */
    const AttackMetrics& GetMetrics() const { return metrics_; }

    // =========== Cleanup ===========

    /**
     * Disconnect all attackers.
     */
    void DisconnectAttackers();

    /**
     * Reset simulator for next attack.
     */
    void Reset();

private:
    SimulatedNetwork* network_;
    PeerFactory* factory_;
    SimulatedNode* victim_;
    TestOrchestrator orchestrator_;

    // Attack state
    std::vector<std::unique_ptr<SimulatedNode>> attacker_nodes_;
    std::vector<std::unique_ptr<SimulatedNode>> honest_nodes_;
    std::set<int> attacker_peer_ids_;
    std::set<int> honest_peer_ids_;
    AttackMetrics metrics_;

    // Helpers
    void RecordSnapshot(PeerSnapshot& snapshot) const;
    void IdentifyPeerIds();
    std::string NetgroupOf(const std::string& addr) const;
};

// =========== Implementation ===========

inline EclipseAttackSimulator::AttackMetrics
EclipseAttackSimulator::ExecuteSilentPeerAttack(
    size_t num_attackers,
    size_t num_honest,
    const std::string& attacker_subnet,
    bool trigger_eviction) {

    Reset();

    metrics_.type = AttackType::SILENT_PEERS;
    metrics_.attacker_budget = num_attackers;
    metrics_.honest_peer_count = num_honest;
    metrics_.start_time = std::chrono::steady_clock::now();

    // Snapshot before
    RecordSnapshot(metrics_.before);

    // Step 1: Setup honest peers from diverse subnets
    SetupHonestPeers(num_honest);

    // Step 2: Connect attackers (silent - won't relay headers)
    // Use multiple subnets to bypass per-netgroup limit
    size_t attackers_per_subnet = std::min(size_t(4), num_attackers); // Max 4 per netgroup
    size_t subnets_needed = (num_attackers + 3) / 4;

    for (size_t subnet = 0; subnet < subnets_needed && attacker_nodes_.size() < num_attackers; subnet++) {
        std::string base = std::to_string(192 + subnet) + ".168.0.0";
        size_t to_create = std::min(attackers_per_subnet, num_attackers - attacker_nodes_.size());

        auto cluster = factory_->CreateSybilCluster(
            to_create,
            1000 + subnet * 100,  // Start IDs
            base);

        for (auto& node : cluster) {
            node->ConnectTo(victim_->GetId(), victim_->GetAddress());
            metrics_.attempted_connections++;
            attacker_nodes_.push_back(std::move(node));
        }
    }

    // Wait for connections
    orchestrator_.AdvanceTime(std::chrono::seconds(2));

    // Step 3: Honest peers relay headers (attackers don't)
    SimulateHeaderRelay();

    // Step 4: Wait for protection window to expire
    WaitForProtectionExpiry();

    // Step 5: Trigger eviction if requested
    if (trigger_eviction) {
        // Need to fill to capacity first, then evict
        TriggerEviction(num_attackers / 2);  // Try to evict half the attackers
    }

    // Identify which peers are attackers vs honest
    IdentifyPeerIds();

    // Snapshot after
    RecordSnapshot(metrics_.after);

    // Analyze results
    metrics_.successful_connections = metrics_.after.attacker_controlled;
    metrics_.rejected_connections = metrics_.attempted_connections - metrics_.successful_connections;
    metrics_.inbound_eclipsed = (metrics_.after.honest_peers == 0 && metrics_.after.attacker_controlled > 0);
    metrics_.fully_eclipsed = metrics_.inbound_eclipsed;

    metrics_.end_time = std::chrono::steady_clock::now();

    return metrics_;
}

inline EclipseAttackSimulator::AttackMetrics
EclipseAttackSimulator::ExecuteInboundFlood(
    size_t num_attackers,
    size_t num_subnets,
    const std::string& subnet_base) {

    Reset();

    metrics_.type = AttackType::INBOUND_FLOOD;
    metrics_.attacker_budget = num_attackers;
    metrics_.start_time = std::chrono::steady_clock::now();

    RecordSnapshot(metrics_.before);

    // Create attackers spread across subnets
    size_t per_subnet = (num_attackers + num_subnets - 1) / num_subnets;

    for (size_t s = 0; s < num_subnets; s++) {
        // Parse base and increment second octet
        std::string base = std::to_string(10 + s) + ".99.0.0";
        size_t to_create = std::min(per_subnet, num_attackers - attacker_nodes_.size());

        auto cluster = factory_->CreateSybilCluster(to_create, 1000 + s * 100, base);

        for (auto& node : cluster) {
            node->ConnectTo(victim_->GetId(), victim_->GetAddress());
            metrics_.attempted_connections++;
            attacker_nodes_.push_back(std::move(node));
        }
    }

    orchestrator_.AdvanceTime(std::chrono::seconds(2));

    IdentifyPeerIds();
    RecordSnapshot(metrics_.after);

    metrics_.successful_connections = metrics_.after.attacker_controlled;
    metrics_.rejected_connections = metrics_.attempted_connections - metrics_.successful_connections;
    metrics_.end_time = std::chrono::steady_clock::now();

    return metrics_;
}

inline void EclipseAttackSimulator::SetupHonestPeers(size_t count) {
    honest_nodes_ = factory_->CreateDiversePeers(count, 1);

    for (auto& node : honest_nodes_) {
        node->ConnectTo(victim_->GetId(), victim_->GetAddress());
    }

    orchestrator_.AdvanceTime(std::chrono::seconds(2));
}

inline void EclipseAttackSimulator::SimulateHeaderRelay() {
    // Find peer IDs for honest nodes and update their header timestamps
    auto& peer_mgr = victim_->GetNetworkManager().peer_manager();
    auto all_peers = peer_mgr.get_all_peers();

    // Match honest nodes by address
    std::set<std::string> honest_addrs;
    for (const auto& node : honest_nodes_) {
        honest_addrs.insert(node->GetAddress());
    }

    for (const auto& peer : all_peers) {
        if (honest_addrs.count(peer->address()) > 0) {
            peer_mgr.UpdateLastHeadersReceived(peer->id());
            honest_peer_ids_.insert(peer->id());
        }
    }
}

inline void EclipseAttackSimulator::WaitForProtectionExpiry() {
    // Protection window is 60 seconds
    for (int i = 0; i < 65; i++) {
        orchestrator_.AdvanceTime(std::chrono::seconds(1));
    }
}

inline void EclipseAttackSimulator::TriggerEviction(size_t num_evictions) {
    auto& peer_mgr = victim_->GetNetworkManager().peer_manager();

    for (size_t i = 0; i < num_evictions; i++) {
        auto before = peer_mgr.get_all_peers();
        bool evicted = peer_mgr.evict_inbound_peer();
        if (!evicted) break;

        auto after = peer_mgr.get_all_peers();

        // Find who was evicted
        std::set<int> before_ids, after_ids;
        for (const auto& p : before) before_ids.insert(p->id());
        for (const auto& p : after) after_ids.insert(p->id());

        for (int id : before_ids) {
            if (after_ids.count(id) == 0) {
                if (honest_peer_ids_.count(id) > 0) {
                    metrics_.evicted_honest++;
                } else {
                    metrics_.evicted_attackers++;
                }
            }
        }
    }
}

inline void EclipseAttackSimulator::IdentifyPeerIds() {
    auto& peer_mgr = victim_->GetNetworkManager().peer_manager();
    auto all_peers = peer_mgr.get_all_peers();

    // Build set of honest addresses
    std::set<std::string> honest_addrs;
    for (const auto& node : honest_nodes_) {
        honest_addrs.insert(node->GetAddress());
    }

    // Classify each peer
    attacker_peer_ids_.clear();
    for (const auto& peer : all_peers) {
        if (honest_addrs.count(peer->address()) == 0) {
            attacker_peer_ids_.insert(peer->id());
        }
    }
}

inline EclipseAttackSimulator::PeerSnapshot
EclipseAttackSimulator::SnapshotPeers() const {
    PeerSnapshot snap;
    RecordSnapshot(const_cast<PeerSnapshot&>(snap));
    return snap;
}

inline void EclipseAttackSimulator::RecordSnapshot(PeerSnapshot& snapshot) const {
    auto& peer_mgr = victim_->GetNetworkManager().peer_manager();
    auto all_peers = peer_mgr.get_all_peers();

    snapshot.total_peers = all_peers.size();
    snapshot.inbound_peers = 0;
    snapshot.outbound_peers = 0;
    snapshot.attacker_controlled = 0;
    snapshot.honest_peers = 0;
    snapshot.netgroup_distribution.clear();

    // Build honest address set
    std::set<std::string> honest_addrs;
    for (const auto& node : honest_nodes_) {
        honest_addrs.insert(node->GetAddress());
    }

    for (const auto& peer : all_peers) {
        if (peer->is_inbound()) {
            snapshot.inbound_peers++;
        } else {
            snapshot.outbound_peers++;
        }

        if (honest_addrs.count(peer->address()) > 0) {
            snapshot.honest_peers++;
        } else {
            snapshot.attacker_controlled++;
        }

        std::string ng = NetgroupOf(peer->address());
        snapshot.netgroup_distribution[ng]++;
    }
}

inline bool EclipseAttackSimulator::WasDefenseEffective(double max_attacker_ratio) const {
    return metrics_.after.attacker_ratio() <= max_attacker_ratio;
}

inline bool EclipseAttackSimulator::HonestPeersSurvived() const {
    return metrics_.evicted_honest == 0 && metrics_.after.honest_peers > 0;
}

inline std::string EclipseAttackSimulator::GenerateReport() const {
    std::ostringstream ss;

    ss << "\n========== ECLIPSE ATTACK SIMULATION REPORT ==========\n\n";

    ss << "Attack Type: ";
    switch (metrics_.type) {
        case AttackType::SILENT_PEERS: ss << "Silent Peers (test eviction)"; break;
        case AttackType::INBOUND_FLOOD: ss << "Inbound Flood"; break;
        case AttackType::ADDRESS_POISON: ss << "Address Poisoning"; break;
        case AttackType::COMBINED: ss << "Combined Attack"; break;
    }
    ss << "\n";

    ss << "Attacker Budget: " << metrics_.attacker_budget << " nodes\n";
    ss << "Honest Peers: " << metrics_.honest_peer_count << " nodes\n\n";

    ss << "--- Connection Results ---\n";
    ss << "Attempted: " << metrics_.attempted_connections << "\n";
    ss << "Successful: " << metrics_.successful_connections << "\n";
    ss << "Rejected: " << metrics_.rejected_connections << "\n\n";

    ss << "--- Before Attack ---\n";
    ss << "Total Peers: " << metrics_.before.total_peers << "\n";
    ss << "Honest: " << metrics_.before.honest_peers << "\n";
    ss << "Attacker: " << metrics_.before.attacker_controlled << "\n\n";

    ss << "--- After Attack ---\n";
    ss << "Total Peers: " << metrics_.after.total_peers << "\n";
    ss << "Honest: " << metrics_.after.honest_peers << "\n";
    ss << "Attacker: " << metrics_.after.attacker_controlled << "\n";
    ss << "Attacker Ratio: " << (metrics_.after.attacker_ratio() * 100) << "%\n\n";

    ss << "--- Eviction Results ---\n";
    ss << "Evicted Attackers: " << metrics_.evicted_attackers << "\n";
    ss << "Evicted Honest: " << metrics_.evicted_honest << "\n\n";

    ss << "--- Eclipse Status ---\n";
    ss << "Inbound Eclipsed: " << (metrics_.inbound_eclipsed ? "YES" : "NO") << "\n";
    ss << "Fully Eclipsed: " << (metrics_.fully_eclipsed ? "YES" : "NO") << "\n\n";

    ss << "--- Defense Effectiveness ---\n";
    ss << "Defense Effective (<50% attackers): " << (WasDefenseEffective() ? "YES" : "NO") << "\n";
    ss << "Honest Peers Survived: " << (HonestPeersSurvived() ? "YES" : "NO") << "\n";

    ss << "\n========================================================\n";

    return ss.str();
}

inline void EclipseAttackSimulator::DisconnectAttackers() {
    for (auto& node : attacker_nodes_) {
        node->DisconnectFrom(victim_->GetId());
    }
    orchestrator_.AdvanceTime(std::chrono::seconds(1));
}

inline void EclipseAttackSimulator::Reset() {
    attacker_nodes_.clear();
    honest_nodes_.clear();
    attacker_peer_ids_.clear();
    honest_peer_ids_.clear();
    metrics_ = AttackMetrics{};
}

inline std::string EclipseAttackSimulator::NetgroupOf(const std::string& addr) const {
    // Extract /16 prefix (first two octets)
    auto dot1 = addr.find('.');
    if (dot1 == std::string::npos) return addr;
    auto dot2 = addr.find('.', dot1 + 1);
    if (dot2 == std::string::npos) return addr;
    return addr.substr(0, dot2);
}

} // namespace test
} // namespace unicity
