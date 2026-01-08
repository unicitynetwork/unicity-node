#ifndef UNICITY_TEST_NETWORK_OBSERVER_HPP
#define UNICITY_TEST_NETWORK_OBSERVER_HPP

#include <string>
#include <vector>
#include <sstream>
#include <iostream>
#include <iomanip>

namespace unicity {
namespace test {

/**
 * NetworkObserver - Event capture system for debugging test failures
 * 
 * Brittleness problem: When tests fail, you get unhelpful errors like:
 *   "REQUIRE(score >= 100) failed: 0 >= 100"
 * 
 * But WHY did the score stay at 0? What messages were sent? What responses?
 * 
 * Solution: Observer pattern captures all network events with timestamps,
 * displays them in a readable timeline when test fails.
 * 
 * Usage:
 *   NetworkObserver observer;
 *   observer.OnMessageSent(1, 2, "headers", 500);
 *   observer.OnMessageReceived(2, 1, "headers", 500);
 *   observer.OnPeerDisconnected(1, 2, "invalid_pow");
 *   
 *   if (test_failed) {
 *       observer.DumpTimeline();  // Print everything that happened
 *   }
 */
class NetworkObserver {
public:
    // ============= Data Structure =============
    
    struct Event {
        uint64_t time_ms;
        std::string type;
        int node_a;  // Primary node (sender, subject)
        int node_b;  // Secondary node (receiver, peer)
        std::string details;
    };

    NetworkObserver() : current_time_ms_(0) {}
    
    // ============= Event Recording Interface =============
    
    void OnMessageSent(int from_node, int to_node, const std::string& command, size_t bytes) {
        RecordEvent("MSG_SEND", from_node, to_node, command + " (" + std::to_string(bytes) + " bytes)");
    }
    
    void OnMessageReceived(int node_id, int from_node, const std::string& command, size_t bytes) {
        RecordEvent("MSG_RECV", node_id, from_node, command + " (" + std::to_string(bytes) + " bytes)");
    }
    
    void OnMessageDropped(int from_node, int to_node, const std::string& command, const std::string& reason) {
        RecordEvent("MSG_DROP", from_node, to_node, command + " - " + reason);
    }
    
    void OnPeerConnected(int node_a, int node_b, int peer_id) {
        RecordEvent("PEER_CONNECT", node_a, node_b, "peer_id=" + std::to_string(peer_id));
    }
    
    void OnPeerDisconnected(int node_a, int node_b, const std::string& reason) {
        RecordEvent("PEER_DISCONNECT", node_a, node_b, reason);
    }
    
    void OnMisbehaviorScoreChanged(int node_id, int peer_id, int old_score, int new_score, const std::string& reason) {
        std::ostringstream oss;
        oss << "peer_id=" << peer_id << " score: " << old_score << " → " << new_score 
            << " (" << reason << ")";
        RecordEvent("MISBEHAVIOR", node_id, -1, oss.str());
    }
    
    void OnBanStatusChanged(int node_id, const std::string& address, const std::string& status) {
        RecordEvent("BAN", node_id, -1, address + " " + status);
    }
    
    void OnBlockMined(int node_id, const std::string& block_hash, int height) {
        RecordEvent("BLOCK_MINED", node_id, -1, 
                    "height=" + std::to_string(height) + " hash=" + block_hash.substr(0, 16) + "...");
    }
    
    void OnChainReorg(int node_id, int old_height, int new_height, const std::string& reason) {
        std::ostringstream oss;
        oss << "height: " << old_height << " → " << new_height << " (" << reason << ")";
        RecordEvent("REORG", node_id, -1, oss.str());
    }
    
    void OnValidationFailed(int node_id, const std::string& item, const std::string& reason) {
        RecordEvent("VALIDATION_FAIL", node_id, -1, item + " - " + reason);
    }
    
    void OnTestAssertion(const std::string& assertion, bool passed) {
        RecordEvent(passed ? "ASSERT_PASS" : "ASSERT_FAIL", -1, -1, assertion);
    }
    
    void OnCustomEvent(const std::string& event_type, int node_id, const std::string& details) {
        RecordEvent(event_type, node_id, -1, details);
    }
    
    // ============= Time Management =============
    
    void SetCurrentTime(uint64_t time_ms) {
        current_time_ms_ = time_ms;
    }
    
    void AdvanceTime(uint64_t delta_ms) {
        current_time_ms_ += delta_ms;
    }
    
    // ============= Output =============
    
    /**
     * Dump complete timeline to stdout
     * Call this when a test fails to see what happened
     */
    void DumpTimeline(std::ostream& out = std::cout) const {
        out << "\n" << std::string(80, '=') << "\n";
        out << "NETWORK EVENT TIMELINE\n";
        out << std::string(80, '=') << "\n";
        
        if (events_.empty()) {
            out << "No events recorded.\n";
            return;
        }
        
        for (const auto& event : events_) {
            out << FormatEvent(event) << "\n";
        }
        
        out << std::string(80, '=') << "\n";
        out << "Total events: " << events_.size() << "\n";
        out << std::string(80, '=') << "\n\n";
    }
    
    /**
     * Dump events matching filter
     * Useful for focusing on specific nodes or message types
     */
    void DumpFiltered(
        std::function<bool(const Event&)> filter,
        std::ostream& out = std::cout
    ) const {
        out << "\n" << std::string(80, '=') << "\n";
        out << "FILTERED NETWORK EVENTS\n";
        out << std::string(80, '=') << "\n";
        
        size_t count = 0;
        for (const auto& event : events_) {
            if (filter(event)) {
                out << FormatEvent(event) << "\n";
                count++;
            }
        }
        
        out << std::string(80, '=') << "\n";
        out << "Matched events: " << count << " / " << events_.size() << "\n";
        out << std::string(80, '=') << "\n\n";
    }
    
    /**
     * Get summary statistics
     */
    struct Stats {
        size_t total_events = 0;
        size_t messages_sent = 0;
        size_t messages_received = 0;
        size_t messages_dropped = 0;
        size_t connections = 0;
        size_t disconnections = 0;
        size_t misbehaviors = 0;
        size_t validations_failed = 0;
    };
    
    Stats GetStats() const {
        Stats stats;
        stats.total_events = events_.size();
        
        for (const auto& event : events_) {
            if (event.type == "MSG_SEND") stats.messages_sent++;
            else if (event.type == "MSG_RECV") stats.messages_received++;
            else if (event.type == "MSG_DROP") stats.messages_dropped++;
            else if (event.type == "PEER_CONNECT") stats.connections++;
            else if (event.type == "PEER_DISCONNECT") stats.disconnections++;
            else if (event.type == "MISBEHAVIOR") stats.misbehaviors++;
            else if (event.type == "VALIDATION_FAIL") stats.validations_failed++;
        }
        
        return stats;
    }
    
    void DumpStats(std::ostream& out = std::cout) const {
        auto stats = GetStats();
        
        out << "\n" << std::string(40, '=') << "\n";
        out << "NETWORK OBSERVER STATISTICS\n";
        out << std::string(40, '=') << "\n";
        out << "Total events:        " << stats.total_events << "\n";
        out << "Messages sent:       " << stats.messages_sent << "\n";
        out << "Messages received:   " << stats.messages_received << "\n";
        out << "Messages dropped:    " << stats.messages_dropped << "\n";
        out << "Connections:         " << stats.connections << "\n";
        out << "Disconnections:      " << stats.disconnections << "\n";
        out << "Misbehaviors:        " << stats.misbehaviors << "\n";
        out << "Validation failures: " << stats.validations_failed << "\n";
        out << std::string(40, '=') << "\n\n";
    }
    
    /**
     * Clear all recorded events
     */
    void Clear() {
        events_.clear();
    }
    
    const std::vector<Event>& GetEvents() const { return events_; }

private:
    std::vector<Event> events_;
    uint64_t current_time_ms_;
    
    void RecordEvent(const std::string& type, int node_a, int node_b, const std::string& details) {
        Event event;
        event.time_ms = current_time_ms_;
        event.type = type;
        event.node_a = node_a;
        event.node_b = node_b;
        event.details = details;
        events_.push_back(event);
    }
    
    std::string FormatEvent(const Event& event) const {
        std::ostringstream oss;
        
        // Timestamp
        oss << "[" << std::setw(8) << std::setfill(' ') << event.time_ms << "ms] ";
        
        // Event type (fixed width for alignment)
        oss << std::left << std::setw(18) << event.type << " ";
        
        // Node info
        if (event.node_a >= 0) {
            oss << "node" << event.node_a;
            if (event.node_b >= 0) {
                oss << " → node" << event.node_b;
            }
            oss << ": ";
        } else {
            oss << "       : ";
        }
        
        // Details
        oss << event.details;
        
        return oss.str();
    }
};

/**
 * RAII helper to automatically dump timeline on test failure
 * 
 * Usage:
 *   NetworkObserver observer;
 *   AutoDumpOnFailure auto_dump(observer);
 *   
 *   // ... test code ...
 *   REQUIRE(something);  // If this fails, timeline is dumped automatically
 */
class AutoDumpOnFailure {
public:
    explicit AutoDumpOnFailure(const NetworkObserver& observer)
        : observer_(observer), dumped_(false) {}
    
    ~AutoDumpOnFailure() {
        // If we're unwinding due to exception (test failure), dump timeline
        if (!dumped_ && std::uncaught_exceptions() > 0) {
            std::cout << "\n*** TEST FAILED - Dumping network timeline ***\n";
            observer_.DumpTimeline();
            observer_.DumpStats();
        }
    }
    
    // Manually mark as successful (prevents dump)
    void MarkSuccess() {
        dumped_ = true;
    }

private:
    const NetworkObserver& observer_;
    bool dumped_;
};

} // namespace test
} // namespace unicity

#endif // UNICITY_TEST_NETWORK_OBSERVER_HPP
