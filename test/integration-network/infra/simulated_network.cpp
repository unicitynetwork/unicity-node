#include "simulated_network.hpp"
#include "network_bridged_transport.hpp"
#include "util/time.hpp"
#include "util/logging.hpp"
#include "network/message.hpp"
#include <algorithm>

namespace unicity {
namespace test {

SimulatedNetwork::SimulatedNetwork(uint64_t seed)
    : rng_(seed),
      message_queue_([](const PendingMessage& a, const PendingMessage& b) {
          // Min-heap: smaller delivery_time has priority
          // If delivery times are equal, use sequence number to maintain FIFO order
          if (a.delivery_time_ms != b.delivery_time_ms) {
              return a.delivery_time_ms > b.delivery_time_ms;
          }
          return a.sequence_number > b.sequence_number;
      })
{
    // Reset mock time first to clear any stale steady clock reference from previous tests.
    // This ensures g_steady_initialized is reset and GetSteadyTime() will reinitialize
    // with fresh reference points.
    util::SetMockTime(0);

    // Initialize mock time to match simulated time (realistic starting point)
    // Using a post-2020 time avoids edge cases with timestamp validation
    util::SetMockTime(static_cast<int64_t>(SIMULATION_START_TIME_MS / 1000));
}

SimulatedNetwork::~SimulatedNetwork() {
    // Restore real time when simulation is destroyed
    // SetMockTime(0) disables time mocking
    util::SetMockTime(0);
}

void SimulatedNetwork::SetNetworkConditions(const NetworkConditions& conditions) {
    global_conditions_ = conditions;
}

void SimulatedNetwork::SetLinkConditions(int from_node, int to_node, const NetworkConditions& conditions) {
    link_conditions_[{from_node, to_node}] = conditions;
}

void SimulatedNetwork::SendMessage(int from_node, int to_node, const std::vector<uint8_t>& data) {
    // Log command being enqueued
    protocol::MessageHeader hdr;
    std::string cmd = "<invalid>";
    if (data.size() >= protocol::MESSAGE_HEADER_SIZE && message::deserialize_header(data.data(), data.size(), hdr)) {
        cmd = hdr.get_command();
    }
    LOG_NET_TRACE("simnet: enqueue from={} to={} cmd={} size={}", from_node, to_node, cmd, data.size());

    // Track command type for testing if enabled
    if (track_commands_ && data.size() >= protocol::MESSAGE_HEADER_SIZE) {
        protocol::MessageHeader hdr;
        if (message::deserialize_header(data.data(), data.size(), hdr)) {
            std::string cmd = hdr.get_command();
            command_counts_[{from_node, to_node}][cmd]++;
            // Record payload as well
            size_t header_size = protocol::MESSAGE_HEADER_SIZE;
            if (data.size() >= header_size + hdr.length) {
                std::vector<uint8_t> payload(data.begin() + header_size,
                                             data.begin() + header_size + hdr.length);
                command_payloads_[{from_node, to_node, cmd}].push_back(std::move(payload));
            }
        }
    }
    stats_.total_messages_sent++;
    stats_.total_bytes_sent += data.size();
    stats_.messages_per_node[from_node]++;

    // Check network partition
    if (partition_.active && IsPartitioned(from_node, to_node)) {
        stats_.total_messages_dropped++;
        return;  // Message blocked by partition
    }

    // Check packet loss
    if (ShouldDropMessage(from_node, to_node)) {
        stats_.total_messages_dropped++;
        return;
    }

    // Check command blocking (for testing specific protocol behaviors)
    const auto& conditions = GetLinkConditions(from_node, to_node);
    if (!conditions.blocked_commands.empty() && cmd != "<invalid>") {
        if (conditions.blocked_commands.count(cmd) > 0) {
            LOG_NET_TRACE("simnet: blocked cmd={} from={} to={}", cmd, from_node, to_node);
            stats_.total_messages_dropped++;
            return;
        }
    }

    // Calculate delivery time with jitter
    uint64_t delivery_time = CalculateDeliveryTime(from_node, to_node, data.size());

    // Ensure FIFO per-link even under jitter: never schedule earlier than last
    auto key = std::make_pair(from_node, to_node);
    auto it_last = last_delivery_time_.find(key);
    if (it_last != last_delivery_time_.end() && delivery_time < it_last->second) {
        delivery_time = it_last->second + 1; // +1 ms preserves ordering
    }
    last_delivery_time_[key] = delivery_time;

    // Enqueue message with sequence number for stable ordering
    PendingMessage msg;
    msg.from_node = from_node;
    msg.to_node = to_node;
    msg.data = data;
    msg.delivery_time_ms = delivery_time;
    msg.bytes = data.size();
    msg.sequence_number = message_sequence_++;  // Assign unique sequence for FIFO ordering

    message_queue_.push(std::move(msg));
}

void SimulatedNetwork::RegisterConnection(int from_node, int to_node) {
    active_connections_.insert({from_node, to_node});
}

void SimulatedNetwork::NotifyDisconnect(int from_node, int to_node) {
    // Remove from active connections (both directions)
    active_connections_.erase({from_node, to_node});
    active_connections_.erase({to_node, from_node});

    // Purge all queued messages between these nodes
    // We need to rebuild the queue without the messages for this connection
    std::priority_queue<
        PendingMessage,
        std::vector<PendingMessage>,
        std::function<bool(const PendingMessage&, const PendingMessage&)>
    > new_queue([](const PendingMessage& a, const PendingMessage& b) {
        // Min-heap with sequence tiebreaker (same as constructor)
        if (a.delivery_time_ms != b.delivery_time_ms) {
            return a.delivery_time_ms > b.delivery_time_ms;
        }
        return a.sequence_number > b.sequence_number;
    });

    size_t purged_count = 0;
    while (!message_queue_.empty()) {
        const auto& msg = message_queue_.top();

        // Keep message if it's not between the disconnected nodes
        if (!((msg.from_node == from_node && msg.to_node == to_node) ||
              (msg.from_node == to_node && msg.to_node == from_node))) {
            new_queue.push(msg);
        } else {
            purged_count++;
        }

        message_queue_.pop();
    }

    message_queue_ = std::move(new_queue);

    // Find the transport for the target node and notify
    auto it = transports_.find(to_node);
    if (it != transports_.end() && it->second) {
        // Call handle_remote_disconnect on the remote transport
        it->second->handle_remote_disconnect(from_node);
    }
}

size_t SimulatedNetwork::ProcessMessages(uint64_t current_time_ms) {
    size_t delivered = 0;

    while (!message_queue_.empty() && message_queue_.top().delivery_time_ms <= current_time_ms) {
        // IMPORTANT: Copy the message BEFORE popping, because the callback may
        // trigger a disconnect which rebuilds the queue, invalidating references
        PendingMessage msg = message_queue_.top();
        message_queue_.pop();

        // Deliver message via node-specific callback (pass sender node_id)
        auto it = node_callbacks_.find(msg.to_node);
        if (it != node_callbacks_.end()) {
            it->second(msg.from_node, msg.data);
        }

        stats_.total_messages_delivered++;
        stats_.total_bytes_delivered += msg.bytes;
        delivered++;
    }

    return delivered;
}

size_t SimulatedNetwork::AdvanceTime(uint64_t duration_ms) {
    // Add duration to current time (relative advancement)
    current_time_ms_ += duration_ms;

    // Synchronize util::GetTime() with simulated time
    // Convert milliseconds to seconds for the time mock
    // IMPORTANT: SetMockTime(0) means "disable mocking", so always use at least 1
    int64_t mock_time_seconds = std::max(int64_t(1), static_cast<int64_t>(current_time_ms_ / 1000));
    util::SetMockTime(mock_time_seconds);

    // Process messages and events in multiple rounds to handle message chains
    // (e.g., INV -> GETHEADERS -> HEADERS)
    // IMPORTANT: Keep looping as long as there are pending messages ready for delivery
    size_t total_delivered = 0;
    const int MAX_ROUNDS = 50;  // Increased from 10 to handle longer message chains in fast (non-TSAN) builds

    for (int round = 0; round < MAX_ROUNDS; ++round) {
        // Process any messages that are ready for delivery
        size_t delivered = ProcessMessages(current_time_ms_);
        total_delivered += delivered;

        // DEBUG: Log round activity
        if (delivered > 0) {
        }

        // Run periodic maintenance on all nodes first
        // This simulates the periodic timers that run in production and queues block announcements
        // (process_periodic checks for misbehaving peers and disconnects them)
        for (auto& [node_id, node] : nodes_) {
            if (node) {
                node->ProcessPeriodic();
            }
        }

        // Process io_context events on all nodes after periodic tasks
        // This flushes block announcements queued by ProcessPeriodic() and allows peers to react to received messages
        // IMPORTANT: This may queue new messages with delivery_time <= current_time_ms
        for (auto& [node_id, node] : nodes_) {
            if (node) {
                node->ProcessEvents();
            }
        }

        // Check if we should continue:
        // - If messages were delivered this round, continue (there may be responses)
        // - If queue is empty, we're done
        // - If next message is in the future, we're done
        bool has_ready_messages = !message_queue_.empty() &&
                                  message_queue_.top().delivery_time_ms <= current_time_ms_;

        if (delivered == 0 && !has_ready_messages) {
            break;  // No work done and no pending work
        }
    }

    return total_delivered;
}

void SimulatedNetwork::CreatePartition(const std::vector<int>& group_a, const std::vector<int>& group_b) {
    partition_.group_a = group_a;
    partition_.group_b = group_b;
    partition_.active = true;
}

void SimulatedNetwork::HealPartition() {
    partition_.active = false;
    partition_.group_a.clear();
    partition_.group_b.clear();
}

bool SimulatedNetwork::IsPartitioned(int node_a, int node_b) const {
    if (!partition_.active) {
        return false;
    }

    // Check if nodes are in different groups
    bool a_in_group_a = std::find(partition_.group_a.begin(), partition_.group_a.end(), node_a) != partition_.group_a.end();
    bool a_in_group_b = std::find(partition_.group_b.begin(), partition_.group_b.end(), node_a) != partition_.group_b.end();
    bool b_in_group_a = std::find(partition_.group_a.begin(), partition_.group_a.end(), node_b) != partition_.group_a.end();
    bool b_in_group_b = std::find(partition_.group_b.begin(), partition_.group_b.end(), node_b) != partition_.group_b.end();

    // Partitioned if one is in group_a and other is in group_b
    return (a_in_group_a && b_in_group_b) || (a_in_group_b && b_in_group_a);
}

void SimulatedNetwork::Reset() {
    current_time_ms_ = SIMULATION_START_TIME_MS;
    while (!message_queue_.empty()) {
        message_queue_.pop();
    }
    link_conditions_.clear();
    partition_.active = false;
    partition_.group_a.clear();
    partition_.group_b.clear();
    stats_ = Stats{};
}

uint64_t SimulatedNetwork::CalculateDeliveryTime(int from_node, int to_node, size_t bytes) {
    const auto& conditions = GetLinkConditions(from_node, to_node);

    // Base latency (uniform random between min and max)
    std::uniform_int_distribution<uint64_t> latency_dist(
        conditions.latency_min.count(),
        conditions.latency_max.count()
    );
    uint64_t latency_ms = latency_dist(rng_);

    // Add jitter
    if (conditions.jitter_max.count() > 0) {
        std::uniform_int_distribution<uint64_t> jitter_dist(0, conditions.jitter_max.count());
        latency_ms += jitter_dist(rng_);
    }

    // Bandwidth delay (if limited)
    if (conditions.bandwidth_bytes_per_sec > 0) {
        uint64_t transmission_time_ms = (bytes * 1000) / conditions.bandwidth_bytes_per_sec;
        latency_ms += transmission_time_ms;
    }

    return current_time_ms_ + latency_ms;
}

bool SimulatedNetwork::ShouldDropMessage(int from_node, int to_node) {
    const auto& conditions = GetLinkConditions(from_node, to_node);

    if (conditions.packet_loss_rate <= 0.0) {
        return false;
    }

    std::uniform_real_distribution<double> dist(0.0, 1.0);
    return dist(rng_) < conditions.packet_loss_rate;
}

const SimulatedNetwork::NetworkConditions& SimulatedNetwork::GetLinkConditions(int from_node, int to_node) const {
    auto it = link_conditions_.find({from_node, to_node});
    if (it != link_conditions_.end()) {
        return it->second;
    }
    return global_conditions_;
}

int SimulatedNetwork::CountCommandSent(int from_node, int to_node, const std::string& command) const {
    auto it = command_counts_.find({from_node, to_node});
    if (it == command_counts_.end()) return 0;
    auto it2 = it->second.find(command);
    if (it2 == it->second.end()) return 0;
    return it2->second;
}

int SimulatedNetwork::CountDistinctPeersSent(int from_node, const std::string& command) const {
    std::set<int> peers;
    for (const auto& kv : command_counts_) {
        if (kv.first.first != from_node) continue;
        auto it2 = kv.second.find(command);
        if (it2 != kv.second.end() && it2->second > 0) {
            peers.insert(kv.first.second);
        }
    }
return static_cast<int>(peers.size());
}

std::vector<std::vector<uint8_t>> SimulatedNetwork::GetCommandPayloads(int from_node, int to_node, const std::string& command) const {
    auto it = command_payloads_.find(std::make_tuple(from_node, to_node, command));
    if (it == command_payloads_.end()) return {};
    return it->second;
}

} // namespace test
} // namespace unicity
