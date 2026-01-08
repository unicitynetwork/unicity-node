#ifndef UNICITY_TEST_MALICIOUS_BEHAVIORS_HPP
#define UNICITY_TEST_MALICIOUS_BEHAVIORS_HPP

#include "network/message.hpp"
#include "chain/block.hpp"
#include <vector>
#include <memory>
#include <functional>

namespace unicity {
namespace test {

/**
 * MaliciousBehavior - Strategy pattern for composable attack behaviors
 * 
 * Instead of NodeSimulator with hardcoded methods, behaviors can be
 * dynamically attached to any SimulatedNode to intercept/modify messages.
 * 
 * Benefits:
 * - Compose multiple behaviors (e.g., delay + corrupt)
 * - Apply to honest nodes selectively (e.g., 30% of time)
 * - Easy to create new attack patterns
 * - Testable in isolation
 */
class MaliciousBehavior {
public:
    virtual ~MaliciousBehavior() = default;
    
    /**
     * Intercept outgoing message before sending
     * 
     * @param command Message command (e.g., "headers", "inv")
     * @param payload Original message payload
     * @param to_node_id Destination node ID
     * @return Modified payload (or empty to drop message)
     */
    virtual std::vector<uint8_t> OnSendMessage(
        const std::string& command,
        const std::vector<uint8_t>& payload,
        int to_node_id
    ) {
        return payload; // Default: pass through
    }
    
    /**
     * Intercept incoming message before processing
     * 
     * @param command Message command
     * @param payload Original payload
     * @param from_node_id Source node ID
     * @return Modified payload (or empty to drop message)
     */
    virtual std::vector<uint8_t> OnReceiveMessage(
        const std::string& command,
        const std::vector<uint8_t>& payload,
        int from_node_id
    ) {
        return payload; // Default: pass through
    }
    
    /**
     * Called when node should respond to GETHEADERS
     * Return false to suppress response (stalling attack)
     */
    virtual bool ShouldRespondToGetHeaders(int from_node_id) {
        return true; // Default: respond normally
    }
    
    /**
     * Called when generating INV announcements
     * Can inject fake block hashes
     */
    virtual std::vector<uint256> ModifyInventory(
        const std::vector<uint256>& original_inv
    ) {
        return original_inv; // Default: no modification
    }
};

/**
 * DropMessagesBehavior - Drop all messages matching filter
 */
class DropMessagesBehavior : public MaliciousBehavior {
public:
    DropMessagesBehavior(std::function<bool(const std::string&)> filter)
        : filter_(filter) {}
    
    std::vector<uint8_t> OnSendMessage(
        const std::string& command,
        const std::vector<uint8_t>& payload,
        int to_node_id
    ) override {
        if (filter_(command)) {
            return {}; // Drop message
        }
        return payload;
    }

private:
    std::function<bool(const std::string&)> filter_;
};

/**
 * DelayMessagesBehavior - Add artificial delay to messages
 */
class DelayMessagesBehavior : public MaliciousBehavior {
public:
    DelayMessagesBehavior(uint64_t delay_ms, std::function<bool(const std::string&)> filter)
        : delay_ms_(delay_ms), filter_(filter) {}
    
    // Note: Actual delay implementation requires cooperation with SimulatedNetwork
    // This is a marker behavior that TestOrchestrator can detect
    
    uint64_t GetDelay() const { return delay_ms_; }
    bool ShouldDelay(const std::string& command) const { return filter_(command); }

private:
    uint64_t delay_ms_;
    std::function<bool(const std::string&)> filter_;
};

/**
 * CorruptHeadersBehavior - Send headers with invalid PoW
 */
class CorruptHeadersBehavior : public MaliciousBehavior {
public:
    enum class CorruptionType {
        INVALID_POW,        // Set hashRandomX to null
        INVALID_TIMESTAMP,  // Set timestamp in past
        INVALID_DIFFICULTY, // Wrong nBits
        DISCONTINUOUS,      // Break hashPrevBlock chain
    };
    
    CorruptHeadersBehavior(CorruptionType type, double probability = 1.0)
        : type_(type), probability_(probability), rng_(std::random_device{}()) {}
    
    std::vector<uint8_t> OnSendMessage(
        const std::string& command,
        const std::vector<uint8_t>& payload,
        int to_node_id
    ) override;

private:
    CorruptionType type_;
    double probability_;
    std::mt19937_64 rng_;
};

/**
 * StallResponsesBehavior - Don't respond to GETHEADERS
 */
class StallResponsesBehavior : public MaliciousBehavior {
public:
    StallResponsesBehavior(bool permanent = true, int max_stalls = -1)
        : permanent_(permanent), max_stalls_(max_stalls), stall_count_(0) {}
    
    bool ShouldRespondToGetHeaders(int from_node_id) override {
        if (max_stalls_ >= 0 && stall_count_ >= max_stalls_) {
            return true; // Stop stalling after limit
        }
        stall_count_++;
        return !permanent_;
    }

private:
    bool permanent_;
    int max_stalls_;
    int stall_count_;
};

/**
 * SelfishMiningBehavior - Withhold mined blocks, release strategically
 */
class SelfishMiningBehavior : public MaliciousBehavior {
public:
    SelfishMiningBehavior() : withheld_blocks_() {}
    
    // Withhold a newly mined block
    void WithholdBlock(const uint256& block_hash) {
        withheld_blocks_.push_back(block_hash);
    }
    
    // Release all withheld blocks
    std::vector<uint256> ReleaseBlocks() {
        auto blocks = withheld_blocks_;
        withheld_blocks_.clear();
        return blocks;
    }
    
    std::vector<uint256> ModifyInventory(
        const std::vector<uint256>& original_inv
    ) override {
        // Don't announce withheld blocks
        std::vector<uint256> filtered;
        for (const auto& hash : original_inv) {
            if (std::find(withheld_blocks_.begin(), withheld_blocks_.end(), hash)
                == withheld_blocks_.end()) {
                filtered.push_back(hash);
            }
        }
        return filtered;
    }

private:
    std::vector<uint256> withheld_blocks_;
};

/**
 * OversizedMessageBehavior - Send messages exceeding protocol limits
 */
class OversizedMessageBehavior : public MaliciousBehavior {
public:
    OversizedMessageBehavior(size_t multiplier = 10) : multiplier_(multiplier) {}
    
    std::vector<uint8_t> OnSendMessage(
        const std::string& command,
        const std::vector<uint8_t>& payload,
        int to_node_id
    ) override;

private:
    size_t multiplier_;
};

/**
 * SpamBehavior - Flood with repeated messages
 */
class SpamBehavior : public MaliciousBehavior {
public:
    SpamBehavior(const std::string& target_command, size_t repeat_count)
        : target_command_(target_command), repeat_count_(repeat_count) {}
    
    std::vector<uint8_t> OnSendMessage(
        const std::string& command,
        const std::vector<uint8_t>& payload,
        int to_node_id
    ) override;
    
    // Get number of times to repeat the message (used by TestOrchestrator)
    size_t GetRepeatCount(const std::string& command) const {
        return (command == target_command_) ? repeat_count_ : 1;
    }

private:
    std::string target_command_;
    size_t repeat_count_;
};

/**
 * BehaviorChain - Compose multiple behaviors
 */
class BehaviorChain : public MaliciousBehavior {
public:
    void AddBehavior(std::shared_ptr<MaliciousBehavior> behavior) {
        behaviors_.push_back(behavior);
    }
    
    std::vector<uint8_t> OnSendMessage(
        const std::string& command,
        const std::vector<uint8_t>& payload,
        int to_node_id
    ) override {
        auto result = payload;
        for (auto& behavior : behaviors_) {
            result = behavior->OnSendMessage(command, result, to_node_id);
            if (result.empty()) break; // Message dropped
        }
        return result;
    }
    
    std::vector<uint8_t> OnReceiveMessage(
        const std::string& command,
        const std::vector<uint8_t>& payload,
        int from_node_id
    ) override {
        auto result = payload;
        for (auto& behavior : behaviors_) {
            result = behavior->OnReceiveMessage(command, result, from_node_id);
            if (result.empty()) break; // Message dropped
        }
        return result;
    }
    
    bool ShouldRespondToGetHeaders(int from_node_id) override {
        for (auto& behavior : behaviors_) {
            if (!behavior->ShouldRespondToGetHeaders(from_node_id)) {
                return false; // Any behavior can veto response
            }
        }
        return true;
    }
    
    std::vector<uint256> ModifyInventory(
        const std::vector<uint256>& original_inv
    ) override {
        auto result = original_inv;
        for (auto& behavior : behaviors_) {
            result = behavior->ModifyInventory(result);
        }
        return result;
    }

private:
    std::vector<std::shared_ptr<MaliciousBehavior>> behaviors_;
};

} // namespace test
} // namespace unicity

#endif // UNICITY_TEST_MALICIOUS_BEHAVIORS_HPP
