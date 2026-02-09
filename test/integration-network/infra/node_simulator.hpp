#ifndef UNICITY_TEST_ATTACK_SIMULATED_NODE_HPP
#define UNICITY_TEST_ATTACK_SIMULATED_NODE_HPP

#include "simulated_node.hpp"
#include "chain/block.hpp"

namespace unicity {
namespace test {

/**
 * NodeSimulator - Extends SimulatedNode to send malicious P2P messages
 *
 * This node can:
 * - Send headers with invalid PoW
 * - Send non-continuous headers
 * - Send oversized messages
 * - Stall responses to GETHEADERS
 *
 * Used for testing DoS protection and attack resilience.
 */
class NodeSimulator : public SimulatedNode {
public:
    NodeSimulator(int node_id,
                        SimulatedNetwork* network,
                        const chain::ChainParams* params = nullptr)
        : SimulatedNode(node_id, network, params)
    {
    }

    // Constructor with custom address - for testing with non-localhost addresses
    NodeSimulator(int node_id,
                  SimulatedNetwork* network,
                  const std::string& custom_address,
                  const chain::ChainParams* params = nullptr)
        : SimulatedNode(node_id, network, custom_address, params)
    {
    }

    // Send unconnecting headers (headers with unknown parents that trigger GETHEADERS)
    // These headers are discarded by the recipient (no orphan pool).
    void SendUnconnectingHeaders(int peer_node_id, size_t count);
    // Alias for backward compatibility with tests
    void SendOrphanHeaders(int peer_node_id, size_t count) { SendUnconnectingHeaders(peer_node_id, count); }

    // Send headers with invalid PoW
    void SendInvalidPoWHeaders(int peer_node_id, const uint256& prev_hash, size_t count);

    // Send non-continuous headers (don't connect properly)
    void SendNonContinuousHeaders(int peer_node_id, const uint256& prev_hash);

    // Send oversized HEADERS message (>2000 headers)
    void SendOversizedHeaders(int peer_node_id, size_t count);

    // Enable stalling mode - don't respond to GETHEADERS requests
    void EnableStalling(bool enabled) { stalling_enabled_ = enabled; }

    // Mine a block privately (don't broadcast) - for selfish mining attacks
    uint256 MineBlockPrivate(const std::string& miner_address = "selfish_miner");

    // Broadcast a previously mined private block to a specific peer
    void BroadcastBlock(const uint256& block_hash, int peer_node_id);

    // Send low-work headers to a peer (for DoS testing)
    // Sends headers from the attacker's chain (which has low total work)
    void SendLowWorkHeaders(int peer_node_id, const std::vector<uint256>& block_hashes);

    // Send headers out of order (child before parent) to test out-of-order handling
    // Returns pair of {parent_hash, child_hash}
    std::pair<uint256, uint256> SendOutOfOrderHeaders(int peer_node_id, const uint256& prev_hash);

    // Send valid side-chain headers forking from a given block
    // Creates a chain of `count` headers building on fork_point
    // Used for testing side-chain pruning protection
    void SendValidSideChainHeaders(int peer_node_id, const uint256& fork_point, size_t count);

    // Send valid headers from our chain to a peer via P2P HEADERS message
    // Used for testing that valid headers arriving don't reset stall deadline
    void SendValidHeaders(int peer_node_id, const std::vector<CBlockHeader>& headers);

private:
    bool stalling_enabled_ = false;

    // Helper: Create a dummy header
    CBlockHeader CreateDummyHeader(const uint256& prev_hash, uint32_t nBits);

    // Access protected members from SimulatedNode
    using SimulatedNode::sim_network_;
    using SimulatedNode::params_;
};

} // namespace test
} // namespace unicity

#endif // UNICITY_TEST_ATTACK_SIMULATED_NODE_HPP
