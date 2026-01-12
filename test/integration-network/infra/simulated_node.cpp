// Copyright (c) 2025 The Unicity Foundation
// SimulatedNode implementation - Uses REAL P2P components with simulated transport

#include "simulated_node.hpp"
#include <random>
#include <sstream>
#include "chain/block.hpp"
#include "chain/chainstate_manager.hpp"
#include "util/logging.hpp"
#include "chain/pow.hpp"
#include "chain/randomx_pow.hpp"
#include "util/sha256.hpp"
#include "chain/validation.hpp"
#include "network/block_relay_manager.hpp"
#include "network/connection_types.hpp"
#include "network/peer_discovery_manager.hpp"

namespace unicity {
namespace test {

using unicity::validation::ValidationState;

// Helper to generate default address from node_id
static std::string GenerateDefaultAddress(int node_id) {
    std::ostringstream oss;
    oss << "127.0.0." << (node_id % 255);
    return oss.str();
}

// Common initialization logic used by all constructors
void SimulatedNode::InitializeNode(const chain::ChainParams* params) {
    // Setup chain params
    if (params) {
        params_ = params;
    } else {
        params_owned_ = chain::ChainParams::CreateRegTest();
        params_ = params_owned_.get();
    }

    // Initialize chainstate with genesis
    chainstate_ = std::make_unique<TestChainstateManager>(*params_);
    chainstate_->Initialize(params_->GenesisBlock());

    // Create work guard to keep io_context alive
    work_guard_ = std::make_unique<asio::executor_work_guard<asio::io_context::executor_type>>(
        asio::make_work_guard(io_context_)
    );

    // Initialize networking
    InitializeNetworking();

    // Re-register with SimulatedNetwork to include node pointer for event processing and transport
    if (sim_network_ && transport_) {
        sim_network_->RegisterNode(node_id_, [this](int from_node_id, const std::vector<uint8_t>& data) {
            if (transport_) {
                transport_->deliver_message(from_node_id, data);
            }
        }, this, transport_.get());
    }
}

// Standard constructor - auto-generates address
SimulatedNode::SimulatedNode(int node_id,
                             SimulatedNetwork* network,
                             const chain::ChainParams* params)
    : node_id_(node_id)
    , port_(protocol::ports::REGTEST + node_id)
    , sim_network_(network)
    , address_(GenerateDefaultAddress(node_id))
{
    InitializeNode(params);
}

// Constructor with custom address - for testing netgroup diversity
SimulatedNode::SimulatedNode(int node_id,
                             SimulatedNetwork* network,
                             const std::string& custom_address,
                             const chain::ChainParams* params)
    : node_id_(node_id)
    , port_(protocol::ports::REGTEST + node_id)
    , sim_network_(network)
    , address_(custom_address)
{
    InitializeNode(params);
}

// Constructor with IO threads override
SimulatedNode::SimulatedNode(int node_id,
                             SimulatedNetwork* network,
                             const chain::ChainParams* params,
                             size_t io_threads_override)
    : node_id_(node_id)
    , port_(protocol::ports::REGTEST + node_id)
    , sim_network_(network)
    , address_(GenerateDefaultAddress(node_id))
    , io_threads_override_(io_threads_override)
{
    InitializeNode(params);
}

// Full constructor with all options
SimulatedNode::SimulatedNode(int node_id,
                             SimulatedNetwork* network,
                             const std::string& custom_address,
                             const chain::ChainParams* params,
                             size_t io_threads_override)
    : node_id_(node_id)
    , port_(protocol::ports::REGTEST + node_id)
    , sim_network_(network)
    , address_(custom_address)
    , io_threads_override_(io_threads_override)
{
    InitializeNode(params);
}

SimulatedNode::~SimulatedNode() {
    // Stop networking
    if (network_manager_) {
        network_manager_->stop();
    }

    // Release work guard to allow io_context to finish
    work_guard_.reset();

    // Process remaining events
    io_context_.run();
}

void SimulatedNode::InitializeNetworking() {
    // Create bridged transport that routes through SimulatedNetwork
    transport_ = std::make_shared<NetworkBridgedTransport>(node_id_, sim_network_);

    // Create NetworkManager with our transport
    network::NetworkManager::Config config;
    config.network_magic = params_->GetNetworkMagic();
    config.listen_enabled = true;
    config.listen_port = port_;
    config.io_threads = io_threads_override_;  // 0 by default (deterministic); tests may override
    config.enable_nat = false;  // Disable NAT/UPnP in tests (would block trying to discover devices)

    // CRITICAL: Set unique test_nonce for each node to prevent self-connection rejection
    // In multi-node tests, each SimulatedNode needs a unique nonce (node_id + offset)
    // Setting test_nonce disables process-wide nonce, and each peer gets this value
    // via set_local_nonce() in PeerLifecycleManager, ensuring different nodes can connect
    config.test_nonce = static_cast<uint64_t>(node_id_) + 1000000;

    // Create shared_ptr wrapper for io_context (NetworkManager requires shared ownership)
    // Use aliasing constructor with no-op deleter since SimulatedNode owns the io_context
    auto io_context_ptr = std::shared_ptr<asio::io_context>(
        std::shared_ptr<void>{}, &io_context_
    );

    network_manager_ = std::make_unique<network::NetworkManager>(
        *chainstate_,  // Pass TestChainstateManager (inherits from ChainstateManager)
        config,
        transport_,
        io_context_ptr  // Pass shared_ptr to our io_context
    );

    // Start networking
    if (!network_manager_->start()) {
        throw std::runtime_error("Failed to start NetworkManager");
    }
}

std::string SimulatedNode::GetAddress() const {
    return address_;
}

bool SimulatedNode::ConnectTo(int peer_node_id, const std::string& address, uint16_t port) {
    // Prevent self-connection
    if (peer_node_id == node_id_) {
        return false;
    }

    // Generate peer address
    std::string peer_addr = address;
    if (peer_addr.empty()) {
        std::ostringstream oss;
        oss << "127.0.0." << (peer_node_id % 255);
        peer_addr = oss.str();
    }

// Construct NetworkAddress for new API
    protocol::NetworkAddress net_addr;
    net_addr.services = protocol::ServiceFlags::NODE_NETWORK;
    // Default to the peer's simulated listen port if caller passed the base regtest port
    uint16_t connect_port = port;
    if (connect_port == protocol::ports::REGTEST) {
        // In simulation, each node listens on REGTEST + node_id
        connect_port = static_cast<uint16_t>(protocol::ports::REGTEST + peer_node_id);
    }
    net_addr.port = connect_port;

    // Convert IP string to bytes (IPv4-mapped IPv6)
    asio::error_code ec;
    auto ip_addr = asio::ip::make_address(peer_addr, ec);

    if (ec) {
      LOG_ERROR("SimulatedNode::ConnectToPeer: Invalid IP address: {}", peer_addr);
      return false;
    }

    if (ip_addr.is_v4()) {
      auto v6_mapped = asio::ip::make_address_v6(
          asio::ip::v4_mapped, ip_addr.to_v4());
      auto bytes = v6_mapped.to_bytes();
      std::copy(bytes.begin(), bytes.end(), net_addr.ip.begin());
    } else {
      auto bytes = ip_addr.to_v6().to_bytes();
      std::copy(bytes.begin(), bytes.end(), net_addr.ip.begin());
    }

    // Use real NetworkManager to connect
    auto result = network_manager_->connect_to(net_addr);
    bool success = (result == network::ConnectionResult::Success);
    if (success) {
        stats_.connections_made++;
    }

    // Process events to ensure connection is initiated
    // This is important in fast (non-TSAN) builds where async operations complete quickly
    ProcessEvents();

    return success;
}

bool SimulatedNode::ConnectToFullRelay(int peer_node_id, const std::string& address, uint16_t port) {
    // Prevent self-connection
    if (peer_node_id == node_id_) {
        return false;
    }

    // Generate peer address
    std::string peer_addr = address;
    if (peer_addr.empty()) {
        std::ostringstream oss;
        oss << "127.0.0." << (peer_node_id % 255);
        peer_addr = oss.str();
    }

    // Construct NetworkAddress for new API
    protocol::NetworkAddress net_addr;
    net_addr.services = protocol::ServiceFlags::NODE_NETWORK;
    uint16_t connect_port = port;
    if (connect_port == protocol::ports::REGTEST) {
        connect_port = static_cast<uint16_t>(protocol::ports::REGTEST + peer_node_id);
    }
    net_addr.port = connect_port;

    // Convert IP string to bytes (IPv4-mapped IPv6)
    asio::error_code ec;
    auto ip_addr = asio::ip::make_address(peer_addr, ec);

    if (ec) {
        LOG_ERROR("SimulatedNode::ConnectToFullRelay: Invalid IP address: {}", peer_addr);
        return false;
    }

    if (ip_addr.is_v4()) {
        auto v6_mapped = asio::ip::make_address_v6(
            asio::ip::v4_mapped, ip_addr.to_v4());
        auto bytes = v6_mapped.to_bytes();
        std::copy(bytes.begin(), bytes.end(), net_addr.ip.begin());
    } else {
        auto bytes = ip_addr.to_v6().to_bytes();
        std::copy(bytes.begin(), bytes.end(), net_addr.ip.begin());
    }

    // Use connect_to with OUTBOUND_FULL_RELAY connection type (participates in ADDR relay)
    auto result = network_manager_->connect_to(net_addr, network::NetPermissionFlags::None, network::ConnectionType::OUTBOUND_FULL_RELAY);
    bool success = (result == network::ConnectionResult::Success);
    if (success) {
        stats_.connections_made++;
    }

    ProcessEvents();
    return success;
}

bool SimulatedNode::ConnectToBlockRelayOnly(int peer_node_id, const std::string& address, uint16_t port) {
    // Prevent self-connection
    if (peer_node_id == node_id_) {
        return false;
    }

    // Generate peer address
    std::string peer_addr = address;
    if (peer_addr.empty()) {
        std::ostringstream oss;
        oss << "127.0.0." << (peer_node_id % 255);
        peer_addr = oss.str();
    }

    // Construct NetworkAddress for new API
    protocol::NetworkAddress net_addr;
    net_addr.services = protocol::ServiceFlags::NODE_NETWORK;
    uint16_t connect_port = port;
    if (connect_port == protocol::ports::REGTEST) {
        connect_port = static_cast<uint16_t>(protocol::ports::REGTEST + peer_node_id);
    }
    net_addr.port = connect_port;

    // Convert IP string to bytes (IPv4-mapped IPv6)
    asio::error_code ec;
    auto ip_addr = asio::ip::make_address(peer_addr, ec);

    if (ec) {
        LOG_ERROR("SimulatedNode::ConnectToBlockRelayOnly: Invalid IP address: {}", peer_addr);
        return false;
    }

    if (ip_addr.is_v4()) {
        auto v6_mapped = asio::ip::make_address_v6(
            asio::ip::v4_mapped, ip_addr.to_v4());
        auto bytes = v6_mapped.to_bytes();
        std::copy(bytes.begin(), bytes.end(), net_addr.ip.begin());
    } else {
        auto bytes = ip_addr.to_v6().to_bytes();
        std::copy(bytes.begin(), bytes.end(), net_addr.ip.begin());
    }

    // Use connect_to with BLOCK_RELAY connection type
    auto result = network_manager_->connect_to(net_addr, network::NetPermissionFlags::None, network::ConnectionType::BLOCK_RELAY);
    bool success = (result == network::ConnectionResult::Success);
    if (success) {
        stats_.connections_made++;
    }

    ProcessEvents();
    return success;
}

void SimulatedNode::DisconnectFrom(int peer_node_id) {
    // Convert node_id to IP address, then find and disconnect the peer
    if (!network_manager_) {
        LOG_NET_TRACE("DisconnectFrom({}): no network_manager", peer_node_id);
        return;
    }

    // Get the peer's actual address from the simulated network
    // This is critical for nodes with custom addresses (e.g., "192.168.1.100")
    std::string peer_addr;
    if (sim_network_) {
        peer_addr = sim_network_->GetNodeAddress(peer_node_id);
    }
    // Fallback to default if not found in network
    if (peer_addr.empty()) {
        std::ostringstream oss;
        oss << "127.0.0." << (peer_node_id % 255);
        peer_addr = oss.str();
    }
    LOG_NET_DEBUG("DisconnectFrom({}): looking for peer with address '{}'", peer_node_id, peer_addr);

    // Get peer ID by address (this returns the ConnectionManager map key)
    auto& peer_mgr = network_manager_->peer_manager();

    // Search all peers to find one matching this address
    // We can't use find_peer_by_address() because:
    // - For outbound peers: target_port = protocol::ports::REGTEST
    // - For inbound peers: target_port = ephemeral source port (unknown)
    // Since each node has a unique IP (127.0.0.X), search by address only
    int peer_manager_id = -1;
    auto all_peers = peer_mgr.get_all_peers();
    for (const auto& peer : all_peers) {
        if (peer && peer->target_address() == peer_addr) {
            peer_manager_id = peer->id();
            break;
        }
    }

    if (peer_manager_id >= 0) {
        LOG_NET_DEBUG("DisconnectFrom({}): found peer_manager_id={}, disconnecting", peer_node_id, peer_manager_id);
        network_manager_->disconnect_from(peer_manager_id);
        stats_.disconnections++;

        // Process events to ensure disconnect is processed locally
        ProcessEvents();

        // NOTE: The remote node won't know about the disconnect until it processes
        // the connection close event. The test should call AdvanceTime() and ProcessEvents()
        // on the remote node after calling DisconnectFrom().
    } else {
        LOG_NET_DEBUG("DisconnectFrom({}): peer NOT FOUND (addr='{}')", peer_node_id, peer_addr);
        // Debug: list all peers and their addresses
        for (const auto& peer : all_peers) {
            if (peer) {
                LOG_NET_DEBUG("  peer={} target_address='{}' target_port={} is_inbound={}",
                    peer->id(), peer->target_address(), peer->target_port(), peer->is_inbound());
            }
        }
    }
}

uint256 SimulatedNode::MineBlock(const std::string& miner_address) {
    // Create block header
    CBlockHeader header;
    header.nVersion = 1;
    header.hashPrevBlock = GetTipHash();
    header.nTime = static_cast<uint32_t>(sim_network_->GetCurrentTime() / 1000);
    header.nBits = params_->GenesisBlock().nBits;

    // Random nonce
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint32_t> dis_nonce;
    header.nNonce = dis_nonce(gen);

    // Random miner address
    std::uniform_int_distribution<uint8_t> dis_byte(0, 255);
    for (int i = 0; i < 20; i++) {
        header.minerAddress.data()[i] = dis_byte(gen);
    }

    // Set dummy RandomX hash (PoW bypass enabled by default)
    header.hashRandomX.SetHex("0000000000000000000000000000000000000000000000000000000000000000");

    // Add to chainstate
    validation::ValidationState state;
auto* pindex = chainstate_->AcceptBlockHeader(header, state);

    if (pindex) {
        chainstate_->TryAddBlockIndexCandidate(pindex);
        chainstate_->ActivateBestChain();
        stats_.blocks_mined++;

        // Broadcast the block to peers via NetworkManager
        uint256 block_hash = header.GetHash();
        if (network_manager_) {
            size_t peer_count = network_manager_->active_peer_count();
            network_manager_->relay_block(block_hash);
        }

        // Process events to ensure the block relay messages are queued
        // This is important in fast (non-TSAN) builds where async operations complete quickly
        ProcessEvents();

        return block_hash;
    }

    return uint256();  // Failed
}

bool SimulatedNode::MineBlocks(int count, const std::string& miner_address) {
    for (int i = 0; i < count; i++) {
        uint256 hash = MineBlock(miner_address);
        if (hash.IsNull()) {
            return false;
        }
    }
    return true;
}

int SimulatedNode::GetTipHeight() const {
    const auto* tip = chainstate_->GetTip();
    return tip ? tip->nHeight : 0;
}

uint256 SimulatedNode::GetTipHash() const {
    const auto* tip = chainstate_->GetTip();
    return tip ? tip->GetBlockHash() : params_->GenesisBlock().GetHash();
}

const chain::CBlockIndex* SimulatedNode::GetTip() const {
    return chainstate_->GetTip();
}

bool SimulatedNode::GetIsIBD() const {
    return chainstate_->IsInitialBlockDownload();
}

uint256 SimulatedNode::GetBlockHash(int height) const {
    // Need to search through the chain to find block at given height
    const auto* tip = chainstate_->GetTip();
    if (!tip || height > tip->nHeight) {
        return uint256();
    }

    // Walk back from tip to find block at height
    const auto* pindex = tip;
    while (pindex && pindex->nHeight > height) {
        pindex = pindex->pprev;
    }

    return (pindex && pindex->nHeight == height) ? pindex->GetBlockHash() : uint256();
}

CBlockHeader SimulatedNode::GetBlockHeader(const uint256& hash) const {
    const auto* pindex = chainstate_->LookupBlockIndex(hash);
    return pindex ? pindex->GetBlockHeader() : CBlockHeader();
}

size_t SimulatedNode::GetOrphanCount() const {
    return chainstate_->GetOrphanHeaderCount();
}

void SimulatedNode::EvictExpiredOrphans() {
    chainstate_->EvictOrphanHeaders();
}

void SimulatedNode::ReceiveHeaders(int from_peer_id, const std::vector<CBlockHeader>& headers) {
    // This simulates receiving headers from a peer
    // Process headers directly through chainstate
    for (const auto& header : headers) {
        validation::ValidationState state;
        auto* pindex = chainstate_->AcceptBlockHeader(header, state);
        if (pindex) {
            chainstate_->TryAddBlockIndexCandidate(pindex);
        } else if (state.GetRejectReason() == "prev-blk-not-found") {
            // Add to orphan pool
            chainstate_->AddOrphanHeader(header, from_peer_id);
        }
    }
}

size_t SimulatedNode::GetPeerCount() const {
    if (network_manager_) {
        return network_manager_->active_peer_count();
    }
    return 0;
}

size_t SimulatedNode::GetOutboundPeerCount() const {
    if (network_manager_) {
        return network_manager_->outbound_peer_count();
    }
    return 0;
}

size_t SimulatedNode::GetInboundPeerCount() const {
    if (network_manager_) {
        return network_manager_->inbound_peer_count();
    }
    return 0;
}

bool SimulatedNode::IsBanned(const std::string& address) const {
    if (network_manager_) {
        return const_cast<network::NetworkManager*>(network_manager_.get())->peer_manager().IsBanned(address);
    }
    return false;
}

void SimulatedNode::Ban(const std::string& address, int64_t ban_time_seconds) {
    if (network_manager_) {
        network_manager_->peer_manager().Ban(address, ban_time_seconds);
    }
}

void SimulatedNode::Unban(const std::string& address) {
    if (network_manager_) {
        network_manager_->peer_manager().Unban(address);
    }
}

void SimulatedNode::ProcessEvents() {
    // Process pending async operations
    // poll() runs all ready handlers, which may post new work
    // Keep polling until no more work is immediately ready
    while (true) {
        size_t executed = io_context_.poll();
        if (executed == 0) {
            break;
        }
    }

    // Flush pending block announcements after processing events
    // This ensures announcements are sent regardless of how tests trigger event processing
    // (matches Bitcoin's SendMessages loop which flushes after processing events)
    if (network_manager_) {
        network_manager_->flush_block_announcements();
    }
}

void SimulatedNode::SetBlockRelayChunkSize(size_t chunk_size) {
    // Access BlockRelayManager directly through NetworkManager
    // Uses friend class privilege to call private SetInvChunkSize()
    if (network_manager_) {
        network_manager_->block_relay_for_test().SetInvChunkSize(chunk_size);
    }
}

void SimulatedNode::ProcessPeriodic() {
    // Run periodic maintenance tasks
    // In a real node, these run on timers, but in simulation they're triggered by AdvanceTime()
    if (network_manager_) {
        // Trigger initial sync selection deterministically (no timers)
        network_manager_->test_hook_check_initial_sync();

        network_manager_->peer_manager().process_periodic();

        // Process pending ADDR relays (trickle delay for privacy)
        network_manager_->discovery_manager().ProcessPendingAddrRelays();

        // Call announce_tip_to_peers() to add blocks to announcement queues
        // The actual flushing happens in ProcessEvents() (like Bitcoin's SendMessages loop)
        network_manager_->announce_tip_to_peers();
    }
}

} // namespace test
} // namespace unicity
