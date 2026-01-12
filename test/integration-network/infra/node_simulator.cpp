// Copyright (c) 2025 The Unicity Foundation
// NodeSimulator implementation - Sends malicious P2P messages for testing

#include "node_simulator.hpp"
#include "network/protocol.hpp"
#include "network/message.hpp"
#include "util/hash.hpp"
#include "chain/validation.hpp"
#include "chain/pow.hpp"
#include "chain/randomx_pow.hpp"
#include <random>

namespace unicity {
namespace test {

CBlockHeader NodeSimulator::CreateDummyHeader(const uint256& prev_hash, uint32_t nBits) {
    CBlockHeader header;
    header.nVersion = 1;
    header.hashPrevBlock = prev_hash;
    header.nTime = static_cast<uint32_t>(sim_network_->GetCurrentTime() / 1000);
    header.nBits = nBits;

    // Random nonce and miner address
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint32_t> dis_nonce;
    header.nNonce = dis_nonce(gen);

    std::uniform_int_distribution<uint8_t> dis_byte(0, 255);
    for (int i = 0; i < 20; i++) {
        header.minerAddress.data()[i] = dis_byte(gen);
    }

    // Set dummy RandomX hash (needed for commitment check)
    header.hashRandomX.SetHex("0000000000000000000000000000000000000000000000000000000000000000");

    return header;
}

void NodeSimulator::SendOrphanHeaders(int peer_node_id, size_t count) {
    // To trigger orphan-limit DoS protection, we need:
    // 1. First header must connect to victim's known chain
    // 2. Subsequent headers have random parents (orphans)
    // This passes the "first header connects" check but creates many orphans

    std::vector<CBlockHeader> headers;
    std::random_device rd;
    std::mt19937_64 gen(rd());

    // First header connects to victim's tip
    CBlockHeader first_header = CreateDummyHeader(GetTipHash(), params_->GenesisBlock().nBits);
    headers.push_back(first_header);

    // Remaining headers are orphans (random parents)
    for (size_t i = 1; i < count; i++) {
        // Random prev_hash - won't exist in victim's chain
        uint256 random_prev_hash;
        std::uniform_int_distribution<uint8_t> dis_byte(0, 255);
        for (int j = 0; j < 32; j++) {
            random_prev_hash.data()[j] = dis_byte(gen);
        }

        CBlockHeader header = CreateDummyHeader(random_prev_hash, params_->GenesisBlock().nBits);
        headers.push_back(header);
    }

    // Serialize HEADERS message
    message::HeadersMessage msg;
    msg.headers = headers;
    auto payload = msg.serialize();

    // Create message header
    protocol::MessageHeader header(protocol::magic::REGTEST, protocol::commands::HEADERS, static_cast<uint32_t>(payload.size()));
    uint256 hash = Hash(payload);
    std::memcpy(header.checksum.data(), hash.begin(), 4);
    auto header_bytes = message::serialize_header(header);

    // Combine header + payload
    std::vector<uint8_t> full_message;
    full_message.insert(full_message.end(), header_bytes.begin(), header_bytes.end());
    full_message.insert(full_message.end(), payload.begin(), payload.end());

    // Inject directly into SimulatedNetwork, bypassing normal P2P validation
    sim_network_->SendMessage(GetId(), peer_node_id, full_message);
}

void NodeSimulator::SendInvalidPoWHeaders(int peer_node_id, const uint256& prev_hash, size_t count) {
    std::vector<CBlockHeader> headers;
    for (size_t i = 0; i < count; i++) {
        CBlockHeader header = CreateDummyHeader(prev_hash, 0x00000001);  // Impossible difficulty
        header.hashRandomX.SetNull();  // Invalid: NULL RandomX hash
        headers.push_back(header);
    }

    // Serialize and inject
    message::HeadersMessage msg;
    msg.headers = headers;
    auto payload = msg.serialize();

    protocol::MessageHeader header(protocol::magic::REGTEST, protocol::commands::HEADERS, static_cast<uint32_t>(payload.size()));
        uint256 hash = Hash(payload);
        std::memcpy(header.checksum.data(), hash.begin(), 4);
    auto header_bytes = message::serialize_header(header);

    std::vector<uint8_t> full_message;
    full_message.insert(full_message.end(), header_bytes.begin(), header_bytes.end());
    full_message.insert(full_message.end(), payload.begin(), payload.end());

    sim_network_->SendMessage(GetId(), peer_node_id, full_message);
}

void NodeSimulator::SendNonContinuousHeaders(int peer_node_id, const uint256& prev_hash) {
    // Create two headers that don't connect
    CBlockHeader header1 = CreateDummyHeader(prev_hash, params_->GenesisBlock().nBits);
    CBlockHeader header2 = CreateDummyHeader(uint256(), params_->GenesisBlock().nBits);  // Wrong prev_hash!

    std::vector<CBlockHeader> headers = {header1, header2};

    // Serialize and inject
    message::HeadersMessage msg;
    msg.headers = headers;
    auto payload = msg.serialize();

    protocol::MessageHeader header(protocol::magic::REGTEST, protocol::commands::HEADERS, static_cast<uint32_t>(payload.size()));
        uint256 hash = Hash(payload);
        std::memcpy(header.checksum.data(), hash.begin(), 4);
    auto header_bytes = message::serialize_header(header);

    std::vector<uint8_t> full_message;
    full_message.insert(full_message.end(), header_bytes.begin(), header_bytes.end());
    full_message.insert(full_message.end(), payload.begin(), payload.end());

    sim_network_->SendMessage(GetId(), peer_node_id, full_message);
}

void NodeSimulator::SendOversizedHeaders(int peer_node_id, size_t count) {
    if (count <= protocol::MAX_HEADERS_SIZE) {
        return;
    }

    std::vector<CBlockHeader> headers;
    uint256 prev_hash = GetTipHash();

    for (size_t i = 0; i < count; i++) {
        CBlockHeader header = CreateDummyHeader(prev_hash, params_->GenesisBlock().nBits);
        headers.push_back(header);
        prev_hash = header.GetHash();
    }

    // Serialize and inject oversized message
    message::HeadersMessage msg;
    msg.headers = headers;
    auto payload = msg.serialize();

    protocol::MessageHeader header(protocol::magic::REGTEST, protocol::commands::HEADERS, static_cast<uint32_t>(payload.size()));
        uint256 hash = Hash(payload);
        std::memcpy(header.checksum.data(), hash.begin(), 4);
    auto header_bytes = message::serialize_header(header);

    std::vector<uint8_t> full_message;
    full_message.insert(full_message.end(), header_bytes.begin(), header_bytes.end());
    full_message.insert(full_message.end(), payload.begin(), payload.end());

    sim_network_->SendMessage(GetId(), peer_node_id, full_message);
}

uint256 NodeSimulator::MineBlockPrivate(const std::string& miner_address) {
    // Create block header (same as normal MineBlock)
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

    // Bypass PoW (bypass enabled by default)
    header.hashRandomX.SetNull();

    // Add to chainstate
    validation::ValidationState state;
    auto& chainstate = GetChainstate();
    auto* pindex = chainstate.AcceptBlockHeader(header, state);

    if (pindex) {
        chainstate.TryAddBlockIndexCandidate(pindex);
        chainstate.ActivateBestChain();

        uint256 block_hash = header.GetHash();

        // DO NOT call relay_block() - keep it private!
        return block_hash;
    }

    return uint256();  // Failed
}

void NodeSimulator::BroadcastBlock(const uint256& block_hash, int peer_node_id) {
    // Look up the block header from our chainstate
    auto& chainstate = GetChainstate();
    const chain::CBlockIndex* pindex = chainstate.LookupBlockIndex(block_hash);

    if (!pindex) {
        return;
    }

    // Get the block header
    CBlockHeader header = pindex->GetBlockHeader();

    // Send as HEADERS message directly to peer
    std::vector<CBlockHeader> headers = {header};
    message::HeadersMessage msg;
    msg.headers = headers;
    auto payload = msg.serialize();

    protocol::MessageHeader msg_header(protocol::magic::REGTEST, protocol::commands::HEADERS, static_cast<uint32_t>(payload.size()));
    uint256 hash = Hash(payload);
    std::memcpy(msg_header.checksum.data(), hash.begin(), 4);
    auto header_bytes = message::serialize_header(msg_header);

    std::vector<uint8_t> full_message;
    full_message.insert(full_message.end(), header_bytes.begin(), header_bytes.end());
    full_message.insert(full_message.end(), payload.begin(), payload.end());

    sim_network_->SendMessage(GetId(), peer_node_id, full_message);
}

void NodeSimulator::SendLowWorkHeaders(int peer_node_id, const std::vector<uint256>& block_hashes) {
    // Look up all the block headers from our chainstate
    auto& chainstate = GetChainstate();
    std::vector<CBlockHeader> headers;

    for (const auto& block_hash : block_hashes) {
        const chain::CBlockIndex* pindex = chainstate.LookupBlockIndex(block_hash);

        if (!pindex) {
            continue;
        }

        headers.push_back(pindex->GetBlockHeader());
    }

    if (headers.empty()) {
        return;
    }

    // Serialize HEADERS message
    message::HeadersMessage msg;
    msg.headers = headers;
    auto payload = msg.serialize();

    protocol::MessageHeader msg_header(protocol::magic::REGTEST, protocol::commands::HEADERS, static_cast<uint32_t>(payload.size()));
    uint256 hash = Hash(payload);
    std::memcpy(msg_header.checksum.data(), hash.begin(), 4);
    auto header_bytes = message::serialize_header(msg_header);

    std::vector<uint8_t> full_message;
    full_message.insert(full_message.end(), header_bytes.begin(), header_bytes.end());
    full_message.insert(full_message.end(), payload.begin(), payload.end());

    // Inject message directly into network
    sim_network_->SendMessage(GetId(), peer_node_id, full_message);
}

std::pair<uint256, uint256> NodeSimulator::SendOutOfOrderHeaders(int peer_node_id, const uint256& prev_hash) {
    // Create parent header (builds on prev_hash)
    CBlockHeader parent_header = CreateDummyHeader(prev_hash, params_->GenesisBlock().nBits);
    parent_header.hashRandomX.SetNull();  // Bypass PoW validation
    uint256 parent_hash = parent_header.GetHash();

    // Create child header (builds on parent - will be orphan if sent first)
    CBlockHeader child_header = CreateDummyHeader(parent_hash, params_->GenesisBlock().nBits);
    child_header.nTime = parent_header.nTime + 1;  // Ensure different hash
    child_header.hashRandomX.SetNull();  // Bypass PoW validation
    uint256 child_hash = child_header.GetHash();

    // Helper lambda to send a single header
    auto send_header = [this, peer_node_id](const CBlockHeader& hdr) {
        std::vector<CBlockHeader> headers = {hdr};
        message::HeadersMessage msg;
        msg.headers = headers;
        auto payload = msg.serialize();

        protocol::MessageHeader msg_header(protocol::magic::REGTEST, protocol::commands::HEADERS, static_cast<uint32_t>(payload.size()));
        uint256 hash = Hash(payload);
        std::memcpy(msg_header.checksum.data(), hash.begin(), 4);
        auto header_bytes = message::serialize_header(msg_header);

        std::vector<uint8_t> full_message;
        full_message.insert(full_message.end(), header_bytes.begin(), header_bytes.end());
        full_message.insert(full_message.end(), payload.begin(), payload.end());

        sim_network_->SendMessage(GetId(), peer_node_id, full_message);
    };

    // Send CHILD FIRST (will become orphan - parent unknown)
    send_header(child_header);

    // Process the orphan
    sim_network_->ProcessMessages(sim_network_->GetCurrentTime());

    // Send PARENT SECOND (should trigger orphan resolution)
    send_header(parent_header);

    return {parent_hash, child_hash};
}

void NodeSimulator::SendValidSideChainHeaders(int peer_node_id, const uint256& fork_point, size_t count) {
    // Create a chain of valid headers building on fork_point
    // Each header has bypass PoW enabled so it will be accepted
    std::vector<CBlockHeader> headers;
    uint256 prev_hash = fork_point;

    // Generate random bytes for uniqueness
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint32_t> dis_nonce;
    std::uniform_int_distribution<uint8_t> dis_byte(0, 255);

    for (size_t i = 0; i < count; i++) {
        CBlockHeader header;
        header.nVersion = 1;
        header.hashPrevBlock = prev_hash;
        header.nTime = static_cast<uint32_t>(sim_network_->GetCurrentTime() / 1000) + static_cast<uint32_t>(i);
        header.nBits = params_->GenesisBlock().nBits;
        header.nNonce = dis_nonce(gen);

        // Random miner address for uniqueness
        for (int j = 0; j < 20; j++) {
            header.minerAddress.data()[j] = dis_byte(gen);
        }

        // Set null RandomX hash - PoW bypass mode will accept this
        header.hashRandomX.SetNull();

        headers.push_back(header);
        prev_hash = header.GetHash();
    }

    if (headers.empty()) {
        return;
    }

    // Serialize HEADERS message
    message::HeadersMessage msg;
    msg.headers = headers;
    auto payload = msg.serialize();

    protocol::MessageHeader msg_header(protocol::magic::REGTEST, protocol::commands::HEADERS, static_cast<uint32_t>(payload.size()));
    uint256 hash = Hash(payload);
    std::memcpy(msg_header.checksum.data(), hash.begin(), 4);
    auto header_bytes = message::serialize_header(msg_header);

    std::vector<uint8_t> full_message;
    full_message.insert(full_message.end(), header_bytes.begin(), header_bytes.end());
    full_message.insert(full_message.end(), payload.begin(), payload.end());

    // Inject message directly into network
    sim_network_->SendMessage(GetId(), peer_node_id, full_message);
}

} // namespace test
} // namespace unicity
