// Copyright (c) 2025 The Unicity Foundation
// DoS Attack Simulator - Unified infrastructure for DoS attack testing
//
// Provides high-level attack primitives for testing denial-of-service defenses:
// - Message flooding (buffer overflow, oversized messages)
// - Validation attacks (invalid PoW, low-work headers, unconnecting headers)
// - Connection attacks (rapid reconnect, stalling)
//
// Usage:
//   SimulatedNetwork network(42);
//   SimulatedNode victim(1, &network);
//   DoSAttackSimulator sim(&network, &victim);
//
//   auto result = sim.SendMessageFlood(attacker, 30, 256*1024);
//   CHECK(result.triggered_disconnect);
//   INFO(sim.GenerateReport());

#ifndef UNICITY_TEST_DOS_ATTACK_SIMULATOR_HPP
#define UNICITY_TEST_DOS_ATTACK_SIMULATOR_HPP

#include "simulated_network.hpp"
#include "simulated_node.hpp"
#include "node_simulator.hpp"
#include "peer_factory.hpp"
#include "../test_orchestrator.hpp"
#include "network/message.hpp"
#include "network/protocol.hpp"
#include "network/addr_relay_manager.hpp"
#include "chain/chainparams.hpp"
#include "util/hash.hpp"

#include <memory>
#include <ctime>
#include <vector>
#include <string>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <optional>

namespace unicity {
namespace test {

/**
 * DoSAttackSimulator - Unified DoS attack testing infrastructure
 */
class DoSAttackSimulator {
public:
    // =========================================================================
    // Result Structures
    // =========================================================================

    /**
     * Result of any DoS attack attempt
     */
    struct AttackResult {
        // Attack identification
        std::string attack_type;
        std::string attack_description;

        // Outcome
        bool triggered_disconnect{false};
        bool peer_discouraged{false};
        bool peer_banned{false};
        bool misbehaving{false};

        // Volume metrics
        size_t messages_sent{0};
        size_t bytes_sent{0};
        size_t messages_accepted{0};
        size_t messages_rejected{0};

        // Timing
        std::chrono::milliseconds duration{0};

        // Defense triggered
        std::string defense_triggered;  // "disconnect", "rate_limit", "ignore", "ban", etc.

        // Chain integrity
        bool victim_chain_intact{true};
        int victim_height_before{0};
        int victim_height_after{0};
    };

    /**
     * Snapshot of node state for before/after comparison
     */
    struct NodeSnapshot {
        size_t peer_count{0};
        size_t inbound_count{0};
        size_t outbound_count{0};
        int chain_height{0};
        std::chrono::steady_clock::time_point timestamp;
    };

    // =========================================================================
    // Constructor
    // =========================================================================

    DoSAttackSimulator(SimulatedNetwork* network, SimulatedNode* victim)
        : network_(network)
        , victim_(victim)
        , orchestrator_(network)
    {
        RecordSnapshot(before_);
    }

    // =========================================================================
    // Message Flooding Attacks
    // =========================================================================

    /**
     * Send a flood of messages to trigger receive buffer overflow
     *
     * Two modes:
     * 1. Complete messages (declared_size not set): Valid messages with correct checksum
     * 2. Partial payload attack (declared_size > payload_size): Declares large size but
     *    sends small payload, causing buffer to fill waiting for rest of data
     *
     * @param attacker Node sending the flood
     * @param message_count Number of messages to send
     * @param payload_size_bytes Size of actual payload sent
     * @param declared_size Optional: declared size in header (for partial payload attacks)
     * @return Attack result
     */
    AttackResult SendMessageFlood(
            SimulatedNode& attacker,
            size_t message_count,
            size_t payload_size_bytes,
            std::optional<size_t> declared_size = std::nullopt) {

        AttackResult result;
        result.attack_type = "MESSAGE_FLOOD";
        result.attack_description = "Buffer overflow via message flooding";

        auto start = std::chrono::steady_clock::now();

        // Build payload
        std::vector<uint8_t> payload(payload_size_bytes, 0);

        // Determine if this is a partial payload attack
        bool partial_payload_attack = declared_size.has_value() &&
                                      declared_size.value() > payload_size_bytes;

        std::vector<uint8_t> hdr_bytes;

        if (partial_payload_attack) {
            // Partial payload attack: declare large size but send small payload
            // This fills the receive buffer waiting for more data
            // Use raw header construction (checksum won't match, but buffer fills first)
            protocol::MessageHeader hdr(
                protocol::magic::REGTEST,
                protocol::commands::PING,
                static_cast<uint32_t>(declared_size.value())
            );
            hdr_bytes = message::serialize_header(hdr);
        } else {
            // Complete message: compute correct checksum so message is processed
            auto hdr = message::create_header(
                protocol::magic::REGTEST,
                protocol::commands::PING,
                payload
            );
            hdr_bytes = message::serialize_header(hdr);
        }

        // Send flood
        for (size_t i = 0; i < message_count; i++) {
            std::vector<uint8_t> msg;
            msg.reserve(hdr_bytes.size() + payload.size());
            msg.insert(msg.end(), hdr_bytes.begin(), hdr_bytes.end());
            msg.insert(msg.end(), payload.begin(), payload.end());

            network_->SendMessage(attacker.GetId(), victim_->GetId(), msg);
            result.messages_sent++;
            result.bytes_sent += msg.size();
        }

        // Let messages process
        orchestrator_.AdvanceTime(std::chrono::seconds(2));

        // Check result - attacker peer count dropping indicates disconnect
        result.triggered_disconnect = (attacker.GetPeerCount() == 0);

        if (result.triggered_disconnect) {
            result.defense_triggered = partial_payload_attack ?
                "recv_buffer_overflow" : "message_processing";
        }

        auto end = std::chrono::steady_clock::now();
        result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

        RecordSnapshot(after_);
        result.victim_chain_intact = (after_.chain_height >= before_.chain_height);
        result.victim_height_before = before_.chain_height;
        result.victim_height_after = after_.chain_height;

        last_result_ = result;
        return result;
    }

    /**
     * Send oversized messages (headers, addr, inv) exceeding protocol limits
     *
     * @param attacker NodeSimulator sending oversized messages
     * @param message_type Type of message ("headers", "addr", "inv")
     * @param count Number exceeding the maximum allowed
     * @return Attack result
     */
    AttackResult SendOversizedMessages(
            NodeSimulator& attacker,
            const std::string& message_type,
            size_t count) {

        AttackResult result;
        result.attack_type = "OVERSIZED_" + message_type;
        result.attack_description = "Protocol violation: oversized " + message_type;

        auto start = std::chrono::steady_clock::now();

        if (message_type == "headers") {
            // MAX_HEADERS_SIZE = 80000
            attacker.SendOversizedHeaders(victim_->GetId(), count);
            result.messages_sent = 1;
        }
        // Note: SendOversizedAddr not implemented in NodeSimulator
        // Use raw message injection via SimulatedNetwork if needed

        orchestrator_.AdvanceTime(std::chrono::seconds(2));

        // Check if attacker is still connected
        result.triggered_disconnect = (attacker.GetPeerCount() == 0);

        // Check if victim discouraged the attacker
        result.peer_discouraged = victim_->GetNetworkManager().peer_manager()
            .IsDiscouraged(attacker.GetAddress());

        if (result.triggered_disconnect) {
            result.defense_triggered = "protocol_violation";
        }

        auto end = std::chrono::steady_clock::now();
        result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

        RecordSnapshot(after_);
        last_result_ = result;
        return result;
    }

    // =========================================================================
    // Validation-Breaking Attacks
    // =========================================================================

    /**
     * Send headers with invalid proof-of-work
     *
     * @param attacker NodeSimulator with attack capabilities
     * @param count Number of invalid headers to send
     * @param parent_hash Optional parent to build on (uses victim tip if not specified)
     * @return Attack result
     */
    AttackResult SendInvalidPoWHeaders(
            NodeSimulator& attacker,
            size_t count,
            const std::optional<uint256>& parent_hash = std::nullopt) {

        AttackResult result;
        result.attack_type = "INVALID_POW";
        result.attack_description = "Headers with invalid proof-of-work";
        result.victim_height_before = victim_->GetTipHeight();

        auto start = std::chrono::steady_clock::now();

        uint256 parent = parent_hash.value_or(victim_->GetTipHash());
        attacker.SendInvalidPoWHeaders(victim_->GetId(), parent, count);
        result.messages_sent = 1;

        orchestrator_.AdvanceTime(std::chrono::seconds(2));

        result.triggered_disconnect = (attacker.GetPeerCount() == 0);
        result.peer_discouraged = victim_->GetNetworkManager().peer_manager()
            .IsDiscouraged(attacker.GetAddress());

        // Check if peer is misbehaving (still connected)
        int peer_id = orchestrator_.GetPeerId(*victim_, attacker);
        if (peer_id >= 0) {
            result.misbehaving = victim_->GetNetworkManager().peer_manager()
                .IsMisbehaving(peer_id);
        }

        if (result.peer_discouraged) {
            result.defense_triggered = "misbehavior_instant_discourage";
        }

        auto end = std::chrono::steady_clock::now();
        result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

        result.victim_height_after = victim_->GetTipHeight();
        result.victim_chain_intact = (result.victim_height_after == result.victim_height_before);

        RecordSnapshot(after_);
        last_result_ = result;
        return result;
    }

    /**
     * Send headers with insufficient cumulative work (low-work attack)
     *
     * @param attacker NodeSimulator with attack capabilities
     * @param batch_count Number of header batches to send
     * @param headers_per_batch Headers per batch
     * @return Attack result
     */
    AttackResult SendLowWorkHeaders(
            NodeSimulator& attacker,
            size_t batch_count,
            size_t headers_per_batch = 10) {

        AttackResult result;
        result.attack_type = "LOW_WORK_HEADERS";
        result.attack_description = "Headers with insufficient cumulative work";
        result.victim_height_before = victim_->GetTipHeight();

        auto start = std::chrono::steady_clock::now();

        // Build a chain of low-work headers
        std::vector<uint256> hashes;
        for (size_t i = 0; i < batch_count; i++) {
            uint256 fake_hash;
            std::memset(fake_hash.data(), static_cast<int>(i + 1), 32);
            hashes.push_back(fake_hash);
        }

        // Send as low work headers
        attacker.SendLowWorkHeaders(victim_->GetId(), hashes);
        result.messages_sent = 1;

        orchestrator_.AdvanceTime(std::chrono::seconds(1));

        // Low-work headers should be silently ignored (no disconnect, no penalty)
        result.triggered_disconnect = (attacker.GetPeerCount() == 0);
        result.peer_discouraged = victim_->GetNetworkManager().peer_manager()
            .IsDiscouraged(attacker.GetAddress());

        if (!result.triggered_disconnect && !result.peer_discouraged) {
            result.defense_triggered = "silent_ignore";
        }

        auto end = std::chrono::steady_clock::now();
        result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

        result.victim_height_after = victim_->GetTipHeight();
        result.victim_chain_intact = (result.victim_height_after == result.victim_height_before);

        RecordSnapshot(after_);
        last_result_ = result;
        return result;
    }

    /**
     * Send orphan headers (headers with unknown parent)
     *
     * @param attacker NodeSimulator with attack capabilities
     * @param total_orphans Total orphan headers to send
     * @param batch_size Headers per message
     * @return Attack result
     */
    AttackResult SendOrphanHeaders(
            NodeSimulator& attacker,
            size_t total_orphans,
            size_t batch_size = 50) {

        AttackResult result;
        result.attack_type = "ORPHAN_SPAM";
        result.attack_description = "Orphan headers with unknown parents";
        result.victim_height_before = victim_->GetTipHeight();

        auto start = std::chrono::steady_clock::now();

        size_t batches = (total_orphans + batch_size - 1) / batch_size;
        for (size_t i = 0; i < batches; i++) {
            size_t this_batch = std::min(batch_size, total_orphans - i * batch_size);
            attacker.SendOrphanHeaders(victim_->GetId(), this_batch);
            result.messages_sent++;
            orchestrator_.AdvanceTime(std::chrono::milliseconds(50));
        }

        orchestrator_.AdvanceTime(std::chrono::seconds(1));

        result.triggered_disconnect = (attacker.GetPeerCount() == 0);
        result.peer_discouraged = victim_->GetNetworkManager().peer_manager()
            .IsDiscouraged(attacker.GetAddress());

        // Orphan spam should be rate-limited or ignored
        if (!result.triggered_disconnect) {
            result.defense_triggered = "orphan_limit";
        }

        auto end = std::chrono::steady_clock::now();
        result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

        result.victim_height_after = victim_->GetTipHeight();
        result.victim_chain_intact = (result.victim_height_after == result.victim_height_before);

        RecordSnapshot(after_);
        last_result_ = result;
        return result;
    }

    // =========================================================================
    // Connection Attacks
    // =========================================================================

    /**
     * Rapid reconnection attempts from same IP
     *
     * Tests the per-IP connection throttle by having a SINGLE node repeatedly
     * connect and disconnect. The throttle tracks by IP address, so the same
     * node reconnecting tests the actual throttle mechanism.
     *
     * @param attacker SimulatedNode to use for repeated connection attempts
     * @param attempts Number of reconnection attempts
     * @param interval Delay between attempts
     * @return Attack result
     */
    AttackResult RapidReconnect(
            SimulatedNode& attacker,
            size_t attempts,
            std::chrono::milliseconds interval = std::chrono::milliseconds(100)) {

        AttackResult result;
        result.attack_type = "RAPID_RECONNECT";
        result.attack_description = "Connection throttle test from IP " + attacker.GetAddress();

        auto start = std::chrono::steady_clock::now();

        size_t successful = 0;
        size_t rejected = 0;

        for (size_t i = 0; i < attempts; i++) {
            // Try to connect
            bool connected = attacker.ConnectTo(victim_->GetId(), victim_->GetAddress());

            // Wait for connection to establish or be rejected
            orchestrator_.AdvanceTime(std::chrono::milliseconds(200));

            if (connected && attacker.GetPeerCount() > 0) {
                successful++;
                // Disconnect for next attempt
                attacker.Disconnect(victim_->GetId());
                // Wait for disconnect to process
                orchestrator_.AdvanceTime(std::chrono::milliseconds(100));
            } else {
                rejected++;
            }

            result.messages_sent++;

            // Wait between attempts
            orchestrator_.AdvanceTime(interval);
        }

        result.messages_accepted = successful;
        result.messages_rejected = rejected;

        // Connection throttle: max 3 connections per 60 seconds per IP
        // So first 3 should succeed, rest rejected
        if (rejected > 0) {
            result.defense_triggered = "connection_throttle";
        }

        auto end = std::chrono::steady_clock::now();
        result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

        RecordSnapshot(after_);
        last_result_ = result;
        return result;
    }

    /**
     * Sybil connection attempt from multiple IPs in same netgroup
     *
     * Tests the per-netgroup limit by creating multiple nodes from the same /16.
     * Each node has a unique IP within the subnet, testing netgroup limits
     * rather than per-IP throttle.
     *
     * @param attacker_factory PeerFactory to create attacker nodes
     * @param subnet_base Base of /16 subnet (e.g., "192.168.0.0")
     * @param num_attackers Number of attacker nodes to create
     * @return Attack result
     */
    AttackResult SybilConnectionFlood(
            PeerFactory& attacker_factory,
            const std::string& subnet_base,
            size_t num_attackers) {

        AttackResult result;
        result.attack_type = "SYBIL_CONNECTION_FLOOD";
        result.attack_description = "Netgroup exhaustion from " + subnet_base + "/16";

        auto start = std::chrono::steady_clock::now();

        // Create attackers in same netgroup
        auto attackers = attacker_factory.CreateSybilCluster(
            num_attackers, 1000, subnet_base);

        size_t successful = 0;
        size_t rejected = 0;

        for (auto& attacker : attackers) {
            attacker->ConnectTo(victim_->GetId(), victim_->GetAddress());
            result.messages_sent++;
        }

        // Wait for connections to establish
        orchestrator_.AdvanceTime(std::chrono::seconds(2));

        // Count results
        for (auto& attacker : attackers) {
            if (attacker->GetPeerCount() > 0) {
                successful++;
            } else {
                rejected++;
            }
        }

        result.messages_accepted = successful;
        result.messages_rejected = rejected;

        // Per-netgroup limit is 4, so at most 4 should succeed
        if (rejected > 0) {
            result.defense_triggered = "netgroup_limit";
        }

        auto end = std::chrono::steady_clock::now();
        result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

        RecordSnapshot(after_);
        last_result_ = result;
        return result;
    }

    /**
     * Stalling attack - peer stops responding to requests
     *
     * Simulates a stalling attack by dropping all packets from attacker to victim.
     * The attacker appears connected but never sends responses, triggering
     * the victim's stall detection timeout.
     *
     * @param attacker Attacker node that will stall
     * @param stall_duration How long to stall before checking result
     * @return Attack result
     */
    AttackResult StallResponses(
            SimulatedNode& attacker,
            std::chrono::seconds stall_duration) {

        AttackResult result;
        result.attack_type = "STALLING";
        result.attack_description = "Peer stops responding (100% packet loss)";

        auto start = std::chrono::steady_clock::now();

        // Simulate stalling by dropping all packets from attacker to victim
        SimulatedNetwork::NetworkConditions drop;
        drop.packet_loss_rate = 1.0;  // 100% packet loss = stalling
        network_->SetLinkConditions(attacker.GetId(), victim_->GetId(), drop);

        // Also trigger header sync timers periodically to detect stall
        for (int i = 0; i < stall_duration.count(); i++) {
            orchestrator_.AdvanceTime(std::chrono::seconds(1));

            // Trigger stall detection timer processing
            victim_->ProcessHeaderSyncTimers();

            // Check if victim detected stall and disconnected
            if (attacker.GetPeerCount() == 0) {
                result.triggered_disconnect = true;
                result.defense_triggered = "stall_timeout";
                break;
            }
        }

        // Restore normal network conditions
        SimulatedNetwork::NetworkConditions normal;
        network_->SetLinkConditions(attacker.GetId(), victim_->GetId(), normal);

        auto end = std::chrono::steady_clock::now();
        result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

        RecordSnapshot(after_);
        last_result_ = result;
        return result;
    }

    // =========================================================================
    // Protocol Message Attacks
    // =========================================================================


    /**
     * Send oversized ADDR message (exceeds MAX_ADDR_SIZE = 1,000)
     *
     * @param attacker SimulatedNode sending the message
     * @param count Number of addresses to declare (> 1,000 for attack)
     * @return Attack result
     */
    AttackResult SendOversizedAddr(
            SimulatedNode& attacker,
            size_t count) {

        AttackResult result;
        result.attack_type = "OVERSIZED_ADDR";
        result.attack_description = "ADDR with " + std::to_string(count) +
            " addresses (MAX=" + std::to_string(protocol::MAX_ADDR_SIZE) + ")";

        auto start = std::chrono::steady_clock::now();

        // Build payload: just the count (parser rejects by count alone)
        message::MessageSerializer s;
        s.write_varint(count);
        auto payload = s.data();

        // Create header with correct checksum
        protocol::MessageHeader header(protocol::magic::REGTEST,
            protocol::commands::ADDR, static_cast<uint32_t>(payload.size()));
        uint256 hash = Hash(payload);
        std::memcpy(header.checksum.data(), hash.begin(), 4);
        auto header_bytes = message::serialize_header(header);

        std::vector<uint8_t> full;
        full.reserve(header_bytes.size() + payload.size());
        full.insert(full.end(), header_bytes.begin(), header_bytes.end());
        full.insert(full.end(), payload.begin(), payload.end());

        network_->SendMessage(attacker.GetId(), victim_->GetId(), full);
        result.messages_sent = 1;
        result.bytes_sent = full.size();

        orchestrator_.AdvanceTime(std::chrono::seconds(2));

        result.triggered_disconnect = (attacker.GetPeerCount() == 0);
        if (result.triggered_disconnect) {
            result.defense_triggered = "oversized_addr_rejected";
        }

        auto end = std::chrono::steady_clock::now();
        result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

        RecordSnapshot(after_);
        last_result_ = result;
        return result;
    }

    /**
     * Send CompactSize overflow attack (declares impossibly large allocation)
     *
     * Historical vulnerability: CompactSize read without MAX_SIZE cap could trigger
     * huge allocations. Attack sends 0xFF prefix with 0xFFFFFFFFFFFFFFFF to claim
     * 18 exabytes.
     *
     * @param attacker SimulatedNode sending the message
     * @param message_type Message type to attack ("headers", "inv", "addr")
     * @return Attack result
     */
    AttackResult SendCompactSizeOverflow(
            SimulatedNode& attacker,
            const std::string& message_type = "headers") {

        AttackResult result;
        result.attack_type = "COMPACTSIZE_OVERFLOW";
        result.attack_description = "CompactSize overflow in " + message_type +
            " (18 EB allocation attempt)";

        auto start = std::chrono::steady_clock::now();

        // Build malicious payload: CompactSize = 0xFF + 0xFFFFFFFFFFFFFFFF (LE)
        std::vector<uint8_t> payload;
        payload.reserve(9);
        payload.push_back(0xFF);
        for (int i = 0; i < 8; ++i) payload.push_back(0xFF);

        // Determine command
        std::string command = protocol::commands::HEADERS;
        if (message_type == "addr") command = protocol::commands::ADDR;

        // Create header with correct checksum
        protocol::MessageHeader header(protocol::magic::REGTEST,
            command, static_cast<uint32_t>(payload.size()));
        uint256 hash = Hash(payload);
        std::memcpy(header.checksum.data(), hash.begin(), 4);
        auto header_bytes = message::serialize_header(header);

        std::vector<uint8_t> full;
        full.reserve(header_bytes.size() + payload.size());
        full.insert(full.end(), header_bytes.begin(), header_bytes.end());
        full.insert(full.end(), payload.begin(), payload.end());

        network_->SendMessage(attacker.GetId(), victim_->GetId(), full);
        result.messages_sent = 1;
        result.bytes_sent = full.size();

        orchestrator_.AdvanceTime(std::chrono::seconds(2));

        result.triggered_disconnect = (attacker.GetPeerCount() == 0);
        if (result.triggered_disconnect) {
            result.defense_triggered = "compactsize_overflow_rejected";
        }

        auto end = std::chrono::steady_clock::now();
        result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

        RecordSnapshot(after_);
        last_result_ = result;
        return result;
    }

    /**
     * Send ADDR flood to test rate limiting
     *
     * @param attacker SimulatedNode sending the flood
     * @param num_messages Number of ADDR messages to send
     * @param addrs_per_message Addresses per message (max 1000)
     * @param delay_between Delay between messages
     * @return Attack result with addresses processed count
     */
    AttackResult SendAddrFlood(
            SimulatedNode& attacker,
            size_t num_messages,
            size_t addrs_per_message = protocol::MAX_ADDR_SIZE,
            std::chrono::milliseconds delay_between = std::chrono::milliseconds(100)) {

        AttackResult result;
        result.attack_type = "ADDR_FLOOD";
        result.attack_description = std::to_string(num_messages) + " ADDR messages × " +
            std::to_string(addrs_per_message) + " addresses";

        auto start = std::chrono::steady_clock::now();

        // Get initial address count
        auto& discovery_mgr = victim_->GetDiscoveryManager();
        size_t initial_addr_count = discovery_mgr.Size();

        for (size_t msg_idx = 0; msg_idx < num_messages; msg_idx++) {
            message::AddrMessage addr_msg;
            addr_msg.addresses.reserve(addrs_per_message);

            for (size_t i = 0; i < addrs_per_message; i++) {
                uint32_t unique_idx = static_cast<uint32_t>(msg_idx * addrs_per_message + i);
                addr_msg.addresses.push_back(MakeTestAddress(unique_idx));
            }

            auto payload = addr_msg.serialize();
            protocol::MessageHeader header(protocol::magic::REGTEST,
                protocol::commands::ADDR, static_cast<uint32_t>(payload.size()));
            uint256 hash = Hash(payload);
            std::memcpy(header.checksum.data(), hash.begin(), 4);
            auto header_bytes = message::serialize_header(header);

            std::vector<uint8_t> full;
            full.reserve(header_bytes.size() + payload.size());
            full.insert(full.end(), header_bytes.begin(), header_bytes.end());
            full.insert(full.end(), payload.begin(), payload.end());

            network_->SendMessage(attacker.GetId(), victim_->GetId(), full);
            result.messages_sent++;
            result.bytes_sent += full.size();

            orchestrator_.AdvanceTime(delay_between);
        }

        orchestrator_.AdvanceTime(std::chrono::seconds(1));

        // Check how many addresses were actually processed
        size_t final_addr_count = discovery_mgr.Size();
        size_t addrs_processed = final_addr_count - initial_addr_count;
        size_t total_sent = num_messages * addrs_per_message;

        result.messages_accepted = addrs_processed;
        result.messages_rejected = total_sent - addrs_processed;

        // Rate limiting kicks in if significantly fewer processed than sent
        if (addrs_processed < total_sent * 0.5) {
            result.defense_triggered = "addr_rate_limiting";
        }

        result.triggered_disconnect = (attacker.GetPeerCount() == 0);

        auto end = std::chrono::steady_clock::now();
        result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

        RecordSnapshot(after_);
        last_result_ = result;
        return result;
    }


    /**
     * Send oversized GETHEADERS locator attack
     *
     * Historical vulnerability: No cap on CBlockLocator size => CPU blowup in FindFork()
     *
     * @param attacker SimulatedNode sending the message
     * @param locator_count Number of locator hashes (> 101 = MAX_LOCATOR_SZ for attack)
     * @return Attack result
     */
    AttackResult SendOversizedGetHeaders(
            SimulatedNode& attacker,
            size_t locator_count) {

        AttackResult result;
        result.attack_type = "OVERSIZED_GETHEADERS";
        result.attack_description = "GETHEADERS with " + std::to_string(locator_count) +
            " locator hashes (MAX=101)";

        auto start = std::chrono::steady_clock::now();

        // Build oversized GETHEADERS payload
        message::MessageSerializer s;
        s.write_uint32(protocol::PROTOCOL_VERSION);
        s.write_varint(locator_count);

        // Write locator_count dummy hashes (all zeros)
        std::array<uint8_t, 32> zero{};
        for (size_t i = 0; i < locator_count; ++i) {
            s.write_bytes(zero.data(), zero.size());
        }
        // hash_stop = zero
        s.write_bytes(zero.data(), zero.size());

        auto payload = s.data();

        protocol::MessageHeader header(protocol::magic::REGTEST,
            protocol::commands::GETHEADERS, static_cast<uint32_t>(payload.size()));
        uint256 hash = Hash(payload);
        std::memcpy(header.checksum.data(), hash.begin(), 4);
        auto header_bytes = message::serialize_header(header);

        std::vector<uint8_t> full;
        full.reserve(header_bytes.size() + payload.size());
        full.insert(full.end(), header_bytes.begin(), header_bytes.end());
        full.insert(full.end(), payload.begin(), payload.end());

        network_->SendMessage(attacker.GetId(), victim_->GetId(), full);
        result.messages_sent = 1;
        result.bytes_sent = full.size();

        orchestrator_.AdvanceTime(std::chrono::seconds(2));

        result.triggered_disconnect = (attacker.GetPeerCount() == 0);
        if (result.triggered_disconnect) {
            result.defense_triggered = "oversized_getheaders_rejected";
        }

        auto end = std::chrono::steady_clock::now();
        result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

        RecordSnapshot(after_);
        last_result_ = result;
        return result;
    }

    /**
     * Send PING flood attack
     *
     * Verifies that PING flood elicits PONG responses without disconnect
     *
     * @param attacker SimulatedNode sending the flood
     * @param count Number of PING messages to send
     * @return Attack result with PONG count
     */
    AttackResult SendPingFlood(
            SimulatedNode& attacker,
            size_t count) {

        AttackResult result;
        result.attack_type = "PING_FLOOD";
        result.attack_description = std::to_string(count) + " PING messages";

        auto start = std::chrono::steady_clock::now();

        // Wait for handshake to complete - PING is ignored before handshake
        // (security feature to prevent DoS amplification from unauthenticated peers)
        bool handshake_complete = false;
        for (int i = 0; i < 20 && !handshake_complete; ++i) {
            orchestrator_.AdvanceTime(std::chrono::milliseconds(100));
            auto peers = victim_->GetNetworkManager().peer_manager().get_all_peers();
            for (const auto& peer : peers) {
                if (peer && peer->successfully_connected()) {
                    handshake_complete = true;
                    break;
                }
            }
        }

        network_->EnableCommandTracking(true);
        int pong_before = network_->CountCommandSent(victim_->GetId(), attacker.GetId(),
            protocol::commands::PONG);

        for (size_t i = 0; i < count; i++) {
            message::PingMessage ping(0xABC00000ULL + i);
            auto payload = ping.serialize();

            protocol::MessageHeader header(protocol::magic::REGTEST,
                protocol::commands::PING, static_cast<uint32_t>(payload.size()));
            uint256 hash = Hash(payload);
            std::memcpy(header.checksum.data(), hash.begin(), 4);
            auto header_bytes = message::serialize_header(header);

            std::vector<uint8_t> full;
            full.reserve(header_bytes.size() + payload.size());
            full.insert(full.end(), header_bytes.begin(), header_bytes.end());
            full.insert(full.end(), payload.begin(), payload.end());

            network_->SendMessage(attacker.GetId(), victim_->GetId(), full);
            result.messages_sent++;
            result.bytes_sent += full.size();

            orchestrator_.AdvanceTime(std::chrono::milliseconds(5));
        }

        orchestrator_.AdvanceTime(std::chrono::seconds(1));

        int pong_after = network_->CountCommandSent(victim_->GetId(), attacker.GetId(),
            protocol::commands::PONG);

        result.messages_accepted = static_cast<size_t>(pong_after - pong_before);
        result.triggered_disconnect = (attacker.GetPeerCount() == 0);

        // PING flood should NOT cause disconnect - victim responds with PONGs
        if (!result.triggered_disconnect && result.messages_accepted >= count) {
            result.defense_triggered = "ping_flood_handled";
        }

        auto end = std::chrono::steady_clock::now();
        result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

        RecordSnapshot(after_);
        last_result_ = result;
        return result;
    }

    /**
     * Test per-IP connection limit
     *
     * Creates multiple attackers from the same IP and verifies per-IP limit
     *
     * @param base_node_id Base ID for attacker nodes (all will map to same IP)
     * @param num_attackers Number of connection attempts from same IP
     * @param per_ip_limit Expected per-IP limit
     * @return Attack result with accepted connection count
     */
    AttackResult TestPerIpLimit(
            int base_node_id,
            size_t num_attackers,
            size_t per_ip_limit = 2) {

        AttackResult result;
        result.attack_type = "PER_IP_LIMIT";
        result.attack_description = std::to_string(num_attackers) +
            " connections from same IP (limit=" + std::to_string(per_ip_limit) + ")";

        auto start = std::chrono::steady_clock::now();

        // Create attackers whose node_id maps to the same IP via (id % 255)
        std::vector<std::unique_ptr<SimulatedNode>> attackers;
        for (size_t i = 0; i < num_attackers; ++i) {
            int attacker_id = base_node_id + 255 * static_cast<int>(i + 1);
            attackers.push_back(std::make_unique<SimulatedNode>(attacker_id, network_));
            attackers.back()->ConnectTo(victim_->GetId());
            result.messages_sent++;
        }

        orchestrator_.AdvanceTime(std::chrono::seconds(2));

        // Count how many connections were actually accepted
        auto& pm = victim_->GetNetworkManager().peer_manager();
        auto inbound = pm.get_inbound_peers();

        // Count connections from the same IP
        std::string expected_ip = "127.0.0." + std::to_string(base_node_id % 255);
        size_t same_ip_count = 0;
        for (const auto& p : inbound) {
            if (p && p->address() == expected_ip) {
                same_ip_count++;
            }
        }

        result.messages_accepted = same_ip_count;
        result.messages_rejected = num_attackers - same_ip_count;

        if (same_ip_count <= per_ip_limit) {
            result.defense_triggered = "per_ip_limit_enforced";
        }

        auto end = std::chrono::steady_clock::now();
        result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

        RecordSnapshot(after_);
        last_result_ = result;
        return result;
    }

    /**
     * Test send queue overflow attack (slow reader)
     *
     * Configures a very slow link and floods messages to trigger send queue overflow.
     * This simulates a scenario where the victim is sending to a slow reader, causing
     * send queue buildup.
     *
     * @param target SimulatedNode to flood (the slow reader)
     * @param message_count Number of messages to send
     * @return Attack result
     */
    AttackResult TestSendQueueOverflow(
            SimulatedNode& target,
            size_t message_count) {

        AttackResult result;
        result.attack_type = "SEND_QUEUE_OVERFLOW";
        result.attack_description = "Flood " + std::to_string(message_count) +
            " messages to slow reader";

        auto start = std::chrono::steady_clock::now();

        // Configure very slow link from victim to target
        SimulatedNetwork::NetworkConditions slow;
        slow.latency_min = std::chrono::milliseconds(0);
        slow.latency_max = std::chrono::milliseconds(1);
        slow.jitter_max = std::chrono::milliseconds(0);
        slow.bandwidth_bytes_per_sec = 10 * 1024; // 10 KB/s - very slow
        network_->SetLinkConditions(victim_->GetId(), target.GetId(), slow);

        // Find the peer connection from victim to target
        auto peers = victim_->GetNetworkManager().peer_manager().get_all_peers();
        network::PeerPtr target_peer = nullptr;
        for (auto& peer : peers) {
            if (peer) {
                target_peer = peer;
                break;
            }
        }

        if (!target_peer) {
            result.defense_triggered = "no_peer_connection";
            return result;
        }

        // Flood messages from victim to target
        for (size_t i = 0; i < message_count; ++i) {
            auto ping_msg = std::make_unique<message::PingMessage>(i);
            target_peer->send_message(std::move(ping_msg));
            result.messages_sent++;

            if (i % 100 == 0) {
                orchestrator_.AdvanceTime(std::chrono::milliseconds(10));
            }
        }

        orchestrator_.AdvanceTime(std::chrono::seconds(5));

        // Check if victim disconnected target due to send queue overflow
        result.triggered_disconnect = (victim_->GetPeerCount() == 0);
        if (result.triggered_disconnect) {
            result.defense_triggered = "send_queue_overflow";
        }

        // Restore normal conditions
        SimulatedNetwork::NetworkConditions normal;
        network_->SetLinkConditions(victim_->GetId(), target.GetId(), normal);

        auto end = std::chrono::steady_clock::now();
        result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

        RecordSnapshot(after_);
        last_result_ = result;
        return result;
    }

    /**
     * Send orphan header spam attack
     *
     * Floods victim with headers that have unknown parents, triggering
     * orphan processing and potential misbehavior penalties.
     *
     * @param attacker NodeSimulator sending orphan headers
     * @param batches Number of batches to send
     * @param orphans_per_batch Number of orphan headers per batch
     * @return Attack result
     */
    AttackResult SendOrphanSpam(
            NodeSimulator& attacker,
            size_t batches,
            size_t orphans_per_batch) {

        AttackResult result;
        result.attack_type = "ORPHAN_SPAM";
        result.attack_description = std::to_string(batches) + " batches x " +
            std::to_string(orphans_per_batch) + " orphan headers";

        auto start = std::chrono::steady_clock::now();
        RecordSnapshot(before_);

        for (size_t batch = 0; batch < batches; ++batch) {
            attacker.SendOrphanHeaders(victim_->GetId(), orphans_per_batch);
            result.messages_sent += orphans_per_batch;
            orchestrator_.AdvanceTime(std::chrono::milliseconds(300));
        }

        orchestrator_.AdvanceTime(std::chrono::seconds(2));

        result.triggered_disconnect = (victim_->GetPeerCount() == 0);
        if (result.triggered_disconnect) {
            result.defense_triggered = "orphan_spam_disconnect";
        }

        result.victim_chain_intact = (victim_->GetTipHeight() >= before_.chain_height);
        result.victim_height_before = before_.chain_height;
        result.victim_height_after = victim_->GetTipHeight();

        auto end = std::chrono::steady_clock::now();
        result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

        RecordSnapshot(after_);
        last_result_ = result;
        return result;
    }

    /**
     * Test stalling peer attack
     *
     * Attacker connects and triggers GETHEADERS but never responds,
     * testing stall timeout behavior.
     *
     * @param attacker NodeSimulator that will stall
     * @param stall_seconds How long to stall
     * @return Attack result
     */
    AttackResult TestStallingPeer(
            NodeSimulator& attacker,
            int stall_seconds) {

        AttackResult result;
        result.attack_type = "STALLING_PEER";
        result.attack_description = "Stall for " + std::to_string(stall_seconds) + " seconds";

        auto start = std::chrono::steady_clock::now();
        RecordSnapshot(before_);

        // Enable stalling mode
        attacker.EnableStalling(true);

        // Send orphans to trigger GETHEADERS request from victim
        attacker.SendOrphanHeaders(victim_->GetId(), 50);
        result.messages_sent = 50;

        // Stall by not responding - advance time
        for (int i = 0; i < stall_seconds; ++i) {
            orchestrator_.AdvanceTime(std::chrono::seconds(1));
        }

        // Victim should still be functional
        result.victim_chain_intact = (victim_->GetTipHeight() >= before_.chain_height);
        result.victim_height_before = before_.chain_height;
        result.victim_height_after = victim_->GetTipHeight();

        // Check if attacker was disconnected for stalling
        result.triggered_disconnect = (victim_->GetPeerCount() == 0);
        if (result.triggered_disconnect) {
            result.defense_triggered = "stall_timeout";
        } else {
            result.defense_triggered = "victim_survived";
        }

        auto end = std::chrono::steady_clock::now();
        result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

        RecordSnapshot(after_);
        last_result_ = result;
        return result;
    }

    /**
     * Send out-of-order headers attack
     *
     * Sends headers in non-chronological order (child before parent)
     * to test orphan resolution.
     *
     * @param attacker NodeSimulator sending the headers
     * @return Attack result with final chain state
     */
    AttackResult SendOutOfOrderHeaders(NodeSimulator& attacker) {

        AttackResult result;
        result.attack_type = "OUT_OF_ORDER_HEADERS";
        result.attack_description = "Child before parent headers";

        auto start = std::chrono::steady_clock::now();
        RecordSnapshot(before_);

        // Send headers out of order (child before parent)
        auto [parent_hash, child_hash] = attacker.SendOutOfOrderHeaders(
            victim_->GetId(),
            victim_->GetTipHash()
        );

        result.messages_sent = 2;

        orchestrator_.AdvanceTime(std::chrono::milliseconds(100));

        // Activate best chain
        victim_->GetChainstate().ActivateBestChain();

        result.victim_height_before = before_.chain_height;
        result.victim_height_after = victim_->GetTipHeight();

        // Chain should advance by 2 (parent + child)
        if (result.victim_height_after == before_.chain_height + 2) {
            result.defense_triggered = "orphan_resolved";
            result.victim_chain_intact = true;
        } else {
            result.victim_chain_intact = false;
        }

        auto end = std::chrono::steady_clock::now();
        result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

        RecordSnapshot(after_);
        last_result_ = result;
        return result;
    }

    /**
     * Send bad magic bytes attack
     *
     * Sends a message with wrong network magic bytes.
     *
     * @param attacker SimulatedNode sending the bad message
     * @return Attack result
     */
    AttackResult SendBadMagic(SimulatedNode& attacker) {

        AttackResult result;
        result.attack_type = "BAD_MAGIC";
        result.attack_description = "Message with wrong network magic";

        auto start = std::chrono::steady_clock::now();
        RecordSnapshot(before_);

        // Create message with wrong magic (mainnet magic on regtest)
        std::vector<uint8_t> payload = {0x00};  // minimal payload
        protocol::MessageHeader header(protocol::magic::MAINNET,  // Wrong magic!
            protocol::commands::PING, static_cast<uint32_t>(payload.size()));
        uint256 hash = Hash(payload);
        std::memcpy(header.checksum.data(), hash.begin(), 4);
        auto header_bytes = message::serialize_header(header);

        std::vector<uint8_t> full;
        full.reserve(header_bytes.size() + payload.size());
        full.insert(full.end(), header_bytes.begin(), header_bytes.end());
        full.insert(full.end(), payload.begin(), payload.end());

        network_->SendMessage(attacker.GetId(), victim_->GetId(), full);
        result.messages_sent = 1;
        result.bytes_sent = full.size();

        orchestrator_.AdvanceTime(std::chrono::seconds(1));

        result.triggered_disconnect = (victim_->GetPeerCount() == 0);
        if (result.triggered_disconnect) {
            result.defense_triggered = "bad_magic_disconnect";
        }

        auto end = std::chrono::steady_clock::now();
        result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

        RecordSnapshot(after_);
        last_result_ = result;
        return result;
    }

    /**
     * Send bad checksum attack
     *
     * Sends a message with corrupted checksum.
     *
     * @param attacker SimulatedNode sending the bad message
     * @return Attack result
     */
    AttackResult SendBadChecksum(SimulatedNode& attacker) {

        AttackResult result;
        result.attack_type = "BAD_CHECKSUM";
        result.attack_description = "Message with corrupted checksum";

        auto start = std::chrono::steady_clock::now();
        RecordSnapshot(before_);

        // Create message with bad checksum
        std::vector<uint8_t> payload = {0x00};
        protocol::MessageHeader header(protocol::magic::REGTEST,
            protocol::commands::PING, static_cast<uint32_t>(payload.size()));
        // Set wrong checksum
        header.checksum = {0xDE, 0xAD, 0xBE, 0xEF};
        auto header_bytes = message::serialize_header(header);

        std::vector<uint8_t> full;
        full.reserve(header_bytes.size() + payload.size());
        full.insert(full.end(), header_bytes.begin(), header_bytes.end());
        full.insert(full.end(), payload.begin(), payload.end());

        network_->SendMessage(attacker.GetId(), victim_->GetId(), full);
        result.messages_sent = 1;
        result.bytes_sent = full.size();

        orchestrator_.AdvanceTime(std::chrono::seconds(1));

        result.triggered_disconnect = (victim_->GetPeerCount() == 0);
        if (result.triggered_disconnect) {
            result.defense_triggered = "bad_checksum_disconnect";
        }

        auto end = std::chrono::steady_clock::now();
        result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

        RecordSnapshot(after_);
        last_result_ = result;
        return result;
    }

    /**
     * Send truncated message attack
     *
     * Sends a message header claiming large payload but only partial data.
     *
     * @param attacker SimulatedNode sending the truncated message
     * @return Attack result
     */
    AttackResult SendTruncatedMessage(SimulatedNode& attacker) {

        AttackResult result;
        result.attack_type = "TRUNCATED_MESSAGE";
        result.attack_description = "Header claims 1000 bytes, sends 10";

        auto start = std::chrono::steady_clock::now();
        RecordSnapshot(before_);

        // Header claims 1000 bytes but we only send 10
        std::vector<uint8_t> payload(10, 0x42);
        protocol::MessageHeader header(protocol::magic::REGTEST,
            protocol::commands::HEADERS, 1000);  // Claims 1000 bytes
        uint256 hash = Hash(payload);
        std::memcpy(header.checksum.data(), hash.begin(), 4);
        auto header_bytes = message::serialize_header(header);

        std::vector<uint8_t> full;
        full.reserve(header_bytes.size() + payload.size());
        full.insert(full.end(), header_bytes.begin(), header_bytes.end());
        full.insert(full.end(), payload.begin(), payload.end());  // Only 10 bytes

        network_->SendMessage(attacker.GetId(), victim_->GetId(), full);
        result.messages_sent = 1;
        result.bytes_sent = full.size();

        orchestrator_.AdvanceTime(std::chrono::seconds(2));

        // Connection should timeout waiting for rest of payload
        result.triggered_disconnect = (victim_->GetPeerCount() == 0);
        if (result.triggered_disconnect) {
            result.defense_triggered = "truncated_timeout";
        }

        auto end = std::chrono::steady_clock::now();
        result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

        RecordSnapshot(after_);
        last_result_ = result;
        return result;
    }

    // =========================================================================
    // Metrics & Verification
    // =========================================================================

    /**
     * Check if victim's chain is intact (not modified by attack)
     */
    bool IsChainIntact() const {
        return after_.chain_height >= before_.chain_height;
    }

    /**
     * Check if attack was successfully defended
     */
    bool WasDefended() const {
        return last_result_.defense_triggered.length() > 0;
    }

    /**
     * Check if peer was disconnected as a result of attack
     */
    bool PeerWasDisconnected() const {
        return last_result_.triggered_disconnect;
    }

    /**
     * Get the last attack result
     */
    const AttackResult& GetLastResult() const {
        return last_result_;
    }

    /**
     * Get snapshot before attack
     */
    const NodeSnapshot& GetBeforeSnapshot() const {
        return before_;
    }

    /**
     * Get snapshot after attack
     */
    const NodeSnapshot& GetAfterSnapshot() const {
        return after_;
    }

    // =========================================================================
    // Report Generation
    // =========================================================================

    /**
     * Generate human-readable attack report
     */
    std::string GenerateReport() const {
        std::ostringstream oss;

        oss << "\n";
        oss << "========== DoS ATTACK SIMULATION REPORT ==========\n";
        oss << "\n";

        oss << "Attack Type: " << last_result_.attack_type << "\n";
        oss << "Description: " << last_result_.attack_description << "\n";
        oss << "Duration: " << last_result_.duration.count() << "ms\n";
        oss << "\n";

        oss << "--- Attack Volume ---\n";
        oss << "  Messages Sent: " << last_result_.messages_sent << "\n";
        oss << "  Bytes Sent: " << last_result_.bytes_sent << "\n";
        oss << "  Accepted: " << last_result_.messages_accepted << "\n";
        oss << "  Rejected: " << last_result_.messages_rejected << "\n";
        oss << "\n";

        oss << "--- Defense Response ---\n";
        oss << "  Triggered Disconnect: " << (last_result_.triggered_disconnect ? "YES" : "NO") << "\n";
        oss << "  Peer Discouraged: " << (last_result_.peer_discouraged ? "YES" : "NO") << "\n";
        oss << "  Peer Banned: " << (last_result_.peer_banned ? "YES" : "NO") << "\n";
        oss << "  Misbehaving: " << (last_result_.misbehaving ? "YES" : "NO") << "\n";
        oss << "  Defense Triggered: " << (last_result_.defense_triggered.empty() ? "NONE" : last_result_.defense_triggered) << "\n";
        oss << "\n";

        oss << "--- Victim State ---\n";
        oss << "  Chain Intact: " << (last_result_.victim_chain_intact ? "YES" : "NO") << "\n";
        oss << "  Height Before: " << last_result_.victim_height_before << "\n";
        oss << "  Height After: " << last_result_.victim_height_after << "\n";
        oss << "  Peers Before: " << before_.peer_count << "\n";
        oss << "  Peers After: " << after_.peer_count << "\n";
        oss << "\n";

        oss << "--- Verdict ---\n";
        if (last_result_.defense_triggered.empty()) {
            oss << "  Result: ATTACK NOT DEFENDED\n";
        } else if (last_result_.victim_chain_intact) {
            oss << "  Result: ATTACK DEFENDED SUCCESSFULLY\n";
        } else {
            oss << "  Result: PARTIAL DEFENSE (chain modified)\n";
        }

        oss << "==================================================\n";

        return oss.str();
    }

    // =========================================================================
    // Utility Methods
    // =========================================================================

    /**
     * Advance simulated time
     */
    void AdvanceTime(std::chrono::milliseconds duration) {
        orchestrator_.AdvanceTime(duration);
    }

    /**
     * Reset state for a new attack
     */
    void Reset() {
        last_result_ = AttackResult{};
        RecordSnapshot(before_);
    }

    /**
     * Build victim's chain to a target height (with PoW bypass for speed)
     */
    void BuildVictimChain(int target_height) {
        victim_->SetBypassPOWValidation(true);
        for (int i = victim_->GetTipHeight(); i < target_height; i++) {
            victim_->MineBlock();
        }
        victim_->SetBypassPOWValidation(false);
        RecordSnapshot(before_);
    }

    /**
     * Connect attacker to victim and wait for sync
     */
    bool ConnectAndSync(SimulatedNode& attacker) {
        attacker.ConnectTo(victim_->GetId(), victim_->GetAddress());
        return orchestrator_.WaitForConnection(*victim_, attacker) &&
               orchestrator_.WaitForSync(*victim_, attacker);
    }

    /**
     * Connect attacker to victim and wait for sync (NodeSimulator version)
     */
    bool ConnectAndSync(NodeSimulator& attacker) {
        attacker.ConnectTo(victim_->GetId());
        return orchestrator_.WaitForConnection(*victim_, attacker) &&
               orchestrator_.WaitForSync(*victim_, attacker);
    }

private:
    void RecordSnapshot(NodeSnapshot& snapshot) const {
        snapshot.peer_count = victim_->GetPeerCount();
        snapshot.inbound_count = victim_->GetInboundPeerCount();
        snapshot.outbound_count = victim_->GetOutboundPeerCount();
        snapshot.chain_height = victim_->GetTipHeight();
        snapshot.timestamp = std::chrono::steady_clock::now();
    }

    /**
     * Create a test address with unique IP across diverse /16 netgroups
     * Used for ADDR flood testing to avoid hitting per-netgroup limits
     */
    static protocol::TimestampedAddress MakeTestAddress(uint32_t index) {
        protocol::TimestampedAddress ta;
        ta.timestamp = static_cast<uint32_t>(std::time(nullptr));

        // Generate unique IP across diverse /16 netgroups:
        // Use A.B.x.y where A.B varies to create different /16 netgroups
        // With MAX_PER_NETGROUP_NEW = 32, we distribute across many /16s
        uint8_t first_byte = 8 + (index / 32) % 200;  // 8-207
        uint8_t second_byte = (index / 32 / 200) % 256;
        uint8_t third_byte = (index % 32);
        uint8_t fourth_byte = 1;  // Non-zero

        uint32_t ip_val = (static_cast<uint32_t>(first_byte) << 24) |
                          (static_cast<uint32_t>(second_byte) << 16) |
                          (static_cast<uint32_t>(third_byte) << 8) |
                          static_cast<uint32_t>(fourth_byte);

        auto ip = asio::ip::make_address_v6(
            asio::ip::v4_mapped,
            asio::ip::address_v4{static_cast<asio::ip::address_v4::uint_type>(ip_val)}
        );
        auto bytes = ip.to_bytes();
        std::copy(bytes.begin(), bytes.end(), ta.address.ip.begin());
        ta.address.services = protocol::ServiceFlags::NODE_NETWORK;
        ta.address.port = protocol::ports::REGTEST;

        return ta;
    }

    SimulatedNetwork* network_;
    SimulatedNode* victim_;
    TestOrchestrator orchestrator_;

    NodeSnapshot before_;
    NodeSnapshot after_;
    AttackResult last_result_;
};

// =========================================================================
// Pre-built Attack Profiles
// =========================================================================

/**
 * Common DoS attack profiles for quick testing
 */
namespace DoSProfiles {

/**
 * Test receive buffer overflow defense
 */
inline DoSAttackSimulator::AttackResult TestBufferOverflow(
        DoSAttackSimulator& sim,
        SimulatedNode& attacker) {
    // 30 messages * 256KB with 1MB declared = ~7.5MB actual, ~30MB declared
    return sim.SendMessageFlood(attacker, 30, 256 * 1024, 1024 * 1024);
}

/**
 * Test invalid PoW defense
 */
inline DoSAttackSimulator::AttackResult TestInvalidPoW(
        DoSAttackSimulator& sim,
        NodeSimulator& attacker) {
    return sim.SendInvalidPoWHeaders(attacker, 1);
}

/**
 * Test oversized headers defense
 */
inline DoSAttackSimulator::AttackResult TestOversizedHeaders(
        DoSAttackSimulator& sim,
        NodeSimulator& attacker) {
    return sim.SendOversizedMessages(attacker, "headers", protocol::MAX_HEADERS_SIZE + 1);
}

/**
 * Test stalling peer detection
 */
inline DoSAttackSimulator::AttackResult TestStallingPeer(
        DoSAttackSimulator& sim,
        SimulatedNode& attacker,
        std::chrono::seconds stall_time = std::chrono::seconds(300)) {
    return sim.StallResponses(attacker, stall_time);
}

} // namespace DoSProfiles

} // namespace test
} // namespace unicity

#endif // UNICITY_TEST_DOS_ATTACK_SIMULATOR_HPP
