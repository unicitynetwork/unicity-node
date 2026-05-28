#pragma once

#include <vector>
#include <string>
#include <map>
#include <cstdint>
#include <optional>
#include <span>
#include <nlohmann/json.hpp>

namespace unicity {
namespace chain {

// CBOR Tag for RootTrustBaseV1
constexpr int TAG_ROOT_TRUST_BASE = 39000;

struct NodeInfo {
    std::string node_id;
    std::vector<uint8_t> sig_key;
    uint64_t stake;

    // Serialization for CBOR array format
    friend void to_json(nlohmann::json& j, const NodeInfo& n);
    friend void from_json(const nlohmann::json& j, NodeInfo& n);
};

struct RootTrustBaseV1 {
    uint32_t version = 1;
    uint32_t network_id = 0;
    uint64_t epoch = 0;
    uint64_t epoch_start = 0;
    std::vector<NodeInfo> root_nodes;
    uint64_t quorum_threshold = 0;
    std::vector<uint8_t> state_hash;
    std::vector<uint8_t> change_record_hash;
    std::vector<uint8_t> previous_entry_hash;
    std::map<std::string, std::vector<uint8_t>> signatures;

    friend void to_json(nlohmann::json& j, const RootTrustBaseV1& r);
    friend void from_json(const nlohmann::json& j, RootTrustBaseV1& r);

    static RootTrustBaseV1 FromCBOR(std::span<const uint8_t> data);

    // Serialization for signing/hashing (excludes signatures)
    std::vector<uint8_t> SigBytes() const;

    std::vector<uint8_t> ToCBOR() const;

    // Hash of the structure (including signatures)
    std::vector<uint8_t> Hash() const;

    // Verification
    // IsValid verifies the trust base content consistency (without signatures)
    bool IsValid(const std::optional<RootTrustBaseV1>& prev) const;

    // VerifySignatures verifies that the trust base is signed by the previous epoch's validators
    bool VerifySignatures(const std::optional<RootTrustBaseV1>& prev) const;

    // Verify verifies both content consistency and signatures
    bool Verify(const std::optional<RootTrustBaseV1>& prev) const;
    
    // Helper to get a node info by ID
    const NodeInfo* GetNode(const std::string& node_id) const;
};

} // namespace chain
} // namespace unicity
