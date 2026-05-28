#include "chain/trust_base.hpp"

#include "util/hash.hpp"
#include "util/sha256.hpp"
#include "util/string_parsing.hpp"
#include "util/uint.hpp"

#include <limits>

#include <secp256k1.h>

namespace unicity::chain {

namespace {
// Global secp256k1 context
const secp256k1_context* GetContext() {
  return secp256k1_context_static;
}

std::vector<uint8_t> PrependCborTag(const std::vector<uint8_t>& data) {
  std::vector<uint8_t> tagged;
  tagged.reserve(data.size() + 3);
  tagged.push_back(0xd9);
  tagged.push_back(0x98);
  tagged.push_back(0x58);
  tagged.insert(tagged.end(), data.begin(), data.end());
  return tagged;
}
}  // namespace

void to_json(nlohmann::json& j, const NodeInfo& n) {
  j = nlohmann::json::array();
  j.push_back(n.node_id);
  j.push_back(nlohmann::json::binary(n.sig_key));
  j.push_back(n.stake);
}

void from_json(const nlohmann::json& j, NodeInfo& n) {
  if (!j.is_array() || j.size() < 3) {
    throw std::runtime_error("NodeInfo CBOR must be an array of at least 3 elements");
  }
  j.at(0).get_to(n.node_id);
  if (j.at(1).is_binary()) {
    n.sig_key = j.at(1).get_binary();
  } else {
    // Fallback if not strictly binary (e.g. empty array)
    n.sig_key = j.at(1).get<std::vector<uint8_t>>();
  }
  j.at(2).get_to(n.stake);
}

void to_json(nlohmann::json& j, const RootTrustBaseV1& r) {
  j = nlohmann::json::array();
  j.push_back(r.version);
  j.push_back(r.network_id);
  j.push_back(r.epoch);
  j.push_back(r.epoch_start);
  j.push_back(r.root_nodes);  // Uses NodeInfo to_json
  j.push_back(r.quorum_threshold);

  // Handle empty vectors as null/empty bytes
  if (r.state_hash.empty())
    j.push_back(nullptr);
  else
    j.push_back(nlohmann::json::binary(r.state_hash));

  if (r.change_record_hash.empty())
    j.push_back(nullptr);
  else
    j.push_back(nlohmann::json::binary(r.change_record_hash));

  if (r.previous_entry_hash.empty())
    j.push_back(nullptr);
  else
    j.push_back(nlohmann::json::binary(r.previous_entry_hash));

  // Signatures map <string, bytes>
  // Go encodes map[string][]byte
  if (r.signatures.empty()) {
    j.push_back(nlohmann::json::object());
  } else {
    auto sigs_json = nlohmann::json::object();
    for (const auto& [id, sig] : r.signatures) {
      sigs_json[id] = nlohmann::json::binary(sig);
    }
    j.push_back(sigs_json);
  }
}

void from_json(const nlohmann::json& j, RootTrustBaseV1& r) {
  if (!j.is_array() || j.size() < 10) {
    throw std::runtime_error("RootTrustBaseV1 CBOR must be an array of at least 10 elements");
  }

  j.at(0).get_to(r.version);
  j.at(1).get_to(r.network_id);
  j.at(2).get_to(r.epoch);
  j.at(3).get_to(r.epoch_start);
  j.at(4).get_to(r.root_nodes);
  j.at(5).get_to(r.quorum_threshold);

  auto extract_bytes = [](const nlohmann::json& val, std::vector<uint8_t>& out) {
    if (val.is_null()) {
      out.clear();
    } else if (val.is_binary()) {
      out = val.get_binary();
    } else {
      out.clear();  // Or throw? Null usually means empty hash.
    }
  };

  extract_bytes(j.at(6), r.state_hash);
  extract_bytes(j.at(7), r.change_record_hash);
  extract_bytes(j.at(8), r.previous_entry_hash);

  r.signatures.clear();
  if (j.at(9).is_object()) {
    for (auto& [key, val] : j.at(9).items()) {
      if (val.is_binary()) {
        r.signatures[key] = val.get_binary();
      } else {
        // Try vector
        r.signatures[key] = val.get<std::vector<uint8_t>>();
      }
    }
  }
}

RootTrustBaseV1 RootTrustBaseV1::FromCBOR(std::span<const uint8_t> data) {
  const nlohmann::json j = nlohmann::json::from_cbor(data, true, true, nlohmann::json::cbor_tag_handler_t::ignore);
  RootTrustBaseV1 tb;
  from_json(j, tb);
  return tb;
}

std::vector<uint8_t> RootTrustBaseV1::SigBytes() const {
  nlohmann::json j;
  to_json(j, *this);
  j[9] = nullptr;  // Force the last element (signatures) to be null

  return PrependCborTag(nlohmann::json::to_cbor(j));
}

std::vector<uint8_t> RootTrustBaseV1::ToCBOR() const {
  nlohmann::json j;
  to_json(j, *this);

  return PrependCborTag(nlohmann::json::to_cbor(j));
}

std::vector<uint8_t> RootTrustBaseV1::Hash() const {
  std::vector<uint8_t> tagged = ToCBOR();
  uint256 h = SingleHash(tagged);
  return std::vector(h.begin(), h.end());
}

bool RootTrustBaseV1::IsValid(const std::optional<RootTrustBaseV1>& prev) const {
  if (quorum_threshold == 0) {
    return false;
  }
  if (root_nodes.empty()) {
    return false;
  }

  // Check for stake overflow and quorum_threshold consistency
  uint64_t total_possible_stake = 0;
  for (const auto& node : root_nodes) {
    if (total_possible_stake > std::numeric_limits<uint64_t>::max() - node.stake) {
      return false;  // overflow
    }
    total_possible_stake += node.stake;
  }

  if (quorum_threshold > total_possible_stake) {
    return false;  // quorum is not possible
  }

  if (!prev.has_value()) {
    if (epoch != 1)
      return false;
  } else {
    if (network_id != prev->network_id)
      return false;
    if (epoch != prev->epoch + 1)
      return false;
    if (epoch_start <= prev->epoch_start)
      return false;

    // Verify previous entry hash
    std::vector<uint8_t> prev_hash = prev->Hash();
    if (previous_entry_hash != prev_hash)
      return false;
  }
  return true;
}

bool RootTrustBaseV1::VerifySignatures(const std::optional<RootTrustBaseV1>& prev) const {
  const RootTrustBaseV1* trusted = nullptr;
  if (epoch == 1) {
    trusted = this;  // Genesis is self-signed
  } else if (!prev.has_value()) {
    return false;
  } else {
    trusted = &prev.value();
  }

  std::vector<uint8_t> sig_data = SigBytes();
  uint256 msg_hash = SingleHash(sig_data);

  uint64_t total_stake = 0;

  for (const auto& [node_id, sig] : signatures) {
    const NodeInfo* node = trusted->GetNode(node_id);
    if (!node) {
      continue;  // Unknown signer
    }
    // Verify signature
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_parse(GetContext(), &pubkey, node->sig_key.data(), node->sig_key.size())) {
      continue;
    }

    if (sig.size() < 64) {
      continue;
    }

    // We only need the first 64 bytes (r, s). The 65th byte is recovery ID which parse_compact doesn't use.
    secp256k1_ecdsa_signature algo_sig;
    if (!secp256k1_ecdsa_signature_parse_compact(GetContext(), &algo_sig, sig.data())) {
      continue;
    }

    if (secp256k1_ecdsa_verify(GetContext(), &algo_sig, msg_hash.begin(), &pubkey)) {
      if (total_stake > std::numeric_limits<uint64_t>::max() - node->stake) {
        return false;  // overflow
      }
      total_stake += node->stake;
    }
  }

  return total_stake >= trusted->quorum_threshold;
}

bool RootTrustBaseV1::Verify(const std::optional<RootTrustBaseV1>& prev) const {
  return IsValid(prev) && VerifySignatures(prev);
}

const NodeInfo* RootTrustBaseV1::GetNode(const std::string& node_id) const {
  for (const auto& node : root_nodes) {
    if (node.node_id == node_id)
      return &node;
  }
  return nullptr;
}

}  // namespace unicity::chain
