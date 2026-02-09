// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#include "network/misbehavior_manager.hpp"

#include "network/peer_misbehavior.hpp"
#include "util/logging.hpp"

namespace unicity {
namespace network {

MisbehaviorManager::MisbehaviorManager(util::ThreadSafeMap<int, PeerPtr>& peer_states)
    : peer_states_(peer_states) {}

void MisbehaviorManager::ReportInvalidPoW(int peer_id) {
  Misbehaving(peer_id, "header with invalid proof of work");
}

void MisbehaviorManager::ReportOversizedMessage(int peer_id) {
  Misbehaving(peer_id, "oversized message");
}

void MisbehaviorManager::ReportNonContinuousHeaders(int peer_id) {
  Misbehaving(peer_id, "non-continuous headers sequence");
}

void MisbehaviorManager::ReportLowWorkHeaders(int peer_id) {
  Misbehaving(peer_id, "low-work headers");
}

void MisbehaviorManager::ReportInvalidHeader(int peer_id, const std::string& reason) {
  Misbehaving(peer_id, "invalid header: " + reason);
}

void MisbehaviorManager::ReportPreVerackMessage(int peer_id) {
  Misbehaving(peer_id, "protocol message before handshake complete");
}

bool MisbehaviorManager::Misbehaving(int peer_id, const std::string& reason) {
  bool should_disconnect = false;

  peer_states_.Modify(peer_id, [&](PeerPtr& peer) {
    PeerMisbehaviorData& data = peer->misbehavior();

    // Mark for discouragement and increment lifetime counter
    data.should_discourage = true;
    data.misbehavior_count++;

    // NoBan peers are protected from disconnection (Manual peers get NoBan at grant time)
    if (HasPermission(data.permissions, NetPermissionFlags::NoBan)) {
      LOG_NET_WARN("misbehaving: peer={} ({}) {} (warning, not disconnecting due to noban)", peer_id, data.address,
                   reason);
      return;
    }

    LOG_NET_INFO("misbehaving: peer={} ({}) {} (disconnecting)", peer_id, data.address, reason);
    should_disconnect = true;
  });

  return should_disconnect;
}

bool MisbehaviorManager::ShouldDisconnect(int peer_id) const {
  bool result = false;
  peer_states_.Read(peer_id, [&](const PeerPtr& peer) {
    // NoBan peers are never disconnected (Manual peers get NoBan at grant time)
    if (HasPermission(peer->permissions(), NetPermissionFlags::NoBan)) {
      return;
    }
    result = peer->misbehavior().should_discourage;
  });
  return result;
}

bool MisbehaviorManager::IsMisbehaving(int peer_id) const {
  bool result = false;
  // Check lifetime misbehavior count (not the one-shot should_discourage flag)
  peer_states_.Read(peer_id, [&](const PeerPtr& peer) { result = peer->misbehavior().misbehavior_count > 0; });
  return result;
}

void MisbehaviorManager::NoteInvalidHeaderHash(int peer_id, const uint256& hash) {
  peer_states_.Modify(peer_id,
                      [&](PeerPtr& peer) { peer->misbehavior().invalid_header_hashes.insert(hash.GetHex()); });
}

bool MisbehaviorManager::HasInvalidHeaderHash(int peer_id, const uint256& hash) const {
  bool result = false;
  peer_states_.Read(peer_id, [&](const PeerPtr& peer) {
    result = peer->misbehavior().invalid_header_hashes.find(hash.GetHex()) !=
             peer->misbehavior().invalid_header_hashes.end();
  });
  return result;
}

}  // namespace network
}  // namespace unicity
