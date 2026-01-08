// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#include "network/misbehavior_manager.hpp"

#include "network/peer_misbehavior.hpp"
#include "util/logging.hpp"

namespace unicity {
namespace network {

MisbehaviorManager::MisbehaviorManager(util::ThreadSafeMap<int, PeerTrackingData>& peer_states)
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

void MisbehaviorManager::ReportTooManyOrphans(int peer_id) {
  Misbehaving(peer_id, "exceeded orphan header limit");
}

void MisbehaviorManager::ReportPreVerackMessage(int peer_id) {
  Misbehaving(peer_id, "protocol message before handshake complete");
}

bool MisbehaviorManager::Misbehaving(int peer_id, const std::string& reason) {
  bool should_disconnect = false;

  peer_states_.Modify(peer_id, [&](PeerTrackingData& state) {
    PeerMisbehaviorData& data = state.misbehavior;

    // Mark for discouragement
    data.should_discourage = true;

    LOG_NET_INFO("Misbehaving: peer={} ({}) {}", peer_id, data.address, reason);

    // Check if peer has NoBan permission
    if (HasPermission(data.permissions, NetPermissionFlags::NoBan)) {
      LOG_NET_WARN("Not punishing noban peer {}", peer_id);
      return;
    }

    should_disconnect = true;
  });

  return should_disconnect;
}

bool MisbehaviorManager::ShouldDisconnect(int peer_id) const {
  bool result = false;
  peer_states_.Read(peer_id, [&](const PeerTrackingData& state) {
    // Never disconnect peers with NoBan permission
    if (HasPermission(state.misbehavior.permissions, NetPermissionFlags::NoBan)) {
      return;
    }
    result = state.misbehavior.should_discourage;
  });
  return result;
}

bool MisbehaviorManager::IsMisbehaving(int peer_id) const {
  bool result = false;
  peer_states_.Read(peer_id, [&](const PeerTrackingData& state) { result = state.misbehavior.should_discourage; });
  return result;
}

void MisbehaviorManager::NoteInvalidHeaderHash(int peer_id, const uint256& hash) {
  peer_states_.Modify(peer_id,
                      [&](PeerTrackingData& state) { state.misbehavior.invalid_header_hashes.insert(hash.GetHex()); });
}

bool MisbehaviorManager::HasInvalidHeaderHash(int peer_id, const uint256& hash) const {
  bool result = false;
  peer_states_.Read(peer_id, [&](const PeerTrackingData& state) {
    result = state.misbehavior.invalid_header_hashes.find(hash.GetHex()) !=
             state.misbehavior.invalid_header_hashes.end();
  });
  return result;
}

void MisbehaviorManager::IncrementUnconnectingHeaders(int peer_id) {
  bool threshold_exceeded = false;

  peer_states_.Modify(peer_id, [&](PeerTrackingData& state) {
    PeerMisbehaviorData& data = state.misbehavior;
    if (data.unconnecting_penalized) {
      return;  // already penalized; do nothing further
    }
    data.num_unconnecting_headers_msgs++;

    LOG_NET_TRACE("IncrementUnconnectingHeaders: peer {} now has {} unconnecting msgs (threshold={})", peer_id,
                  data.num_unconnecting_headers_msgs, MAX_UNCONNECTING_HEADERS);

    if (data.num_unconnecting_headers_msgs >= MAX_UNCONNECTING_HEADERS) {
      LOG_NET_TRACE("peer {} ({}) sent too many unconnecting headers ({} >= {})", peer_id, data.address,
                    data.num_unconnecting_headers_msgs, MAX_UNCONNECTING_HEADERS);
      data.unconnecting_penalized = true;  // latch to avoid repeated penalties
      threshold_exceeded = true;
    }
  });

  if (!peer_states_.Contains(peer_id)) {
    LOG_NET_TRACE("IncrementUnconnectingHeaders: peer {} not found in misbehavior map", peer_id);
    return;
  }

  if (threshold_exceeded) {
    Misbehaving(peer_id, "too many unconnecting headers");
  }
}

void MisbehaviorManager::ResetUnconnectingHeaders(int peer_id) {
  peer_states_.Modify(peer_id, [](PeerTrackingData& state) { state.misbehavior.num_unconnecting_headers_msgs = 0; });
}

int MisbehaviorManager::GetUnconnectingHeadersCount(int peer_id) const {
  int result = 0;
  peer_states_.Read(peer_id,
                    [&](const PeerTrackingData& state) { result = state.misbehavior.num_unconnecting_headers_msgs; });
  return result;
}

}  // namespace network
}  // namespace unicity
