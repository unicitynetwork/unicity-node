// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#include "test_access.hpp"

namespace unicity {
namespace test {

void PeerTestAccess::SetTimeouts(std::chrono::milliseconds handshake_ms, std::chrono::milliseconds inactivity_ms) {
  network::Peer::handshake_timeout_override_ms_.store(handshake_ms, std::memory_order_relaxed);
  network::Peer::inactivity_timeout_override_ms_.store(inactivity_ms, std::memory_order_relaxed);
}

void PeerTestAccess::ResetTimeouts() {
  network::Peer::handshake_timeout_override_ms_.store(std::chrono::milliseconds{0}, std::memory_order_relaxed);
  network::Peer::inactivity_timeout_override_ms_.store(std::chrono::milliseconds{0}, std::memory_order_relaxed);
}

void NetworkManagerTestAccess::TriggerSelfAdvertisement(network::NetworkManager& nm) {
  // Reset timer to force send and call internal method
  nm.next_local_addr_send_ = {};
  nm.maybe_send_local_addr();
}

void NetworkManagerTestAccess::AttemptFeelerConnection(network::NetworkManager& nm) {
  // Delegate to ConnectionManager
  nm.peer_manager_->AttemptFeelerConnection(nm.chainstate_manager_.GetChainHeight());
}

size_t AddrRelayManagerTestAccess::GetPendingAddrRelayCount(network::AddrRelayManager& pdm) {
  size_t total = 0;
  for (const auto& [peer_id, state] : pdm.peer_addr_send_state_) {
    total += state.addrs_to_send.size();
  }
  return total;
}

void ConnectionManagerTestAccess::SetPeerCreatedAt(network::ConnectionManager& pm, int peer_id, std::chrono::steady_clock::time_point tp) {
  pm.peer_states_.Modify(peer_id, [&](network::PeerPtr& peer) { peer->set_created_at(tp); });
}

void NetworkManagerTestAccess::SetLocalAddr(network::NetworkManager& nm, const protocol::NetworkAddress& addr) {
  std::lock_guard<std::mutex> lock(nm.local_addr_mutex_);
  nm.local_addr_ = addr;
}

void NetworkManagerTestAccess::ClearLocalAddr(network::NetworkManager& nm) {
  std::lock_guard<std::mutex> lock(nm.local_addr_mutex_);
  nm.local_addr_.reset();
}

std::optional<protocol::NetworkAddress> NetworkManagerTestAccess::GetLocalAddr(network::NetworkManager& nm) {
  std::lock_guard<std::mutex> lock(nm.local_addr_mutex_);
  return nm.local_addr_;
}

bool NetworkManagerTestAccess::HasLocalAddr(network::NetworkManager& nm) {
  std::lock_guard<std::mutex> lock(nm.local_addr_mutex_);
  return nm.local_addr_.has_value();
}

void NetworkManagerTestAccess::ResetNextLocalAddrSend(network::NetworkManager& nm) {
  nm.next_local_addr_send_ = {};
}

}  // namespace test
}  // namespace unicity
