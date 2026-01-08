// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#include "chain/notifications.hpp"

#include <algorithm>

namespace unicity {

// ============================================================================
// ChainNotifications::Subscription
// ============================================================================

ChainNotifications::Subscription::Subscription(ChainNotifications* owner, size_t id)
    : owner_(owner), id_(id), active_(true) {}

ChainNotifications::Subscription::~Subscription() {
  Unsubscribe();
}

ChainNotifications::Subscription::Subscription(Subscription&& other) noexcept
    : owner_(other.owner_), id_(other.id_), active_(other.active_) {
  other.owner_ = nullptr;
  other.active_ = false;
}

ChainNotifications::Subscription& ChainNotifications::Subscription::operator=(Subscription&& other) noexcept {
  if (this != &other) {
    Unsubscribe();
    owner_ = other.owner_;
    id_ = other.id_;
    active_ = other.active_;
    other.owner_ = nullptr;
    other.active_ = false;
  }
  return *this;
}

void ChainNotifications::Subscription::Unsubscribe() {
  if (active_ && owner_) {
    owner_->Unsubscribe(id_);
    active_ = false;
  }
}

// ============================================================================
// ChainNotifications
// ============================================================================

ChainNotifications::Subscription ChainNotifications::SubscribeBlockConnected(BlockConnectedCallback callback) {
  std::lock_guard<std::mutex> lock(mutex_);
  size_t id = next_id_++;

  CallbackEntry entry;
  entry.id = id;
  entry.block_connected = std::move(callback);
  callbacks_.push_back(std::move(entry));

  return Subscription(this, id);
}

ChainNotifications::Subscription ChainNotifications::SubscribeChainTip(ChainTipCallback callback) {
  std::lock_guard<std::mutex> lock(mutex_);
  size_t id = next_id_++;

  CallbackEntry entry;
  entry.id = id;
  entry.chain_tip = std::move(callback);
  callbacks_.push_back(std::move(entry));

  return Subscription(this, id);
}

ChainNotifications::Subscription ChainNotifications::SubscribeFatalError(FatalErrorCallback callback) {
  std::lock_guard<std::mutex> lock(mutex_);
  size_t id = next_id_++;

  CallbackEntry entry;
  entry.id = id;
  entry.fatal_error = std::move(callback);
  callbacks_.push_back(std::move(entry));

  return Subscription(this, id);
}

void ChainNotifications::NotifyBlockConnected(const BlockConnectedEvent& event) {
  // Create snapshot of callbacks to avoid holding lock during execution
  std::vector<BlockConnectedCallback> snapshot;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    snapshot.reserve(callbacks_.size());
    for (const auto& entry : callbacks_) {
      if (entry.block_connected) {
        snapshot.push_back(entry.block_connected);
      }
    }
  }

  // Execute callbacks without holding lock (prevents deadlock)
  for (const auto& callback : snapshot) {
    callback(event);
  }
}

void ChainNotifications::NotifyChainTip(const ChainTipEvent& event) {
  // Create snapshot of callbacks to avoid holding lock during execution
  std::vector<ChainTipCallback> snapshot;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    snapshot.reserve(callbacks_.size());
    for (const auto& entry : callbacks_) {
      if (entry.chain_tip) {
        snapshot.push_back(entry.chain_tip);
      }
    }
  }

  // Execute callbacks without holding lock (prevents deadlock)
  for (const auto& callback : snapshot) {
    callback(event);
  }
}

void ChainNotifications::NotifyFatalError(const std::string& debug_message, const std::string& user_message) {
  // Create snapshot of callbacks to avoid holding lock during execution
  std::vector<FatalErrorCallback> snapshot;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    snapshot.reserve(callbacks_.size());
    for (const auto& entry : callbacks_) {
      if (entry.fatal_error) {
        snapshot.push_back(entry.fatal_error);
      }
    }
  }

  // Execute callbacks without holding lock (prevents deadlock)
  for (const auto& callback : snapshot) {
    callback(debug_message, user_message);
  }
}

void ChainNotifications::Unsubscribe(size_t id) {
  std::lock_guard<std::mutex> lock(mutex_);

  auto it = std::find_if(callbacks_.begin(), callbacks_.end(),
                         [id](const CallbackEntry& entry) { return entry.id == id; });

  if (it != callbacks_.end()) {
    callbacks_.erase(it);
  }
}

ChainNotifications& ChainNotifications::Get() {
  static ChainNotifications instance;
  return instance;
}

}  // namespace unicity
