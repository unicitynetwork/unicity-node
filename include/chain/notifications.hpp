// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#pragma once

#include "chain/block.hpp"
#include "util/uint.hpp"

#include <functional>
#include <memory>
#include <mutex>
#include <vector>

namespace unicity {

// Event value types - immutable snapshots of what happened
// No pointers, no lifetime concerns, thread-safe by construction

struct BlockConnectedEvent {
  uint256 hash;
  int height;
  uint32_t time;
};

struct ChainTipEvent {
  uint256 hash;
  int height;
};

// Notification system for blockchain events
//
// Design:
// - Simple observer pattern with std::function
// - Thread-safe using std::mutex
// - Synchronous callbacks (no background queue)
// - RAII-based subscription management
//
// Events:
// - BlockConnected: New block added to active chain
// - ChainTip: Chain tip changed (may skip intermediate blocks)
// - FatalError: Unrecoverable error occurred
class ChainNotifications {
public:
  // Subscription handle - RAII wrapper
  // Automatically unsubscribes when destroyed
  class Subscription {
  public:
    Subscription() = default;
    ~Subscription();

    // Movable but not copyable
    Subscription(Subscription&& other) noexcept;
    Subscription& operator=(Subscription&& other) noexcept;
    Subscription(const Subscription&) = delete;
    Subscription& operator=(const Subscription&) = delete;

    // Unsubscribe explicitly
    void Unsubscribe();

  private:
    friend class ChainNotifications;
    Subscription(ChainNotifications* owner, size_t id);

    ChainNotifications* owner_{nullptr};
    size_t id_{0};
    bool active_{false};
  };

  // Callback types
  using BlockConnectedCallback = std::function<void(const BlockConnectedEvent& event)>;
  using ChainTipCallback = std::function<void(const ChainTipEvent& event)>;
  using FatalErrorCallback = std::function<void(const std::string& debug_message, const std::string& user_message)>;

  // Subscribe to block connected events. Returns RAII subscription handle.
  [[nodiscard]] Subscription SubscribeBlockConnected(BlockConnectedCallback callback);

  // Subscribe to chain tip updates. Returns RAII subscription handle.
  [[nodiscard]] Subscription SubscribeChainTip(ChainTipCallback callback);

  // Subscribe to fatal error notifications. Returns RAII subscription handle.
  [[nodiscard]] Subscription SubscribeFatalError(FatalErrorCallback callback);

  // Notify all subscribers of block connected.
  // Event contains snapshot of block data at connection time.
  void NotifyBlockConnected(const BlockConnectedEvent& event);

  // Notify all subscribers of chain tip update.
  // Event contains snapshot of tip data at change time.
  void NotifyChainTip(const ChainTipEvent& event);

  // Notify all subscribers of fatal error.
  // Called by ChainstateManager when encountering unrecoverable errors.
  void NotifyFatalError(const std::string& debug_message, const std::string& user_message);

  // Get singleton instance
  static ChainNotifications& Get();

private:
  ChainNotifications() = default;

  // Unsubscribe by ID (called by Subscription destructor)
  void Unsubscribe(size_t id);

  struct CallbackEntry {
    size_t id;
    BlockConnectedCallback block_connected;
    ChainTipCallback chain_tip;
    FatalErrorCallback fatal_error;
  };

  std::mutex mutex_;
  std::vector<CallbackEntry> callbacks_;
  size_t next_id_{1};  // 0 reserved for invalid
};

// Global accessor for notifications
inline ChainNotifications& Notifications() {
  return ChainNotifications::Get();
}

}  // namespace unicity