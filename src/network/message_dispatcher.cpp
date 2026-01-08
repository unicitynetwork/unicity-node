// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#include "network/message_dispatcher.hpp"

#include "network/message.hpp"
#include "network/peer.hpp"
#include "util/logging.hpp"

#include <algorithm>

namespace unicity {
namespace network {

void MessageDispatcher::RegisterHandler(const std::string& command, MessageHandler handler) {
  // Validate command is not empty
  if (command.empty()) {
    LOG_NET_WARN("Attempted to register handler for empty command");
    return;
  }

  // Validate handler is not empty (prevent std::bad_function_call)
  if (!handler) {
    LOG_NET_ERROR("Attempted to register empty handler for command: {}", command);
    return;
  }

  std::lock_guard<std::mutex> lock(mutex_);
  handlers_[command] = std::move(handler);
  LOG_NET_DEBUG("Registered handler for command: {}", command);
}

void MessageDispatcher::UnregisterHandler(const std::string& command) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (handlers_.erase(command) > 0) {
    LOG_NET_DEBUG("Unregistered handler for command: {}", command);
  }
}

bool MessageDispatcher::Dispatch(PeerPtr peer, const std::string& command, ::unicity::message::Message* msg) {
  if (command.empty()) {
    LOG_NET_WARN("MessageDispatcher::Dispatch called with empty command");
    return false;
  }

  if (!msg) {
    LOG_NET_WARN("MessageDispatcher::Dispatch called with null message");
    return false;
  }

  // Get handler (lock scope minimized)
  MessageHandler handler;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = handlers_.find(command);
    if (it == handlers_.end()) {
      // Special case: VERSION is always handled at Peer level (Peer::handle_version)
      // and may be optionally forwarded here for higher-layer hooks (e.g., duplicate tracking).
      // Return true to avoid TRACE log spam on every peer connection when no handler registered.
      // This is intentional and expected behavior - not an error condition.
      if (command == protocol::commands::VERSION) {
        return true;
      }
      LOG_NET_TRACE("No handler for command: {}", command);
      return false;
    }
    handler = it->second;
  }

  if (!handler) {
    LOG_NET_ERROR("Empty handler found for command: {} (should not happen)", command);
    return false;
  }

  // Execute handler (outside lock - handlers may take time)
  try {
    return handler(peer, msg);
  } catch (const std::exception& e) {
    LOG_NET_ERROR("Handler exception for command {}: {}", command, e.what());
    return false;
  } catch (...) {
    LOG_NET_ERROR("Unknown exception in handler for command {}", command);
    return false;
  }
}

bool MessageDispatcher::HasHandler(const std::string& command) const {
  std::lock_guard<std::mutex> lock(mutex_);
  return handlers_.count(command) > 0;
}

std::vector<std::string> MessageDispatcher::GetRegisteredCommands() const {
  std::lock_guard<std::mutex> lock(mutex_);
  std::vector<std::string> result;
  result.reserve(handlers_.size());
  for (const auto& [cmd, _] : handlers_) {
    result.push_back(cmd);
  }
  std::sort(result.begin(), result.end());
  return result;
}

}  // namespace network
}  // namespace unicity
