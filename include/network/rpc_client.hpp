// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#pragma once

#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace unicity {
namespace rpc {

// Simple JSON-RPC client for querying the node
// Uses Unix domain sockets for IPC between cli and node
// (simpler than HTTP/REST for local communication)
class RPCClient {
public:
  // Constructor. socket_path is path to Unix domain socket (e.g., ~/.unicity/node.sock).
  explicit RPCClient(const std::string& socket_path);
  ~RPCClient();

  // Connect to the node. Returns empty optional if connected successfully, error message otherwise.
  std::optional<std::string> Connect();

  // Execute RPC command with method name (e.g., "getinfo", "getblockchaininfo") and parameters.
  // Returns response string (JSON).
  std::string ExecuteCommand(const std::string& method, const std::vector<std::string>& params = {});

  // Check if connected.
  bool IsConnected() const { return socket_fd_ >= 0; }

  // Disconnect from node.
  void Disconnect();

private:
  std::string socket_path_;
  int socket_fd_;
};

}  // namespace rpc
}  // namespace unicity
