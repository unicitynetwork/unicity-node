// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#include "network/rpc_client.hpp"

#include <cerrno>
#include <cstring>
#include <sstream>
#include <stdexcept>

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

namespace unicity {
namespace rpc {

RPCClient::RPCClient(const std::string& socket_path) : socket_path_(socket_path), socket_fd_(-1) {}

RPCClient::~RPCClient() {
  Disconnect();
}

std::optional<std::string> RPCClient::Connect() {
  if (socket_fd_ >= 0) {
    return std::nullopt;  // Already connected
  }

  // Validate socket path length BEFORE attempting connect
  // sockaddr_un::sun_path is 108 bytes on Linux/BSD, 104 on some systems
  // Use conservative limit to ensure cross-platform compatibility
  constexpr size_t MAX_SOCKET_PATH = 104;
  if (socket_path_.length() >= MAX_SOCKET_PATH) {
    std::ostringstream err;
    err << "Socket path too long (" << socket_path_.length() << " bytes, max " << MAX_SOCKET_PATH << ").\n"
        << "Use a shorter --datadir path.";
    return err.str();
  }

  // Create Unix domain socket
  socket_fd_ = socket(AF_UNIX, SOCK_STREAM, 0);
  if (socket_fd_ < 0) {
    return "Failed to create socket: " + std::string(std::strerror(errno));
  }

  // Set up socket address
  struct sockaddr_un addr;
  std::memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  std::strncpy(addr.sun_path, socket_path_.c_str(), sizeof(addr.sun_path) - 1);

  // Connect to node
  if (connect(socket_fd_, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
    std::string error = std::strerror(errno);
    close(socket_fd_);
    socket_fd_ = -1;
    return "Cannot connect to node at " + socket_path_ + ": " + error;
  }

  // Set recv() timeout to prevent client from hanging on slow/hung server
  // Timeout: 30 seconds (matches RPC server timeout)
  struct timeval timeout;
  timeout.tv_sec = 30;
  timeout.tv_usec = 0;
  if (setsockopt(socket_fd_, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
    close(socket_fd_);
    socket_fd_ = -1;
    return "Failed to set socket timeout: " + std::string(std::strerror(errno));
  }

  return std::nullopt;
}

std::string RPCClient::ExecuteCommand(const std::string& method, const std::vector<std::string>& params) {
  if (!IsConnected()) {
    throw std::runtime_error("Not connected to node");
  }

  // Build simple JSON-RPC request
  std::ostringstream request;
  request << "{\"method\":\"" << method << "\"";

  if (!params.empty()) {
    request << ",\"params\":[";
    for (size_t i = 0; i < params.size(); ++i) {
      if (i > 0)
        request << ",";
      request << "\"" << params[i] << "\"";
    }
    request << "]";
  }

  request << "}\n";

  std::string request_str = request.str();

  // Send request
  ssize_t sent = send(socket_fd_, request_str.c_str(), request_str.size(), 0);
  if (sent < 0) {
    throw std::runtime_error("Failed to send request");
  }

  // Receive response (read in loop to handle large responses)
  // Unix domain sockets don't have a content-length header, so we read until EOF
  // Server closes connection after sending response, signaling end of data
  std::string response;
  char buffer[4096];
  constexpr size_t MAX_RESPONSE_SIZE = 10 * 1024 * 1024;  // 10 MB limit

  while (true) {
    ssize_t received = recv(socket_fd_, buffer, sizeof(buffer), 0);

    if (received < 0) {
      throw std::runtime_error("Failed to receive response");
    }

    if (received == 0) {
      // Connection closed by server (normal end of response)
      break;
    }

    response.append(buffer, received);

    // Prevent unbounded memory growth from malicious/buggy server
    if (response.size() > MAX_RESPONSE_SIZE) {
      throw std::runtime_error("Response too large (>10MB)");
    }
  }

  return response;
}

void RPCClient::Disconnect() {
  if (socket_fd_ >= 0) {
    close(socket_fd_);
    socket_fd_ = -1;
  }
}

}  // namespace rpc
}  // namespace unicity
