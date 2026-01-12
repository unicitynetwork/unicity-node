// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#pragma once

#include "util/uint.hpp"

#include <atomic>
#include <condition_variable>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace unicity {

// Forward declarations
namespace chain {
class ChainParams;
}
namespace network {
class NetworkManager;
}
namespace mining {
class CPUMiner;
}
namespace validation {
class ChainstateManager;
}

namespace rpc {

// RPC Server using Unix Domain Sockets (Local-Only Access)
class RPCServer {
public:
  using CommandHandler = std::function<std::string(const std::vector<std::string>&)>;

  RPCServer(const std::string& socket_path, validation::ChainstateManager& chainstate_manager,
            network::NetworkManager& network_manager, mining::CPUMiner* miner, const chain::ChainParams& params,
            std::function<void()> shutdown_callback = nullptr);
  ~RPCServer();

  bool Start();
  void Stop();
  bool IsRunning() const { return running_; }

private:

  void ServerThread();
  void HandleClient(int client_fd);
  std::string ExecuteCommand(const std::string& method, const std::vector<std::string>& params);
  void RegisterHandlers();

  // Helper to send response with error handling
  bool SendResponse(int client_fd, const std::string& response);

  // Command handlers - Blockchain
  std::string HandleGetInfo(const std::vector<std::string>& params);
  std::string HandleGetBlockchainInfo(const std::vector<std::string>& params);
  std::string HandleGetBlockCount(const std::vector<std::string>& params);
  std::string HandleGetBlockHash(const std::vector<std::string>& params);
  std::string HandleGetBlockHeader(const std::vector<std::string>& params);
  std::string HandleGetBestBlockHash(const std::vector<std::string>& params);
  std::string HandleGetDifficulty(const std::vector<std::string>& params);

  // Command handlers - Mining
  std::string HandleGetMiningInfo(const std::vector<std::string>& params);
  std::string HandleGetNetworkHashPS(const std::vector<std::string>& params);
  std::string HandleStartMining(const std::vector<std::string>& params);
  std::string HandleStopMining(const std::vector<std::string>& params);
  std::string HandleGenerate(const std::vector<std::string>& params);
  std::string HandleGetBlockTemplate(const std::vector<std::string>& params);
  std::string HandleSubmitBlock(const std::vector<std::string>& params);

  // Command handlers - Network
  std::string HandleGetConnectionCount(const std::vector<std::string>& params);
  std::string HandleGetPeerInfo(const std::vector<std::string>& params);
  std::string HandleAddNode(const std::vector<std::string>& params);
  std::string HandleSetBan(const std::vector<std::string>& params);
  std::string HandleListBanned(const std::vector<std::string>& params);
  std::string HandleGetAddrManInfo(const std::vector<std::string>& params);
  std::string HandleAddPeerAddress(const std::vector<std::string>& params);
  std::string HandleDisconnectNode(const std::vector<std::string>& params);
  std::string HandleGetNextWorkRequired(const std::vector<std::string>& params);
  std::string HandleReportMisbehavior(const std::vector<std::string>& params);
  std::string HandleAddOrphanHeader(const std::vector<std::string>& params);
  std::string HandleGetOrphanStats(const std::vector<std::string>& params);
  std::string HandleEvictOrphans(const std::vector<std::string>& params);

  // Command handlers - Control
  std::string HandleStop(const std::vector<std::string>& params);

  // Command handlers - Logging
  std::string HandleLogging(const std::vector<std::string>& params);

  // Command handlers - Testing
  std::string HandleSetMockTime(const std::vector<std::string>& params);
  std::string HandleInvalidateBlock(const std::vector<std::string>& params);
  std::string HandleClearBanned(const std::vector<std::string>& params);
  std::string HandleGetChainTips(const std::vector<std::string>& params);
  std::string HandleSubmitHeader(const std::vector<std::string>& params);
  std::string HandleAddConnection(const std::vector<std::string>& params);

private:
  std::string socket_path_;
  validation::ChainstateManager& chainstate_manager_;
  network::NetworkManager& network_manager_;
  mining::CPUMiner* miner_;  // Optional, can be nullptr
  const chain::ChainParams& params_;
  std::function<void()> shutdown_callback_;

  int server_fd_;
  std::atomic<bool> running_;
  std::atomic<bool> shutting_down_;
  std::thread server_thread_;

  // DoS protection: limit concurrent requests to prevent thread exhaustion
  std::atomic<int> active_requests_{0};
  static constexpr int MAX_CONCURRENT_REQUESTS = 10;

  std::map<std::string, CommandHandler> handlers_;

  // Long-polling support for getblocktemplate
  mutable std::mutex longpoll_mutex_;
  std::condition_variable longpoll_cv_;
  uint256 longpoll_tip_hash_;  // Current tip hash for long-poll detection

  // Notification subscription (must be destroyed before other members)
  class LongPollNotifier;
  std::unique_ptr<LongPollNotifier> longpoll_notifier_;

  // Called when chain tip changes (from notification callback)
  void OnChainTipChanged(const uint256& new_hash);
};

}  // namespace rpc
}  // namespace unicity
