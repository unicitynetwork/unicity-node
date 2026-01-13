// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#include "application.hpp"
#include "chain/randomx_pow.hpp"
#include "network/peer_discovery_manager.hpp"
#include "util/fs_lock.hpp"
#include "util/logging.hpp"
#include "util/sha256.hpp"
#include "util/time.hpp"
#include "version.hpp"
#include <chrono>
#include <iostream>
#include <thread>
#include <unistd.h>  // For write(), STDOUT_FILENO (async-signal-safe)

namespace unicity {
namespace app {

// Static instance for signal handling
Application *Application::instance_ = nullptr;

Application::Application(const AppConfig &config) : config_(config) {
  instance_ = this;
}

Application::~Application() {
  try {
    stop();
  } catch (...) {   
  }
  instance_ = nullptr;
}

Application *Application::instance() { return instance_; }

bool Application::initialize() {
  if (config_.chain_type == chain::ChainType::MAIN) {
    std::cerr << "ERROR: Mainnet is not yet available.\n"
              << "Please use --testnet or --regtest for now.\n";
    return false;
  }

  // Determine chain type name for banner
  std::string chain_name;
  switch (config_.chain_type) {
  case chain::ChainType::MAIN:
    chain_name = "MAINNET";
    break;
  case chain::ChainType::TESTNET:
    chain_name = "TESTNET";
    break;
  case chain::ChainType::REGTEST:
    chain_name = "REGTEST";
    break;
  }

  // Print startup banner (use std::cout for immediate visibility before logger
  // fully initialized)
  std::cout << GetStartupBanner(chain_name) << std::flush;

  LOG_INFO("Initializing Unicity...");

  // Create data directory
  if (!init_datadir()) {
    LOG_ERROR("Failed to initialize data directory");
    return false;
  }

  // Initialize RandomX
  if (!init_randomx()) {
    LOG_ERROR("Failed to initialize RandomX");
    return false;
  }

  // Initialize blockchain (creates chainstate_manager)
  if (!init_chain()) {
    LOG_ERROR("Failed to initialize blockchain");
    return false;
  }

  // Initialize miner (after chainstate is ready)
  LOG_INFO("Initializing miner...");
  miner_ =
      std::make_unique<mining::CPUMiner>(*chain_params_, *chainstate_manager_);

  // Initialize network manager
  if (!init_network()) {
    LOG_ERROR("Failed to initialize network manager");
    return false;
  }

  // Initialize RPC server
  if (!init_rpc()) {
    LOG_ERROR("Failed to initialize RPC server");
    return false;
  }

  // Subscribe to block notifications to relay new blocks to peers
  block_sub_ = Notifications().SubscribeBlockConnected(
      [this](const BlockConnectedEvent& event) {
        if (!network_manager_ || chainstate_manager_->IsInitialBlockDownload()) {
          return;
        }
        // Relay non-genesis blocks (height > 0)
        if (event.height > 0) {
          network_manager_->relay_block(event.hash);
        }
      });

  // Subscribe to fatal error notifications to trigger immediate shutdown
  fatal_error_sub_ = Notifications().SubscribeFatalError(
      [this](const std::string& debug_message, const std::string& user_message) {
        LOG_ERROR("Application: Fatal error - {}", debug_message);
        if (!user_message.empty()) {
          LOG_ERROR("User message: {}", user_message);
        }
        LOG_ERROR("Initiating emergency shutdown due to unrecoverable error");
        request_shutdown();
      });

  // Subscribe to chain tip changes to invalidate miner block templates and announce to peers
  tip_sub_ = Notifications().SubscribeChainTip(
      [this](const ChainTipEvent& event) {
        (void)event;  // event data available if needed
        if (miner_) {
          miner_->InvalidateTemplate();
        }
        // Announcements are queued here and flushed by periodic SendMessages-like loop
        if (network_manager_) {
          network_manager_->announce_tip_to_peers();
        }
      });

  LOG_INFO("Initialization complete");
  return true;
}

bool Application::start() {
  if (running_) {
    LOG_ERROR("Application already running");
    return false;
  }

  LOG_INFO("Starting Unicity...");

  // Check for network expiration on startup
  const chain::ConsensusParams& consensus = chain_params_->GetConsensus();
  if (consensus.nNetworkExpirationInterval > 0) {
    const chain::CBlockIndex* tip = chainstate_manager_->GetTip();
    if (tip && tip->nHeight >= consensus.nNetworkExpirationInterval) {
      LOG_ERROR("Network expired at block {} (current: {}). "
                "This version is outdated. Please update to the latest version.",
                consensus.nNetworkExpirationInterval, tip->nHeight);
      request_shutdown();
      return false;
    }
  }

  // Setup signal handlers
  setup_signal_handlers();

  // Start network manager
  if (!network_manager_->start()) {
    LOG_ERROR("Failed to start network manager");
    return false;
  }

  // Start RPC server
  if (!rpc_server_->Start()) {
    LOG_ERROR("Failed to start RPC server");
    return false;
  }

  running_ = true;

  // Start periodic save thread
  start_periodic_saves();

  LOG_INFO("Unicity started successfully");
  LOG_INFO("Data directory: {}", config_.datadir.string());

  if (config_.network_config.listen_enabled) {
    LOG_INFO("Listening on port: {}", config_.network_config.listen_port);
  } else {
    LOG_INFO("Inbound connections disabled");
  }

  LOG_INFO("Press Ctrl+C to stop");

  return true;
}

void Application::stop() {
  if (!running_) {
    return;
  }

  shutdown();
}

void Application::wait_for_shutdown() {
  // Wait for shutdown signal
  while (running_ && !shutdown_requested_) {
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }

  if (shutdown_requested_) {
    shutdown();
  }
}

void Application::shutdown() {
  if (!running_) {
    return;
  }

  LOG_INFO("Shutting down Unicity...");

  running_ = false;

  // Stop periodic saves
  stop_periodic_saves();

  // Unsubscribe before stopping components to prevent race conditions
  block_sub_.Unsubscribe();
  fatal_error_sub_.Unsubscribe();
  tip_sub_.Unsubscribe();

  // Stop RPC server first (stop accepting new requests)
  if (rpc_server_) {
    LOG_INFO("Stopping RPC server...");
    rpc_server_->Stop();
  }

  // Stop miner if running
  if (miner_ && miner_->IsMining()) {
    LOG_INFO("Stopping miner...");
    miner_->Stop();
  }

  // Stop network manager
  if (network_manager_) {
    LOG_INFO("Stopping network manager...");
    network_manager_->stop();
  }

  // Save headers and peers to disk (anchors saved in NetworkManager::stop)
  if (chainstate_manager_) {
    LOG_INFO("Saving headers to disk...");
    std::string headers_file = (config_.datadir / "headers.json").string();
    if (!chainstate_manager_->Save(headers_file)) {
      LOG_ERROR("Failed to save headers");
    }
  }

  if (network_manager_) {
    LOG_INFO("Saving peer addresses to disk...");
    std::string peers_file = (config_.datadir / "peers.json").string();
    if (!network_manager_->discovery_manager().SaveAddresses(peers_file)) {
      LOG_ERROR("Failed to save peer addresses");
    }
  }

  // Shutdown RandomX
  LOG_INFO("Shutting down RandomX...");
  crypto::ShutdownRandomX();

  // Release data directory lock
  LOG_INFO("Releasing data directory lock...");
  util::UnlockDirectory(config_.datadir, ".lock");

  LOG_INFO("Shutdown complete");
}

bool Application::init_datadir() {
  // Validate datadir is set (should never be empty if get_default_datadir() works correctly)
  if (config_.datadir.empty()) {
    LOG_ERROR("Data directory is not set. This should not happen - "
              "HOME environment variable may not be set. "
              "Please use --datadir flag to specify data directory explicitly.");
    return false;
  }

  LOG_INFO("Data directory: {}", config_.datadir.string());

  if (!util::ensure_directory(config_.datadir)) {
    LOG_ERROR("Failed to create data directory: {}", config_.datadir.string());
    return false;
  }

  // SECURITY: Enforce restrictive permissions on datadir (owner-only access)
#if defined(__unix__) || defined(__APPLE__)
  std::filesystem::permissions(config_.datadir,
                                std::filesystem::perms::owner_all,
                                std::filesystem::perm_options::replace);
  LOG_DEBUG("Set datadir permissions to 0700 (owner-only)");
#endif

  // Lock the data directory to prevent multiple instances
  util::LockResult lock_result = util::LockDirectory(config_.datadir, ".lock");

  if (lock_result == util::LockResult::ErrorWrite) {
    LOG_ERROR("Cannot write to data directory: {}", config_.datadir.string());
    return false;
  }

  if (lock_result == util::LockResult::ErrorLock) {
    LOG_ERROR("Cannot obtain a lock on data directory {}. "
              "Unicity is probably already running.",
              config_.datadir.string());
    return false;
  }

  LOG_DEBUG("Successfully locked data directory");
  return true;
}

bool Application::init_randomx() {
  LOG_INFO("Initializing RandomX...");

  // Initialize RandomX (thread-local VMs and caches)
  crypto::InitRandomX();

  // Initialize SHA256 hardware acceleration
  // IMPORTANT: This must be called early to enable SSE4/AVX2/SHANI optimizations
  std::string sha256_impl = SHA256AutoDetect();
  LOG_INFO("SHA256 implementation: {}", sha256_impl);

  return true;
}

bool Application::init_chain() {
  LOG_INFO("Initializing blockchain...");

  // Select chain type globally (needed by NetworkManager)
  chain::GlobalChainParams::Select(config_.chain_type);

  // Create chain params based on type
  switch (config_.chain_type) {
  case chain::ChainType::MAIN:
    chain_params_ = chain::ChainParams::CreateMainNet();
    LOG_INFO("Using mainnet");
    break;
  case chain::ChainType::TESTNET:
    chain_params_ = chain::ChainParams::CreateTestNet();
    LOG_INFO("Using testnet");
    break;
  case chain::ChainType::REGTEST:
    chain_params_ = chain::ChainParams::CreateRegTest();
    LOG_INFO("Using regtest");
    break;
  }

  // Create chainstate manager (which owns BlockManager)
  // Apply command-line override to chain params if provided
  if (config_.suspicious_reorg_depth > 0) {
    LOG_INFO("Overriding suspicious reorg depth: {} (default was {})",
             config_.suspicious_reorg_depth,
             chain_params_->GetConsensus().nSuspiciousReorgDepth);
    chain_params_->SetSuspiciousReorgDepth(config_.suspicious_reorg_depth);
  }
  chainstate_manager_ = std::make_unique<validation::ChainstateManager>(*chain_params_);

  // Try to load headers from disk
  std::string headers_file = (config_.datadir / "headers.json").string();
  if (config_.revalidate_headers) {
    LOG_INFO("Revalidating all headers on load (paranoid mode)");
  }
  chain::LoadResult load_result = chainstate_manager_->Load(headers_file, config_.revalidate_headers);

  switch (load_result) {
    case chain::LoadResult::SUCCESS:
      LOG_INFO("Loaded headers from disk");
      break;

    case chain::LoadResult::FILE_NOT_FOUND:
      // No existing headers, initialize with genesis block
      LOG_INFO("No existing headers found, initializing with genesis block");
      {
        const CBlockHeader &genesis = chain_params_->GenesisBlock();
        if (!chainstate_manager_->Initialize(genesis)) {
          LOG_ERROR("Failed to initialize blockchain");
          return false;
        }
      }
      break;

    case chain::LoadResult::CORRUPTED:
      // FATAL: Header file exists but is corrupted
      // This requires manual intervention - user must delete headers.json and resync
      LOG_ERROR("FATAL: Header file {} is corrupted!", headers_file);
      LOG_ERROR("Please delete the file and restart to resync from network.");
      LOG_ERROR("Refusing to start to prevent data loss.");
      return false;
  }

  LOG_INFO("Blockchain initialized at height: {}",
           chainstate_manager_->GetChainHeight());

  return true;
}

bool Application::init_network() {
  LOG_INFO("Initializing network manager...");

  config_.network_config.datadir = config_.datadir.string();
  network_manager_ = std::make_unique<network::NetworkManager>(
      *chainstate_manager_, config_.network_config);

  // Load peer addresses (anchors loaded during start() when connection machinery is ready)
  std::string peers_file = (config_.datadir / "peers.json").string();
  network_manager_->discovery_manager().LoadAddresses(peers_file);

  return true;
}

bool Application::init_rpc() {
  LOG_INFO("Initializing RPC server...");

  std::string socket_path = (config_.datadir / "node.sock").string();

  // Create shutdown callback
  auto shutdown_callback = [this]() { this->request_shutdown(); };

  rpc_server_ = std::make_unique<rpc::RPCServer>(
      socket_path, *chainstate_manager_, *network_manager_, miner_.get(),
      *chain_params_, shutdown_callback);

  return true;
}

void Application::setup_signal_handlers() {
  std::signal(SIGINT, Application::signal_handler);
  std::signal(SIGTERM, Application::signal_handler);
  // Ignore SIGPIPE to prevent crashes on broken network connections
  std::signal(SIGPIPE, SIG_IGN);
}

void Application::signal_handler(int signal) {
  if (instance_) {
    // Use write() for async-signal-safety (std::cout, snprintf are NOT safe)
    // Cast to void to silence warn_unused_result - nothing we can do if write fails in signal handler
    static const char msg[] = "\nReceived signal\n";
    (void)write(STDOUT_FILENO, msg, sizeof(msg) - 1);

    instance_->shutdown_requested_ = true;
  }
}

void Application::start_periodic_saves() {
  LOG_INFO("Starting periodic header saves (every 10 minutes)");
  save_thread_ =
      std::make_unique<std::thread>(&Application::periodic_save_loop, this);
}

void Application::stop_periodic_saves() {
  if (save_thread_ && save_thread_->joinable()) {
    LOG_DEBUG("Stopping periodic save thread");
    save_thread_->join();
    save_thread_.reset();
  }
}

void Application::periodic_save_loop() {
  using namespace std::chrono;

  // - Headers: 10 minutes
  // - Peers: 15 minutes
  const auto header_interval = minutes(10);
  const auto peer_interval = minutes(15);

  auto last_header_save = steady_clock::now();
  auto last_peer_save = steady_clock::now();

  while (running_) {
    std::this_thread::sleep_for(seconds(1));

    if (!running_)
      break;

    auto now = steady_clock::now();

    // Save headers every 10 minutes
    if (now - last_header_save >= header_interval) {
      save_headers();
      last_header_save = now;
    }

    // Save peers every 15 minutes
    if (now - last_peer_save >= peer_interval) {
      save_peers();
      last_peer_save = now;
    }
  }
}

void Application::save_headers() {
  if (!chainstate_manager_) {
    return;
  }

  std::string headers_file = (config_.datadir / "headers.json").string();
  LOG_DEBUG("Periodic save: saving headers to {}", headers_file);

  if (!chainstate_manager_->Save(headers_file)) {
    LOG_ERROR("Periodic header save failed");
  } else {
    LOG_DEBUG("Periodic header save complete ({} headers at height {})",
              chainstate_manager_->GetBlockCount(),
              chainstate_manager_->GetChainHeight());
  }
}

void Application::save_peers() {
  if (!network_manager_) {
    return;
  }

  std::string peers_file = (config_.datadir / "peers.json").string();
  LOG_DEBUG("Periodic save: saving peer addresses to {}", peers_file);

  if (!network_manager_->discovery_manager().SaveAddresses(peers_file)) {
    LOG_ERROR("Periodic peer save failed");
  }
}

} // namespace app
} // namespace unicity
