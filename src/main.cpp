// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#include "application.hpp"
#include "util/logging.hpp"
#include "util/string_parsing.hpp"
#include "version.hpp"
#include <filesystem>
#include <iostream> // Keep for CLI output and early errors before logger initialized
#include <set>

void print_usage(const char *program_name) {
  std::cout
      << "Usage: " << program_name << " [options]\n"
      << "\n"
      << "Options:\n"
      << "  --datadir=<path>     Data directory (default: ~/.unicity)\n"
      << "  --port=<port>        Listen port (default: 9590 mainnet, 19590 testnet, 29590 regtest)\n"
      << "  --nolisten           Disable inbound connections (inbound is enabled by default)\n"
      << "  --connect=<n>        Maximum outbound connections (0 = disable automatic outbound)\n"
      << "  --suspiciousreorgdepth=<n>  Override suspicious reorg depth (0 = use chain default)\n"
      << "  --regtest            Use regression test chain (easy mining)\n"
      << "  --testnet            Use test network\n"
      << "\n"
      << "Logging:\n"
      << "  --loglevel=<level>   Set global log level (trace,debug,info,warn,error,critical)\n"
      << "                       Default: info\n"
      << "  --debug=<component>  Enable trace logging for specific component(s)\n"
      << "                       Components: network, sync, chain, crypto, app, all\n"
      << "                       Can be comma-separated: --debug=network,sync\n"
      << "  --verbose            Equivalent to --loglevel=debug\n"
      << "\n"
      << "Other:\n"
      << "  --revalidate-headers Revalidate all headers on load (slow, paranoid mode)\n"
      << "  --version            Show version information\n"
      << "  --help               Show this help message\n"
      << std::endl;
}

int main(int argc, char *argv[]) {
  try {
    // Parse command line arguments
    unicity::app::AppConfig config;
    std::string log_level = "info";
    std::vector<std::string> debug_components;

    for (int i = 1; i < argc; ++i) {
      std::string arg = argv[i];

      if (arg == "--help") {
        print_usage(argv[0]);
        return 0;
      } else if (arg == "--version") {
        std::cout << unicity::GetFullVersionString() << std::endl;
        std::cout << unicity::GetCopyrightString() << std::endl;
        return 0;
      } else if (arg.find("--datadir=") == 0) {
        std::string datadir = arg.substr(10);
        if (datadir.empty()) {
          std::cerr << "Error: --datadir requires a non-empty path" << std::endl;
          return 1;
        }
        config.datadir = datadir;
      } else if (arg.find("--port=") == 0) {
        auto port_opt = unicity::util::SafeParsePort(arg.substr(7));
        if (!port_opt) {
          std::cerr << "Error: Invalid port number: " << arg.substr(7) << std::endl;
          std::cerr << "Port must be a number between 1 and 65535" << std::endl;
          return 1;
        }
        config.network_config.listen_port = *port_opt;
      } else if (arg == "--nolisten") {
        config.network_config.listen_enabled = false;
      } else if (arg == "--listen") {
        // Listen is enabled by default; this flag is a no-op for backwards compatibility
      } else if (arg.find("--connect=") == 0) {
        auto connect_opt = unicity::util::SafeParseInt(arg.substr(10), 0, 10000);
        if (!connect_opt) {
          std::cerr << "Error: Invalid --connect value: " << arg.substr(10) << std::endl;
          std::cerr << "Value must be a number between 0 and 10000" << std::endl;
          return 1;
        }
        config.network_config.max_outbound_connections = *connect_opt;
      } else if (arg.find("--suspiciousreorgdepth=") == 0) {
        auto depth_opt = unicity::util::SafeParseInt(arg.substr(23), 0, 1000000);
        if (!depth_opt) {
          std::cerr << "Error: Invalid suspicious reorg depth: " << arg.substr(23) << std::endl;
          std::cerr << "Depth must be a number between 0 and 1000000" << std::endl;
          return 1;
        }
        config.suspicious_reorg_depth = *depth_opt;
      } else if (arg == "--regtest") {
        config.chain_type = unicity::chain::ChainType::REGTEST;
        config.network_config.network_magic =
            unicity::protocol::magic::REGTEST;
        config.network_config.listen_port =
            unicity::protocol::ports::REGTEST;
        // Disable NAT for regtest (localhost testing doesn't need UPnP)
        config.network_config.enable_nat = false;
      } else if (arg == "--testnet") {
        config.chain_type = unicity::chain::ChainType::TESTNET;
        config.network_config.network_magic =
            unicity::protocol::magic::TESTNET;
        config.network_config.listen_port =
            unicity::protocol::ports::TESTNET;
      } else if (arg == "--verbose") {
        config.verbose = true;
        log_level = "debug";
      } else if (arg.find("--loglevel=") == 0) {
        log_level = arg.substr(11);
      } else if (arg == "--revalidate-headers") {
        config.revalidate_headers = true;
      } else if (arg.find("--debug=") == 0) {
        // Parse comma-separated components: --debug=net,sync,chain
        std::string components = arg.substr(8);
        size_t pos = 0;
        while (pos < components.length()) {
          size_t comma = components.find(',', pos);
          if (comma == std::string::npos) {
            debug_components.push_back(components.substr(pos));
            break;
          }
          debug_components.push_back(components.substr(pos, comma - pos));
          pos = comma + 1;
        }
      } else {
        std::cerr << "Unknown option: " << arg << std::endl;
        print_usage(argv[0]);
        return 1;
      }
    }

    // Ensure datadir exists before initializing file logger
    try {
      std::filesystem::create_directories(config.datadir);
    } catch (const std::exception& e) {
      std::cerr << "Error: Failed to create data directory '" << config.datadir.string()
                << "': " << e.what() << std::endl;
      return 1;
    }
    // Initialize logging system (enable file logging with debug.log)
    std::string log_file = (config.datadir / "debug.log").string();
    unicity::util::LogManager::Initialize(log_level, true, log_file);

    // Apply component-specific debug levels
    // Valid components: all, net/network, sync, chain, crypto, app
    const std::set<std::string> valid_components = {"all", "net", "network", "sync", "chain", "crypto", "app"};
    for (const auto& component : debug_components) {
      if (valid_components.find(component) == valid_components.end()) {
        std::cerr << "Warning: Unknown debug component '" << component
                  << "'. Valid components: network, sync, chain, crypto, app, all" << std::endl;
        continue;
      }
      if (component == "all") {
        unicity::util::LogManager::SetLogLevel("trace");
      } else if (component == "net" || component == "network") {
        unicity::util::LogManager::SetComponentLevel("network", "trace");
      } else {
        unicity::util::LogManager::SetComponentLevel(component, "trace");
      }
    }

    // Create and initialize application
    {
      unicity::app::Application app(config);

      if (!app.initialize()) {
        LOG_ERROR("Failed to initialize application");
        return 1;
      }

      if (!app.start()) {
        LOG_ERROR("Failed to start application");
        return 1;
      }

      // Run until shutdown requested
      app.wait_for_shutdown();
    } // app destructor runs here, stopping all network operations

    unicity::util::LogManager::Shutdown();

    return 0;

  } catch (const std::exception &e) {
    // Use std::cerr here because logger may not be safe during exception
    // handling
    std::cerr << "Fatal exception: " << e.what() << std::endl;
    unicity::util::LogManager::Shutdown();
    return 1;
  }
}
