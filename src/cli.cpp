// Copyright (c) 2025 The Unicity Foundation
// Distributed under the MIT software license

#include "network/rpc_client.hpp"
#include "util/files.hpp"
#include "version.hpp"
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

void PrintUsage(const char *program_name) {
  std::cout
      << "Unicity CLI - Query blockchain node\n\n"
      << "Usage: " << program_name << " [options] <command> [params]\n\n"
      << "Options:\n"
      << "  --datadir=<path>     Data directory (default: ~/.unicity)\n"
      << "  --version            Show version information\n"
      << "  --help               Show this help message\n\n"
      << "Commands:\n"
      << "\n"
      << "Blockchain:\n"
      << "  getinfo                      Get general node information\n"
      << "  getblockchaininfo            Get blockchain state information\n"
      << "  getblockcount                Get current block height\n"
      << "  getblockhash <height>        Get block hash at height\n"
      << "  getblockheader <hash>        Get block header by hash\n"
      << "  getbestblockhash             Get hash of best (tip) block\n"
      << "  getdifficulty                Get proof-of-work difficulty\n"
      << "  getchaintips                 Get all known chain tips\n"
      << "  getnextworkrequired          Get next difficulty target\n"
      << "\n"
      << "Mining:\n"
      << "  getmininginfo                Get mining-related information\n"
      << "  getnetworkhashps [nblocks]   Get network hashes per second\n"
      << "  startmining                  Start CPU mining\n"
      << "  stopmining                   Stop CPU mining\n"
      << "  generate <nblocks>           Generate blocks (regtest only)\n"
      << "  getblocktemplate [longpollid]  Get block template for external mining\n"
      << "  submitblock <hexheader>      Submit mined block (100-byte header)\n"
      << "\n"
      << "Network:\n"
      << "  getconnectioncount           Get number of connections\n"
      << "  getpeerinfo                  Get connected peer information\n"
      << "  getaddrmaninfo               Get address manager statistics\n"
      << "  addnode <node> <add|remove|onetry>  Manage node connections\n"
      << "  disconnectnode <address>     Disconnect a peer\n"
      << "  setban <subnet> <add|remove> Ban/unban IP address or subnet\n"
      << "  listbanned                   List all banned IPs\n"
      << "  clearbanned                  Clear all banned IPs\n"
      << "\n"
      << "Logging:\n"
      << "  logging [<category>:<level>...]  Get/set logging configuration\n"
      << "\n"
      << "Control:\n"
      << "  stop                         Stop the node\n"
      << "\n"
      << "Testing/Debug (regtest only):\n"
      << "  setmocktime <timestamp>      Set mock time for testing\n"
      << "  invalidateblock <hash>       Mark block as invalid\n"
      << "  submitheader <hex>           Submit block header\n"
      << "  addconnection <addr> <type>  Add connection (type: outbound-full-relay,\n"
      << "                               block-relay-only, feeler)\n"
      << "  reportmisbehavior <peerid> <score>  Report peer misbehavior\n"
      << "  addorphanheader <hex>        Add orphan header\n"
      << "  getorphanstats               Get orphan header statistics\n"
      << "  evictorphans                 Force orphan header eviction\n"
      << std::endl;
}

int main(int argc, char *argv[]) {
  try {
    if (argc < 2) {
      PrintUsage(argv[0]);
      return 1;
    }

    // Parse options
    std::string datadir;
    std::string command;
    std::vector<std::string> params;

    for (int i = 1; i < argc; ++i) {
      std::string arg = argv[i];

      if (arg == "--help" || arg == "-h") {
        PrintUsage(argv[0]);
        return 0;
      } else if (arg == "--version" || arg == "-v") {
        std::cout << unicity::GetFullVersionString() << std::endl;
        std::cout << unicity::GetCopyrightString() << std::endl;
        return 0;
      } else if (arg.starts_with("--datadir=")) {
        datadir = arg.substr(10);
        if (datadir.empty()) {
          std::cerr << "Error: --datadir requires a non-empty path\n";
          return 1;
        }
      } else if (arg == "--regtest" || arg == "--testnet" || arg == "--mainnet") {
        // Network flags are accepted but ignored (datadir determines network)
        continue;
      } else if (command.empty()) {
        command = arg;
      } else {
        params.push_back(arg);
      }
    }

    // Get default datadir if not specified
    if (datadir.empty()) {
      std::filesystem::path datadir_path = unicity::util::get_default_datadir();
      if (datadir_path.empty()) {
        std::cerr << "Error: HOME environment variable not set.\n"
                  << "Cannot determine default data directory.\n"
                  << "Please set HOME or use --datadir explicitly.\n";
        return 1;
      }
      datadir = datadir_path.string();
    }

    if (command.empty()) {
      std::cerr << "Error: No command specified\n";
      PrintUsage(argv[0]);
      return 1;
    }

    // Connect to node via Unix socket
    // There is no network RPC port - all commands must be run locally
    std::string socket_path = datadir + "/node.sock";
    unicity::rpc::RPCClient client(socket_path);

    auto connect_error = client.Connect();
    if (connect_error) {
      std::cerr << "Error: " << *connect_error << "\n";
      // Only show the "make sure node is running" hint for connection errors,
      // not for path length or other errors
      if (connect_error->find("Cannot connect") != std::string::npos) {
        std::cerr << "Make sure the node is running.\n";
      }
      return 1;
    }

    // Execute command
    std::string response = client.ExecuteCommand(command, params);

    // Print response
    std::cout << response;

    // Check if response contains an error (simple JSON check)
    // RPC errors are returned as JSON with "error" field
    if (response.find("\"error\":") != std::string::npos) {
      return 1;  // Exit with error code if RPC returned error
    }

    return 0;

  } catch (const std::exception &e) {
    std::cerr << "Error: " << e.what() << std::endl;
    return 1;
  }
}
