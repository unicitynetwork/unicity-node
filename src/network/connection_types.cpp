// Copyright (c) 2025 The Unicity Foundation
// Connection types implementation

#include "network/connection_types.hpp"

namespace unicity {
namespace network {

std::string ConnectionTypeAsString(ConnectionType conn_type) {
  switch (conn_type) {
  case ConnectionType::INBOUND:
    return "inbound";
  case ConnectionType::OUTBOUND_FULL_RELAY:
    return "outbound-full-relay";
  case ConnectionType::BLOCK_RELAY:
    return "block-relay-only";
  case ConnectionType::MANUAL:
    return "manual";
  case ConnectionType::FEELER:
    return "feeler";
  default:
    return "unknown";
  }
}

bool RelaysAddr(ConnectionType conn_type) {
  switch (conn_type) {
  case ConnectionType::OUTBOUND_FULL_RELAY:
  case ConnectionType::INBOUND:
  case ConnectionType::MANUAL:
    return true;
  case ConnectionType::BLOCK_RELAY:
  case ConnectionType::FEELER:
    return false;
  default:
    return false;
  }
}

}  // namespace network
}  // namespace unicity
