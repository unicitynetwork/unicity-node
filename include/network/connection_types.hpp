// Copyright (c) 2025 The Unicity Foundation
// Connection types for peer-to-peer network connections

#pragma once

#include <string>

namespace unicity {
namespace network {

/**
 * Different types of connections to a peer.
 * This enum encapsulates the information we have available at the time of
 * opening or accepting the connection. Aside from INBOUND, all types are
 * initiated by us.
 */
enum class ConnectionType {
  /**
   * Inbound connections are those initiated by a peer. This is the only
   * property we know at the time of connection, until P2P messages are
   * exchanged.
   */
  INBOUND,

  /**
   * These are the default connections that we use to connect with the
   * network. We relay blocks (headers) and addresses.
   * We automatically attempt to open MAX_OUTBOUND_FULL_RELAY_CONNECTIONS
   * using addresses from our AddrMan.
   */
  OUTBOUND_FULL_RELAY,

  /**
   * Block-relay-only connections are outbound connections that do NOT
   * participate in address relay. They only relay blocks.
   *
   *
   * 2 block-relay-only connections in addition to 8 full-relay connections.
   *
   * These peers:
   * - Receive and relay blocks
   * - Do NOT send ADDR messages
   * - Do NOT process incoming ADDR messages
   * - Do NOT respond to GETADDR
   * - Are NOT added to AddrMan (keeps them invisible)
   */
  BLOCK_RELAY,

  /**
   * We open manual connections to addresses that users explicitly requested
   * via RPC or configuration options. Even if a manual connection is
   * misbehaving, we do not automatically disconnect or add it to our
   * discouragement filter.
   */
  MANUAL,

  /**
   * Feeler connections are short-lived connections made to check that a node
   * is alive. They can be useful for:
   * - test-before-evict: if one of the peers is considered for eviction from
   *   our AddrMan because another peer is mapped to the same slot in the
   *   tried table, evict only if this longer-known peer is offline.
   * - move node addresses from New to Tried table, so that we have more
   *   connectable addresses in our AddrMan.
   *
   * We make these connections approximately every FEELER_INTERVAL.
   */
  FEELER,
};

// Convert ConnectionType enum to a string value
std::string ConnectionTypeAsString(ConnectionType conn_type);

// Check if this connection type participates in address relay.
bool RelaysAddr(ConnectionType conn_type);

// Check if this is a full-relay outbound connection.
inline bool IsFullRelayConn(ConnectionType conn_type) {
  return conn_type == ConnectionType::OUTBOUND_FULL_RELAY;
}

// Check if this is a block-relay-only connection.
inline bool IsBlockRelayConn(ConnectionType conn_type) {
  return conn_type == ConnectionType::BLOCK_RELAY;
}

// Check if this is any type of outbound connection (full-relay, block-relay, manual, feeler).
inline bool IsOutboundConn(ConnectionType conn_type) {
  return conn_type != ConnectionType::INBOUND;
}

}  // namespace network
}  // namespace unicity
