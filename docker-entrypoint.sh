#!/bin/bash
set -e

# Unicity Docker Entrypoint Script
# Provides flexible configuration and initialization

# Data directory
DATADIR="${DATADIR:-/home/unicity/.unicity}"

# Default settings (can be overridden via environment variables)
PORT="${UNICITY_PORT:-9590}"
LISTEN="${UNICITY_LISTEN:-1}"
SERVER="${UNICITY_SERVER:-0}"
VERBOSE="${UNICITY_VERBOSE:-0}"
NETWORK="${UNICITY_NETWORK:-mainnet}"
LOGLEVEL="${UNICITY_LOGLEVEL:-}"
DEBUG="${UNICITY_DEBUG:-}"

# Ensure data directory exists
mkdir -p "$DATADIR"

# Build command-line arguments
ARGS=()
ARGS+=("--datadir=$DATADIR")

# Network selection
case "$NETWORK" in
  testnet)
    ARGS+=("--testnet")
    # If UNICITY_PORT is explicitly set, use it; otherwise use default
    if [ -n "$UNICITY_PORT" ]; then
      PORT="$UNICITY_PORT"
    else
      PORT="19590"
    fi
    ;;
  regtest)
    ARGS+=("--regtest")
    # If UNICITY_PORT is explicitly set, use it; otherwise use default
    if [ -n "$UNICITY_PORT" ]; then
      PORT="$UNICITY_PORT"
    else
      PORT="29590"
    fi
    ;;
  mainnet|*)
    # Default is mainnet, no flag needed
    # If UNICITY_PORT is explicitly set, use it; otherwise use default
    if [ -n "$UNICITY_PORT" ]; then
      PORT="$UNICITY_PORT"
    else
      PORT="9590"
    fi
    ;;
esac

# Port configuration
if [ -n "$PORT" ]; then
  ARGS+=("--port=$PORT")
fi

# Listen configuration
if [ "$LISTEN" = "0" ]; then
  ARGS+=("--nolisten")
fi

# Note: RPC server is always enabled, no --server flag needed

# Verbose logging
if [ "$VERBOSE" = "1" ]; then
  ARGS+=("--verbose")
fi

# Log level configuration (trace, debug, info, warn, error, critical)
# Examples: UNICITY_LOGLEVEL=trace or UNICITY_LOGLEVEL=debug
if [ -n "$LOGLEVEL" ]; then
  ARGS+=("--loglevel=$LOGLEVEL")
fi

# Component-specific debug logging
# Examples: UNICITY_DEBUG=chain or UNICITY_DEBUG=chain,network
# Special: UNICITY_DEBUG=all enables TRACE for all components
if [ -n "$DEBUG" ]; then
  ARGS+=("--debug=$DEBUG")
fi

# Add any additional arguments passed to the container
ARGS+=("$@")

# Display configuration
echo "========================================="
echo "Unicity Node Starting"
echo "========================================="
echo "Network:    $NETWORK"
echo "Data Dir:   $DATADIR"
echo "Port:       $PORT"
echo "Listen:     $LISTEN"
echo "Server:     $SERVER"
echo "Verbose:    $VERBOSE"
if [ -n "$LOGLEVEL" ]; then
  echo "Log Level:  $LOGLEVEL"
fi
if [ -n "$DEBUG" ]; then
  echo "Debug:      $DEBUG"
fi
echo "========================================="
echo "Command: unicityd ${ARGS[*]}"
echo "========================================="

# Execute the node
exec unicityd "${ARGS[@]}"
