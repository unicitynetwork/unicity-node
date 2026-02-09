# Unicity Network Protocol

**Version:** 1.0
**Last Updated:** 2026-01-12

## Overview

Unicity is a headers-only blockchain protocol. Nodes exchange block headers (100 bytes each) without transaction data. The protocol uses a Bitcoin like wire format with custom network identifiers.

## Network Parameters

| Parameter | Value |
|-----------|-------|
| Protocol Version | 1 |
| Mainnet Magic | 0x554E4943 ("UNIC") |
| Mainnet Port | 9590 |
| Max Message Size | 8 MB |
| Max Headers per Message | 80000 |

## Message Format

All messages use a 24-byte header followed by a variable-length payload.

### Message Header (24 bytes)

| Field | Size | Type | Description |
|-------|------|------|-------------|
| magic | 4 | uint32_t | Network identifier (little-endian) |
| command | 12 | char[] | Command name, null-padded |
| length | 4 | uint32_t | Payload size in bytes (little-endian) |
| checksum | 4 | uint8_t[] | First 4 bytes of SHA256(SHA256(payload)) |

## Data Types

### Basic Types

All integers use little-endian byte order except where noted.

| Type | Size | Description |
|------|------|-------------|
| uint8_t | 1 byte | Unsigned 8-bit integer |
| uint16_t | 2 bytes | Unsigned 16-bit integer (LE) |
| uint32_t | 4 bytes | Unsigned 32-bit integer (LE) |
| uint64_t | 8 bytes | Unsigned 64-bit integer (LE) |
| int32_t | 4 bytes | Signed 32-bit integer (LE) |
| int64_t | 8 bytes | Signed 64-bit integer (LE) |

### Variable Integer (VarInt)

| Value Range | Format | Total Size |
|-------------|--------|------------|
| 0 - 252 | value | 1 byte |
| 253 - 65535 | 0xFD + uint16_t | 3 bytes |
| 65536 - 4294967295 | 0xFE + uint32_t | 5 bytes |
| 4294967296+ | 0xFF + uint64_t | 9 bytes |

### Network Address (26 bytes)

| Field | Size | Type | Description |
|-------|------|------|-------------|
| services | 8 | uint64_t | Service flags (LE) |
| ip | 16 | uint8_t[] | IPv6 address (IPv4-mapped: ::ffff:x.x.x.x) |
| port | 2 | uint16_t | Port number (big-endian) |

### Timestamped Address (30 bytes)

| Field | Size | Type | Description |
|-------|------|------|-------------|
| timestamp | 4 | uint32_t | Unix timestamp (LE) |
| address | 26 | NetworkAddress | Network address |



### Block Header (100 bytes)

| Field | Size | Type | Description |
|-------|------|------|-------------|
| nVersion | 4 | int32_t | Block version |
| hashPrevBlock | 32 | uint256 | Previous block hash |
| minerAddress | 20 | uint160 | Miner address |
| nTime | 4 | uint32_t | Timestamp |
| nBits | 4 | uint32_t | Difficulty target |
| nNonce | 4 | uint32_t | Nonce |
| hashRandomX | 32 | uint256 | RandomX hash |

## Messages

### VERSION

Initiates connection handshake.

| Field | Type | Description |
|-------|------|-------------|
| version | int32_t | Protocol version (1) |
| services | uint64_t | Service flags (0x01 = NODE_NETWORK) |
| timestamp | int64_t | Current Unix timestamp |
| addr_recv | NetworkAddress | Receiver's address |
| addr_from | NetworkAddress | Sender's address |
| nonce | uint64_t | Random nonce for self-connection detection |
| user_agent | VarString | Client identification string |
| start_height | int32_t | Current blockchain height |

### VERACK

Acknowledges VERSION message. Empty payload.

### PING

Keep-alive check.

| Field | Type | Description |
|-------|------|-------------|
| nonce | uint64_t | Random nonce |

### PONG

Response to PING.

| Field | Type | Description |
|-------|------|-------------|
| nonce | uint64_t | Nonce from PING message |

### ADDR

Share peer addresses.

| Field | Type | Description |
|-------|------|-------------|
| count | VarInt | Number of addresses (max 1000) |
| addresses | TimestampedAddress[] | Address list |

### GETADDR

Request peer addresses. Empty payload.



### GETHEADERS

Request block headers.

| Field | Type | Description |
|-------|------|-------------|
| version | uint32_t | Protocol version |
| count | VarInt | Number of locator hashes (max 101) |
| block_locator | uint256[] | Block locator hashes |
| hash_stop | uint256 | Stop hash (zero = get maximum) |

### HEADERS

Send block headers.

| Field | Type | Description |
|-------|------|-------------|
| count | VarInt | Number of headers (max 80000) |
| headers | BlockHeader[] | Block headers |

## Protocol Flows

### Connection Handshake

```
Node A                  Node B
  |                        |
  |------ VERSION -------->|
  |<----- VERSION ---------|
  |------ VERACK --------->|
  |<----- VERACK ----------|
  |                        |
  [Connection Ready]
```

### Header Synchronization

```
Syncing Node           Synced Node
  |                        |
  |---- GETHEADERS ------->|
  |<---- HEADERS ----------|
  |                        |
  [Repeat until synced]
```

### New Block Announcement

```
Node A                  Node B
  |                        |
  |<----- HEADERS ---------|
  |                        |
```

### Peer Discovery

```
Node A                  Node B
  |                        |
  |------ GETADDR -------->|
  |<----- ADDR ------------|
  |                        |
```

## Timeouts

| Event | Timeout | Action |
|-------|---------|--------|
| Handshake | 60 seconds | Disconnect if not complete |
| Ping interval | 120 seconds | Send PING |
| Ping timeout | 1200 seconds | Disconnect if no PONG |
| Inactivity | 1200 seconds | Disconnect if no messages |

## Service Flags

| Flag | Value | Description |
|------|-------|-------------|
| NODE_NONE | 0x00 | No services |
| NODE_NETWORK | 0x01 | Can serve block headers |

## Limits

| Limit | Value |
|-------|-------|
| Max Protocol Message | 8 MB |
| Max Block Locator Size | 101 |

| Max Headers per Message | 80000 |
| Max Addresses per Message | 1000 |
| Max User Agent Length | 256 bytes |

## Connection Limits

| Type | Default |
|------|---------|
| Outbound Connections | 10 |
| Inbound Connections | 125 |
