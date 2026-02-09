# Unicity Architecture

**Version:** 1.0
**Last Updated:** 2026-01-12

## Overview

Unicity is a headers-only blockchain that implements Bitcoin-compatible P2P networking with RandomX proof-of-work and ASERT difficulty adjustment. The architecture emphasizes simplicity through separation of concerns, thread safety through single-threaded design, and correctness through careful resource management.

### Core Characteristics

- **Headers-Only**: No transactions, no UTXO set, no mempool
- **100-byte Headers**: Extended from Bitcoin's 80 bytes for RandomX PoW
- **RandomX PoW**: ASIC-resistant proof-of-work
- **ASERT Difficulty**: Per-block difficulty adjustment

## System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Application                            │
│  • RPC Server                                               │
│  • Mining (optional)                                        │
│  • Periodic Tasks                                           │
└─────────────────────────────────────────────────────────────┘
                           │
         ┌─────────────────┼─────────────────┐
         ▼                 ▼                 ▼
┌──────────────────┐ ┌──────────────┐ ┌──────────────┐
│ NetworkManager   │ │Chainstate    │ │ Utilities    │
│                  │ │Manager       │ │              │
└──────────────────┘ └──────────────┘ └──────────────┘
         │                 │                 │
         ▼                 ▼                 ▼
   P2P Network        Blockchain        Time, Logging
     Protocol           Validation      Thread Pools
```

---

## Chain Architecture

### Component Overview

The chain layer validates block headers and maintains the blockchain state:

```
┌───────────────────────────────────────────────────────────────────┐
│                        ChainstateManager                          │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │                      Public Interface                       │  │
│  │  • AcceptBlockHeader()      • ActivateBestChain()           │  │
│  │  • ProcessNewBlockHeader()  • InvalidateBlock()             │  │
│  │  • GetTip()                 • IsInitialBlockDownload()      │  │
│  └─────────────────────────────────────────────────────────────┘  │
│                               ▼                                   │
│  ┌──────────────────┐ ┌────────────────────┐ ┌──────────────┐     │
│  │  BlockManager    │ │ ActiveTipCandidates│ │ Orphan Pool  │     │
│  │                  │ │                    │ │              │     │
│  │ • Block storage  │ │ • Candidate tips   │ │ • DoS limits │     │
│  │ • Active chain   │ │ • Best chain       │ │              │     │
│  │ • Persistence    │ │ • Pruning          │ │              │     │
│  └──────────────────┘ └────────────────────┘ └──────────────┘     │
│                               ▼                                   │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │                     Validation Layer                        │  │
│  │  ┌───────────────┐ ┌───────────────┐ ┌───────────────────┐  │  │
│  │  │ CheckBlock    │ │ Contextual    │ │ GetNextWork       │  │  │
│  │  │ Header        │ │ Check         │ │ Required (ASERT)  │  │  │
│  │  └───────────────┘ └───────────────┘ └───────────────────┘  │  │
│  └─────────────────────────────────────────────────────────────┘  │
│                               ▼                                   │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │                   Consensus Layer (PoW)                     │  │
│  │  ┌───────────────────────────────────────────────────────┐  │  │
│  │  │                CheckProofOfWork()                     │  │  │
│  │  │  ┌───────────────────┐  ┌───────────────────────┐     │  │  │
│  │  │  │  COMMITMENT_ONLY  │  │   FULL (RandomX)      │     │  │  │
│  │  │  │  (~1ms, DoS)      │  │   (~50ms, cache)      │     │  │  │
│  │  │  └───────────────────┘  └───────────────────────┘     │  │  │
│  │  └───────────────────────────────────────────────────────┘  │  │
│  └─────────────────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────────────┘
```

### Data Structures

#### Block Header (100 bytes)

The fundamental unit of the blockchain:

| Field | Size | Description |
|-------|------|-------------|
| nVersion | 4 bytes | Block version |
| hashPrevBlock | 32 bytes | Previous block hash |
| minerAddress | 20 bytes | Miner reward address (replaces merkleRoot) |
| nTime | 4 bytes | Unix timestamp |
| nBits | 4 bytes | Difficulty target (compact format) |
| nNonce | 4 bytes | PoW nonce |
| hashRandomX | 32 bytes | RandomX hash (PoW commitment) |


#### Block Index

In-memory metadata for each known block:

- **Validation State**: Flags indicating validation status
- **Chain Position**: Height and cumulative proof-of-work
- **Parent Pointer**: Links to parent block
- **Header Fields**: Stored inline for quick access

#### Active Chain

Linear view from genesis to current tip:

- Stored as vector of block pointers
- O(1) lookup by height
- Rebuilt on reorganizations

### Validation Pipeline

Three-layer validation ensures security while maintaining performance:

```
┌───────────────────────────────────────────────────────────┐
│                  LAYER 1: Pre-Filtering                   │
│              (Fast DoS Protection - ~1ms)                 │
├───────────────────────────────────────────────────────────┤
│  CheckProofOfWork(COMMITMENT_ONLY)                        │
│  • Validates: hashRandomX commitment meets nBits          │
│  • Purpose: Reject invalid headers before expensive PoW   │
└───────────────────────────────────────────────────────────┘
                          ↓ PASSED
┌───────────────────────────────────────────────────────────┐
│             LAYER 2: Context-Free Validation              │
│             (Full PoW Verification - ~50ms)               │
├───────────────────────────────────────────────────────────┤
│  CheckBlockHeader()                                       │
│  • Validates: Full RandomX hash matches hashRandomX       │
│  • Purpose: Cryptographic PoW verification                │
└───────────────────────────────────────────────────────────┘
                          ↓ PASSED
┌───────────────────────────────────────────────────────────┐
│             LAYER 3: Contextual Validation                │
│              (Consensus Rules - ~5ms)                     │
├───────────────────────────────────────────────────────────┤
│  ContextualCheckBlockHeader()                             │
│  • Validates:                                             │
│    - nBits matches ASERT difficulty                       │
│    - Timestamp > previous block (mainnet/testnet)         │
│    - Timestamp < now + 10 minutes                         │
│    - Version >= 1                                         │
└───────────────────────────────────────────────────────────┘
                          ↓ PASSED
                   ✓ Block Accepted
```

### Chain Reorganization

When a competing fork has more accumulated proof-of-work:

```
Before Reorg:
    Genesis → A1 → A2 → A3 → A4* (active tip)
                 ↘ B2 → B3 → B4 → B5 (candidate, more work)

Fork Point: A1
Disconnect: [A4, A3, A2]
Connect:    [B2, B3, B4, B5]

After Reorg:
    Genesis → A1 → B2 → B3 → B4 → B5* (active tip)
                 ↘ A2 → A3 → A4 (orphaned fork)
```

**Process**:
1. Find common ancestor (fork point)
2. Disconnect blocks from old chain back to fork point
3. Connect blocks from new chain forward from fork point
4. Update active chain tip
5. Emit notifications to application

### Consensus Mechanisms

#### RandomX Proof-of-Work

- **Memory-hard**: Requires ~2GB dataset per epoch
- **Epoch-based**: Dataset changes periodically
- **Two-phase verification**: Fast commitment check, then full RandomX

#### ASERT Difficulty Adjustment

Formula: `target_new = target_ref * 2^((time_diff - ideal_time) / half_life)`

- **Per-block adjustment**: Difficulty updates every block
- **Exponential response**: Based on actual vs. ideal block times
- **Anchor system**: References a fixed anchor block for calculations
- **Parameters**:
  - Target spacing: 2.4 hours (8640 seconds)
  - Half-life: 48 hours (difficulty doubles/halves over this period)

#### Timestamp Rules

Prevents timestamp manipulation:
- **Mainnet/Testnet**: Strictly increasing (timestamp > previous block)
- **Regtest**: Median Time Past (timestamp > median of last 11 blocks)
- Future limit: timestamp < now + 10 minutes
- Ensures monotonic time progression

---

## Network Architecture

### Component Overview

The network layer manages P2P connections and blockchain synchronization:

```
┌─────────────────────────────────────────────────────────────┐
│                     NetworkManager                          │
│  (Coordinator, io_context owner, message routing)           │
└─────────────────────────────────────────────────────────────┘
                           │
         ┌─────────────────┼──────────────────────────────────┐
         ▼                 ▼                                  ▼
┌────────────────┐ ┌──────────────┐ ┌──────────────┐ ┌─────────────────┐
│Connection      │ │   AddrRelay  │ │  HeaderSync  │ │    Helpers      │
│   Manager      │ │    Manager   │ │   Manager    │ │ (Ban, Evict,    │
│                │ │              │ │              │ │  Misbehavior)   │
└────────────────┘ └──────────────┘ └──────────────┘ └─────────────────┘
         │                 │                 │                 │
         ▼                 ▼                 ▼                 ▼
  ┌──────────┐    ┌──────────────┐  ┌──────────────┐    ┌───────────┐
  │Peer State│    │AddressManager│  │Sync State    │    │Ban Tables │
  │          │    │AnchorManager │  │              │    │           │
  └──────────┘    └──────────────┘  └──────────────┘    └───────────┘
```

### Network Manager

**Responsibilities**:
- Owns the reactor (boost::asio::io_context)
- Routes messages to appropriate managers
- Coordinates lifecycle (start/stop)
- Manages periodic tasks (connection attempts, maintenance, feelers)
- Prevents self-connections

**Threading Model**:
- Single-threaded reactor pattern
- All handlers serialized by event loop
- No locks needed for network state
- Application layer (validation, mining) runs on separate threads

### Connection Manager

**Responsibilities**:
- Connection state machine management
- Inbound connection acceptance
- Outbound connection initiation
- VERSION/VERACK handshake
- Connection limits and eviction
- Ban/discourage enforcement

**Connection States**:
```
DISCONNECTED → CONNECTING → CONNECTED → VERSION_SENT → READY
                   ↓            ↓            ↓           ↓
              [Timeout]    [Rejected]   [Invalid]  [Running]
                   ↓            ↓            ↓           ↓
              DISCONNECTED DISCONNECTED DISCONNECTED READY
```

### Address Relay Manager

**Responsibilities**:
- Address discovery and storage
- Peer address selection
- ADDR/GETADDR message handling
- Anchor connections (eclipse attack resistance)

**Components**:
- **AddressManager**: Bitcoin Core's tried/new table algorithm
- **AnchorManager**: Persists 2 block-relay anchors across restarts

**Address Selection**:
- Tried table: Addresses we've successfully connected to
- New table: Unverified addresses from peers
- Collision-resistant selection algorithm
- Exponential backoff on failures

### Header Sync Manager

**Responsibilities**:
- Initial Block Download (IBD) coordination
- Header synchronization via GETHEADERS/HEADERS
- Block announcement via direct HEADERS (no INV/GETDATA needed for headers-only)
- Sync peer selection and rotation

**Components**:
- **HeaderSyncManager**: GETHEADERS/HEADERS protocol

**Sync Strategy**:
- Single sync peer during IBD (prevents resource exhaustion)
- Parallel header requests after IBD
- Stall detection with 120-second timeout
- Automatic sync peer rotation on stall

### Message Flow

#### Inbound Messages

```
Network Socket
      │
      ▼
Transport Layer
      │
      ▼
Peer::on_message_received()
      │
      ▼
NetworkManager::handle_message()
      │
      ├─► Check running flag
      ├─► VERSION: Check nonce collision
      │
      ▼
MessageDispatcher
      │
      └─► Route to appropriate manager:
          ├─► VERACK      → ConnectionManager
          ├─► ADDR        → AddrRelayManager
          ├─► GETADDR     → AddrRelayManager
          ├─► HEADERS     → HeaderSyncManager
          └─► PING/PONG   → ConnectionManager
```

#### Outbound Messages

```
Manager
  │
  ▼
Peer::send_message()
  │
  ▼
Transport Layer
  │
  ▼
Network Socket
```

### Connection Lifecycle

#### Outbound Connection

1. Select address from AddressManager
2. Check: not banned, not already connected, slots available
3. Initiate TCP connection
4. Send VERSION message
5. Receive VERSION from peer
6. Send VERACK
7. Receive VERACK
8. Connection ready - begin protocol operations

#### Inbound Connection

1. Accept TCP connection
2. Check: not banned, slots available, rate limits
3. Wait for VERSION from peer
4. Send VERSION
5. Receive VERACK
6. Send VERACK
7. Connection ready - begin protocol operations

### Reactor Pattern

Single-threaded event loop processes:

- **Socket Events**: Readable, writable, connected, disconnected
- **Timers**: Connection attempts, maintenance, feelers, message batching
- **Application Requests**: From validation, mining, RPC threads

---

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

### Initial Block Download

```
Syncing Node           Synced Node
  |                        |
  |---- GETHEADERS ------->|
  |<---- HEADERS ----------|
  |                        |
  |---- GETHEADERS ------->|
  |<---- HEADERS ----------|
  |                        |
  [Repeat until synced]
```

### New Block Announcement

```
Mining Node            Peer Node
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

### Chain Reorganization

```
Time →

Block Arrives:
  AcceptBlockHeader() → Add to BlockIndex
           ↓
  TryAddCandidate() → Add to candidate set
           ↓
  ActivateBestChain() → Compare accumulated work
           ↓
  [If new chain has more work]
           ↓
  FindForkPoint() → Locate common ancestor
           ↓
  DisconnectBlocks() → Remove old tip blocks
           ↓
  ConnectBlocks() → Add new chain blocks
           ↓
  UpdateTip() → Set new active chain
           ↓
  NotifyChainTip() → Inform application
```

---

## Key Design Decisions

### Separation of Concerns

**Chain Layer**:
- BlockManager: Owns all block data
- ActiveTipCandidates: Tracks candidate chain tips
- ChainstateManager: Coordinates validation

**Network Layer**:
- ConnectionManager: Connection management & lifecycle
- AddrRelayManager: Address discovery & storage
- HeaderSyncManager: Synchronization logic


### Thread Safety

**Chain Layer**: Single coarse-grained mutex
- Simple locking model
- Prevents data races
- May become bottleneck at high throughput

**Network Layer**: Single-threaded reactor
- No locks needed for network state
- Handlers serialized by event loop
- Application threads interact via thread-safe interfaces

### DoS Protection

**Fast Rejection**:
- Commitment-only PoW check (~1ms) before expensive validation
- Message size limits (8 MB maximum)
- Orphan header limits (1000 total, 50 per peer)

**Resource Limits**:
- Connection limits (10 outbound, 125 inbound)
- Ban/discourage for misbehaving peers
- Stall detection with timeouts

### Eclipse Attack Resistance

**Address Diversity**:
- Tried/new table separation
- Feeler connections test random addresses
- Exponential backoff on failures

**Anchor Connections**:
- 2 block-relay-only peers saved across restarts
- Prevents attacker from monopolizing connections
- Reconnect to anchors on startup

### Headers-Only Simplification

By eliminating transactions:
- No UTXO set management
- No mempool
- No transaction validation
- No block size limits
- 99% reduction in complexity vs. Bitcoin

Headers carry all consensus-critical information:
- Proof-of-work (RandomX hash)
- Chain linkage (previous block hash)
- Timing (timestamp, difficulty)
- Reward recipient (miner address)

---

