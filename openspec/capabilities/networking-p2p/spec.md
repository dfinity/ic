# Networking: P2P Capability Specification

**Source narrative**: `openspec/specs/networking/p2p.md`
**Crates**: `ic-quic-transport`, `ic-consensus-manager`, `ic-peer-manager`, `ic-artifact-manager`, `ic-artifact-downloader`
**Key files**: `rs/p2p/`, `rs/consensus_manager/`

---

## REQ-P2P-001: QUIC Transport Layer

The P2P layer MUST use QUIC as its transport protocol with encrypted, multiplexed connections.

### SCENARIO-P2P-001: RPC to connected peer
**Given** an RPC request is sent to a connected peer via `Transport::rpc`
**When** the RPC executes
**Then** a new bidirectional QUIC substream is opened
**And** the request is serialized as protobuf `HttpRequest` and written to the send stream
**And** the response is read from the receive stream and deserialized
**And** the response is returned to the caller

### SCENARIO-P2P-002: RPC to disconnected peer
**Given** an RPC request is sent to a peer not in the connection map
**When** the RPC executes
**Then** a `P2PError` is returned with message "Currently not connected to this peer"

### SCENARIO-P2P-003: Message size limit
**Given** a message larger than 128 MB (`MAX_MESSAGE_SIZE_BYTES`) is received on a stream
**When** the read executes
**Then** the read operation fails and the stream is closed

### SCENARIO-P2P-004: Message priority support
**Given** a request includes a `MessagePriority::High` extension
**When** the request is transmitted
**Then** the QUIC stream priority is set to 1 (higher than Low=0)

### SCENARIO-P2P-005: Stream cancellation on drop
**Given** a QUIC send stream wrapped in `ResetStreamOnDrop` is dropped before finishing
**When** the stream is dropped
**Then** a QUIC RESET frame with code `0x80000006` is sent to the peer
**And** the ongoing streams metric gauge is decremented

---

## REQ-P2P-002: Connection Management

The connection manager MUST maintain persistent authenticated connections to all subnet peers.

### SCENARIO-P2P-006: Topology-driven connection establishment
**Given** the subnet topology changes
**When** the connection manager processes the change
**Then** connections are initiated to new peers
**And** connections to peers no longer in the topology are closed
**And** the TLS server config is updated to only accept current subnet members

### SCENARIO-P2P-007: Designated dialer protocol
**Given** two peers need to establish a connection
**When** the dialer is determined
**Then** the peer with the lower `NodeId` is the designated dialer
**And** an inbound connection from a peer with a higher NodeId than this node is rejected with `InvalidIncomingPeerId`

### SCENARIO-P2P-008: TLS mutual authentication
**Given** a connection is being established
**When** TLS handshake runs
**Then** node certificates from the registry are used
**And** the server only accepts connections from current subnet topology nodes
**And** the `NodeId` is extracted from the peer's TLS certificate

### SCENARIO-P2P-009: Connection failure and retry
**Given** an outbound connection attempt fails
**When** the failure is handled
**Then** the peer is re-added to the connect queue with a 5-second backoff (`CONNECT_RETRY_BACKOFF`)

### SCENARIO-P2P-010: Connection timeout
**Given** a connection establishment takes longer than 10 seconds (`CONNECT_TIMEOUT`)
**When** the timeout fires
**Then** the connection attempt is aborted and retried after the backoff period

### SCENARIO-P2P-011: Idle timeout and keep-alive
**Given** a QUIC connection is idle
**When** idle time exceeds thresholds
**Then** keep-alive probes are sent every 1 second (`KEEP_ALIVE_INTERVAL`)
**And** if no response within 5 seconds (`IDLE_TIMEOUT`), the connection is marked as broken

---

## REQ-P2P-003: Consensus Manager Broadcasting

The consensus manager MUST broadcast artifacts within a subnet using a slot-based protocol.

### SCENARIO-P2P-012: Small artifact push
**Given** an artifact's protobuf-encoded size is < 1024 bytes or it is latency-sensitive
**When** the artifact is broadcast
**Then** the full artifact is included in the slot update message
**And** peers do not need to make a separate download request

### SCENARIO-P2P-013: Large artifact advert
**Given** an artifact's size is ≥ 1024 bytes and it is not latency-sensitive
**When** the artifact is broadcast
**Then** only the artifact ID is sent in the slot update
**And** the receiving peer must separately download the full artifact

### SCENARIO-P2P-014: Artifact abort (purge)
**Given** an `ArtifactTransmit::Abort` is received for an artifact ID
**When** the abort is processed
**Then** the transmission task for that artifact is cancelled
**And** the slot is returned to the available slot set for reuse

### SCENARIO-P2P-015: Retry on peer send failure
**Given** sending a slot update to a peer fails
**When** the failure is handled
**Then** the send is retried with exponential backoff (250ms to 60s)

### SCENARIO-P2P-016: Resend on peer reconnection
**Given** a peer reconnects with a new connection ID
**When** reconnection is detected
**Then** all active slot updates are re-sent to that peer
**And** the previous transmission task to that peer is cancelled

---

## REQ-P2P-004: Consensus Manager Receiver

The receiver MUST process incoming slot updates and deliver full artifacts to the local unvalidated pool.

### SCENARIO-P2P-017: Receive slot update with full artifact
**Given** a slot update containing a full artifact is received from a peer
**When** the update is processed
**Then** the artifact is assembled and delivered to the inbound channel as `UnvalidatedArtifactMutation::Insert`

### SCENARIO-P2P-018: Topology change cleanup
**Given** a peer leaves the subnet topology
**When** cleanup runs
**Then** all slot data from that peer is purged
**And** in-progress download tasks for artifacts only held by that peer are cancelled

---

## REQ-P2P-005: Peer Manager

The peer manager MUST periodically publish subnet topology updates from the registry.

### SCENARIO-P2P-019: Periodic topology update
**Given** the peer manager runs its update interval (every 3 seconds)
**When** the update runs
**Then** it queries the registry for subnet membership
**And** publishes the updated `SubnetTopology` to the watch channel

### SCENARIO-P2P-020: Topology unchanged optimization
**Given** the computed topology is identical to the currently published topology
**When** the update is checked
**Then** no update is sent to watchers (using `send_if_modified`)

---

## REQ-P2P-006: State Sync Manager

The state sync manager MUST handle downloading replicated state from peers using a chunk-based protocol.

### SCENARIO-P2P-021: Starting a new state sync
**Given** a state advert is received and `maybe_start_state_sync` returns a `Chunkable`
**When** the sync is started
**Then** an ongoing state sync is started for that state height
**And** the advertising peer is added as a source for chunks

### SCENARIO-P2P-022: Single active state sync
**Given** a state sync is already in progress
**When** a new advert arrives for a different state ID
**Then** the new sync is not started
**And** adverts for the same state ID add new peers to the ongoing sync

---

## Traceability

| ID | Description | Status | Tests |
|----|-------------|--------|-------|
| REQ-P2P-001 | QUIC transport | narrative | rs/p2p/tests/ |
| REQ-P2P-002 | Connection management | narrative | rs/p2p/tests/ |
| REQ-P2P-003 | Consensus manager broadcast | narrative | rs/consensus_manager/ |
| REQ-P2P-004 | Consensus manager receiver | narrative | rs/consensus_manager/ |
| REQ-P2P-005 | Peer manager | narrative | rs/p2p/tests/ |
| REQ-P2P-006 | State sync manager | narrative | rs/p2p/tests/ |
