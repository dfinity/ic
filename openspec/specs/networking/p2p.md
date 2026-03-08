# P2P (Peer-to-Peer) Networking

**Crates**: `ic-artifact-downloader`, `ic-artifact-manager`, `ic-consensus-manager`, `ic-peer-manager`, `ic-quic-transport`, `ic-memory-transport`, `ic-networking-subnet-update-workload`

## Requirements

### Requirement: QUIC Transport Layer

The P2P layer uses QUIC as its transport protocol, providing encrypted, multiplexed connections between subnet peers. Each RPC occurs on a separate bidirectional QUIC substream, fully decoupled from other RPCs.

#### Scenario: Transport startup and topology binding
- **WHEN** a `QuicTransport` is started with a topology watcher, TLS config, registry client, and Axum router
- **THEN** a connection manager begins monitoring the topology for peer changes
- **AND** connections are established to peers listed in the `SubnetTopology`

#### Scenario: RPC to connected peer
- **WHEN** an RPC request is sent to a connected peer via `Transport::rpc`
- **THEN** a new bidirectional QUIC substream is opened
- **AND** the request is serialized as a protobuf `HttpRequest` and written to the send stream
- **AND** the response is read from the receive stream and deserialized from protobuf `HttpResponse`
- **AND** the response is returned to the caller

#### Scenario: RPC to disconnected peer
- **WHEN** an RPC request is sent to a peer not currently in the connection map
- **THEN** a `P2PError` is returned with message "Currently not connected to this peer"

#### Scenario: Listing connected peers
- **WHEN** `Transport::peers()` is called
- **THEN** a list of `(NodeId, ConnId)` tuples is returned for all currently connected peers
- **AND** each `ConnId` is a monotonically increasing unique identifier per connection

#### Scenario: Graceful shutdown
- **WHEN** `QuicTransport::shutdown()` is called
- **THEN** the cancellation token is triggered
- **AND** all active tasks are awaited via the task tracker
- **AND** the join handle is awaited for completion

#### Scenario: Stream cancellation on drop
- **WHEN** a QUIC send stream wrapped in `ResetStreamOnDrop` is dropped before finishing
- **THEN** a QUIC RESET frame with code `0x80000006` is sent to the peer
- **AND** the ongoing streams metric gauge is decremented

#### Scenario: Stream finished before drop
- **WHEN** a QUIC send stream is explicitly finished and stopped before the `ResetStreamOnDrop` guard is dropped
- **THEN** the peer receives the complete message data
- **AND** the ongoing streams metric gauge is decremented on drop

#### Scenario: Message size limit
- **WHEN** a message larger than 128 MB (`MAX_MESSAGE_SIZE_BYTES`) is received on a stream
- **THEN** the read operation fails with an error
- **AND** the stream is closed

#### Scenario: Message priority support
- **WHEN** a request includes a `MessagePriority::High` extension
- **THEN** the QUIC stream priority is set to 1
- **AND** the message is transmitted with higher priority than `Low` (priority 0) messages

### Requirement: Connection Management

The connection manager maintains persistent connections to all subnet peers, using TLS for mutual authentication and automatic reconnection on failure.

#### Scenario: Topology-driven connection establishment
- **WHEN** the subnet topology changes (detected via the topology watcher)
- **THEN** the connection manager initiates connections to new peers
- **AND** closes connections to peers no longer in the topology
- **AND** the TLS server config is updated to only accept connections from current subnet members

#### Scenario: Designated dialer protocol
- **WHEN** two peers need to establish a connection
- **THEN** the peer with the lower `NodeId` is the designated dialer (initiates the outbound connection)
- **AND** the peer with the higher `NodeId` waits for the inbound connection
- **AND** an inbound connection attempt from a peer with a higher NodeId than this node is rejected with `InvalidIncomingPeerId`

#### Scenario: Dialing prerequisites
- **WHEN** the connection manager evaluates whether to dial a peer
- **THEN** it proceeds only if this node is the designated dialer
- **AND** the peer is in the current subnet topology
- **AND** this node is in the current subnet topology
- **AND** there is no outstanding outbound connection attempt to that peer
- **AND** there is no active connection to that peer

#### Scenario: TLS mutual authentication
- **WHEN** a connection is being established
- **THEN** TLS is used with node certificates from the registry
- **AND** the server only accepts connections from nodes in the current subnet topology
- **AND** the client verifies the specific peer identity during connection
- **AND** the `NodeId` is extracted from the peer's TLS certificate

#### Scenario: Connection failure and retry
- **WHEN** an outbound connection attempt fails
- **THEN** the peer is re-added to the connect queue with a 5-second backoff (`CONNECT_RETRY_BACKOFF`)
- **AND** the `connection_results_total` metric is incremented with the "failed" label

#### Scenario: Connection timeout
- **WHEN** a connection establishment takes longer than 10 seconds (`CONNECT_TIMEOUT`)
- **THEN** the connection attempt is aborted with a `Timeout` error
- **AND** the connection is retried after the backoff period

#### Scenario: Idle timeout and keep-alive
- **WHEN** a QUIC connection is idle for more than 1 second
- **THEN** a keep-alive probe is sent every 1 second (`KEEP_ALIVE_INTERVAL`)
- **AND** if no response is received within 5 seconds (`IDLE_TIMEOUT`), the connection is marked as broken

#### Scenario: Active connection replacement
- **WHEN** a new connection is established to a peer that already has an active connection
- **THEN** the old connection is closed with reason "using newer connection"
- **AND** the new connection replaces the old one in the peer map

#### Scenario: Graceful endpoint shutdown
- **WHEN** the connection manager is shut down
- **THEN** the peer map is cleared
- **AND** the endpoint is closed with reason "graceful shutdown of endpoint"
- **AND** the connect queue is cleared
- **AND** all connecting and active connection tasks are shut down
- **AND** the endpoint waits until idle

### Requirement: Request Handling

Incoming requests on established connections are handled by a stream acceptor that routes requests to the appropriate handler.

#### Scenario: Incoming bidirectional stream handling
- **WHEN** a peer opens a bidirectional QUIC stream
- **THEN** the request is read from the receive stream and deserialized from protobuf
- **AND** the `NodeId` and `ConnId` are added as request extensions
- **AND** the request is routed through the Axum router
- **AND** the response is serialized to protobuf and written to the send stream

#### Scenario: Request handler connection error
- **WHEN** the underlying QUIC connection encounters an error during `accept_bi`
- **THEN** the stream acceptor event loop exits
- **AND** the connection is cleaned up by the connection manager

#### Scenario: Concurrent stream limits
- **WHEN** the number of concurrent bidirectional streams reaches 1000 (`MAX_CONCURRENT_BIDI_STREAMS`)
- **THEN** no additional streams can be opened until existing streams complete

#### Scenario: QUIC metrics collection
- **WHEN** the stream acceptor is running
- **THEN** QUIC connection statistics are collected every 5 seconds (`QUIC_METRIC_SCRAPE_INTERVAL`)

### Requirement: Consensus Manager

The consensus manager broadcasts artifacts within a subnet using a slot-based protocol with adverts and full artifact/ID transmission.

#### Scenario: Artifact broadcasting to all peers
- **WHEN** a new artifact is submitted for broadcast via the outbound transmit channel
- **THEN** it is assigned a unique slot number and commit ID
- **AND** a slot update is sent to all currently connected peers
- **AND** the slot update contains either the full artifact (if smaller than 1KB or latency-sensitive) or just the artifact ID

#### Scenario: Small artifact push optimization
- **WHEN** an artifact's protobuf-encoded size is less than 1024 bytes (`ARTIFACT_PUSH_THRESHOLD_BYTES`)
- **THEN** the full artifact is included in the slot update message
- **AND** peers do not need to make a separate download request

#### Scenario: Latency-sensitive artifact push
- **WHEN** an artifact is marked as `is_latency_sensitive: true`
- **THEN** the full artifact is included in the slot update regardless of size

#### Scenario: Large artifact advert only
- **WHEN** an artifact's protobuf-encoded size is >= 1024 bytes and it is not latency-sensitive
- **THEN** only the artifact ID is sent in the slot update
- **AND** the receiving peer must separately download the full artifact

#### Scenario: Duplicate artifact handling
- **WHEN** the same artifact (by ID) is submitted for broadcast a second time
- **THEN** it is not re-sent to peers
- **AND** the `send_view_consensus_dup_adverts_total` metric is incremented

#### Scenario: Artifact abort (purge)
- **WHEN** an `ArtifactTransmit::Abort` is received for an artifact ID
- **THEN** the transmission task for that artifact is cancelled
- **AND** the slot is returned to the available slot set for reuse

#### Scenario: Retry on peer send failure
- **WHEN** sending a slot update to a peer fails
- **THEN** the send is retried with exponential backoff (250ms to 60s)
- **AND** retries continue indefinitely until success or cancellation

#### Scenario: Resend on peer reconnection
- **WHEN** a peer reconnects with a new connection ID
- **THEN** all active slot updates are re-sent to that peer
- **AND** the previous transmission task to that peer is cancelled

#### Scenario: Commit ID monotonicity
- **WHEN** multiple artifacts and aborts are processed sequentially
- **THEN** the commit ID increases by 1 for each transmit event (both Deliver and Abort)
- **AND** the commit ID is included in the slot update for ordering

### Requirement: Consensus Manager Receiver

The receiver side processes incoming slot updates from peers, downloads full artifacts when needed, and delivers them to the local unvalidated pool.

#### Scenario: Receiving a slot update with full artifact
- **WHEN** a slot update containing a full artifact is received from a peer
- **THEN** the artifact is assembled and delivered to the inbound channel as an `UnvalidatedArtifactMutation::Insert`

#### Scenario: Receiving a slot update with artifact ID only
- **WHEN** a slot update containing only an artifact ID is received
- **THEN** the artifact assembler is invoked to download the full artifact from available peers

#### Scenario: Peer slot tracking
- **WHEN** slot updates are received from a peer
- **THEN** only the update with the highest commit ID for each slot is considered current
- **AND** older commit IDs for the same slot are discarded

#### Scenario: Topology change cleanup
- **WHEN** a peer leaves the subnet topology
- **THEN** all slot data from that peer is purged
- **AND** any in-progress download tasks for artifacts only held by that peer are cancelled

#### Scenario: Slot limit enforcement
- **WHEN** the number of occupied slots for a peer exceeds the configured slot limit
- **THEN** excess slot updates are dropped to prevent resource exhaustion

### Requirement: Peer Manager

The peer manager periodically checks the registry and publishes subnet topology updates.

#### Scenario: Periodic topology update
- **WHEN** the peer manager runs its update interval (every 3 seconds)
- **THEN** it queries the registry for subnet membership from the oldest registry version in use to the latest local version
- **AND** publishes the updated `SubnetTopology` to the watch channel

#### Scenario: Registry version range
- **WHEN** determining the subnet membership
- **THEN** all registry versions from `min(consensus_registry_version, latest_local_registry_version)` to `latest_local_registry_version` are considered
- **AND** nodes from higher registry versions take precedence (their addresses are used)

#### Scenario: Ignoring old registry versions
- **WHEN** a registry version is older than the consensus registry version
- **THEN** nodes from that version are not included in the topology

#### Scenario: Topology unchanged
- **WHEN** the computed topology is identical to the currently published topology
- **THEN** no update is sent to watchers (using `send_if_modified`)

### Requirement: Artifact Manager

The artifact manager processes artifacts through validation pools and manages the lifecycle of consensus artifacts.

#### Scenario: Artifact processing loop
- **WHEN** the artifact processor is running
- **THEN** it batches incoming unvalidated artifact mutations from the channel
- **AND** calls the change set producer to validate and apply changes
- **AND** transmits validated artifacts for broadcast

#### Scenario: Initial artifact broadcast
- **WHEN** an artifact handler starts with initial artifacts in the validated pool
- **THEN** all initial artifacts are immediately sent to the outbound channel for broadcast

#### Scenario: Ingress message processing
- **WHEN** an ingress message arrives via the P2P channel
- **THEN** it is inserted into the unvalidated ingress pool with a timestamp and peer ID
- **AND** the ingress handler's `on_state_change` is called to validate and apply changes

#### Scenario: Batch reading from channel
- **WHEN** multiple artifact events are available in the channel
- **THEN** they are read as a batch (up to `MAX_P2P_IO_CHANNEL_SIZE`) for efficient processing
- **AND** if the channel is closed after consuming all messages, `None` is returned to signal termination

### Requirement: State Sync Manager

The state sync manager handles downloading replicated state from peers using a chunk-based protocol.

#### Scenario: Periodic state advert broadcasting
- **WHEN** the state sync manager is running
- **THEN** it broadcasts available state adverts to all peers every 5 seconds (`ADVERT_BROADCAST_INTERVAL`)
- **AND** each broadcast has a 3-second timeout (`ADVERT_BROADCAST_TIMEOUT`)

#### Scenario: Starting a new state sync
- **WHEN** a state advert is received and `maybe_start_state_sync` returns a `Chunkable` object
- **THEN** an ongoing state sync is started for that state height
- **AND** the peer that sent the advert is added as a source for chunks

#### Scenario: Single active state sync
- **WHEN** a state sync is already in progress
- **THEN** no new state syncs are started
- **AND** peers advertising the same state ID are added to the ongoing sync
- **AND** peers advertising a different state ID are not added

#### Scenario: Rejecting peers with different state
- **WHEN** a state sync is in progress for state A
- **AND** a peer advertises state B (different ID)
- **THEN** the peer is not added to the ongoing state sync

#### Scenario: State sync completion
- **WHEN** an ongoing state sync finishes (shutdown is completed)
- **THEN** the ongoing state sync is cleaned up
- **AND** new state syncs can be started for subsequent adverts

#### Scenario: State sync cancellation
- **WHEN** the state sync client indicates the running sync should be cancelled
- **THEN** the ongoing state sync's shutdown is triggered

### Requirement: Memory Transport (Testing)

A channel-based transport for testing that simulates network conditions including latency and capacity limits.

#### Scenario: Star topology simulation
- **WHEN** peers are added to the `TransportRouter`
- **THEN** each peer has a configurable link latency and capacity to a central router
- **AND** messages traverse the sender's uplink and the receiver's downlink with associated delays

#### Scenario: Self-connection prevention
- **WHEN** a peer attempts to send an RPC to itself
- **THEN** a `P2PError` is returned with message "Can't connect to self"

#### Scenario: Capacity-limited transmission
- **WHEN** a message is sent between peers
- **THEN** the sender's uplink capacity must be acquired for the message size
- **AND** the receiver's downlink capacity must be acquired for the message size
- **AND** the appropriate latency is applied at each hop
