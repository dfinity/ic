# System Limits and Constants

## Requirements

### Requirement: Ingress Message Time-To-Live
MAX_INGRESS_TTL defines the maximum time an ingress message can wait before being expired. It is also used to control how long completed ingress status is retained.

#### Scenario: MAX_INGRESS_TTL value
- **WHEN** an ingress message is submitted at time t
- **THEN** it expires at t + MAX_INGRESS_TTL (5 minutes / 300 seconds)

#### Scenario: Permitted drift for clients
- **WHEN** a client creates an ingress message
- **THEN** PERMITTED_DRIFT (60 seconds) is subtracted from MAX_INGRESS_TTL to set the expiry_time_from_now
- **AND** this accounts for clock skew between client and replica

#### Scenario: Permitted drift at validator
- **WHEN** the HTTP handler checks the maximum allowed expiry
- **THEN** PERMITTED_DRIFT_AT_VALIDATOR (30 seconds) is added to MAX_INGRESS_TTL
- **AND** this admits ingress from clients with slightly skewed clocks

### Requirement: Ingress History Capacity
INGRESS_HISTORY_MAX_MESSAGES limits the maximum number of messages in the ingress history at any time.

#### Scenario: History capacity calculation
- **WHEN** the ingress history capacity is checked
- **THEN** the limit is 2 * 1000 * MAX_INGRESS_TTL_seconds = 600,000 messages
- **AND** this accounts for both Received messages and terminal-state messages

### Requirement: System Subnet Stream Throttling
SYSTEM_SUBNET_STREAM_MSG_LIMIT throttles outgoing streams from System subnets.

#### Scenario: Stream message limit
- **WHEN** a System subnet's outgoing stream is checked
- **THEN** it is limited to 100 messages for throttling the matching input stream

### Requirement: Block Payload Size Limits
MAX_BLOCK_PAYLOAD_SIZE and related constants control the size of payloads when sent over wire.

#### Scenario: Block payload size
- **WHEN** a BatchPayload is assembled
- **THEN** its wire representation MUST NOT exceed MAX_BLOCK_PAYLOAD_SIZE (4 MiB)
- **AND** with hashes-in-blocks enabled, wire size may be smaller than in-memory size

#### Scenario: Ingress bytes per block
- **WHEN** ingress messages are included in a block
- **THEN** total ingress bytes MUST NOT exceed MAX_INGRESS_BYTES_PER_BLOCK (4 MiB) in memory

#### Scenario: Ingress messages per block
- **WHEN** ingress messages are counted
- **THEN** the count MUST NOT exceed MAX_INGRESS_MESSAGES_PER_BLOCK (1000)

#### Scenario: Per-message ingress size on app subnets
- **WHEN** a single ingress message is checked on an app subnet
- **THEN** its size MUST NOT exceed MAX_INGRESS_BYTES_PER_MESSAGE_APP_SUBNET (2 MiB)

#### Scenario: Per-message ingress size on NNS subnet
- **WHEN** a single ingress message is checked on the NNS subnet
- **THEN** its size MUST NOT exceed MAX_INGRESS_BYTES_PER_MESSAGE_NNS_SUBNET (3.5 MiB)

### Requirement: DKG Interval Configuration
DKG_INTERVAL_HEIGHT and DKG_DEALINGS_PER_BLOCK control the DKG protocol timing.

#### Scenario: DKG interval length
- **WHEN** DKG intervals are configured
- **THEN** each interval has DKG_INTERVAL_HEIGHT (499) rounds after the summary block
- **AND** total interval length is 500 blocks (499 + 1 summary)

#### Scenario: DKG dealings per block
- **WHEN** DKG dealings are included in blocks
- **THEN** at most DKG_DEALINGS_PER_BLOCK (1) dealing per block

### Requirement: Consensus Timing Parameters
Unit delay and notary delay control the pacing of consensus rounds.

#### Scenario: Unit delay for app subnets
- **WHEN** a higher-rank block maker waits before proposing
- **THEN** the wait time is UNIT_DELAY_APP_SUBNET (1000 ms) per rank difference
- **AND** this allows lower-rank block makers to broadcast their blocks first

#### Scenario: Unit delay for NNS subnet
- **WHEN** the NNS subnet's block makers are timed
- **THEN** the wait time is UNIT_DELAY_NNS_SUBNET (3000 ms) per rank difference
- **AND** the longer delay accounts for the NNS subnet's larger size (~40 nodes)

#### Scenario: Initial notary delay
- **WHEN** a round begins
- **THEN** INITIAL_NOTARY_DELAY (300 ms) is the base delay before notarization

### Requirement: P2P Channel Sizing
MAX_P2P_IO_CHANNEL_SIZE defines the channel capacity for P2P communication.

#### Scenario: Channel capacity
- **WHEN** P2P channels are created
- **THEN** the buffer size is MAX_P2P_IO_CHANNEL_SIZE (100,000)
- **AND** this is sized for performance to avoid blocking on either side

### Requirement: Pre-Signature Pairing Limit
MAX_PAIRED_PRE_SIGNATURES limits how many pre-signatures can be paired with signature requests per key ID.

#### Scenario: Pre-signature pairing
- **WHEN** pre-signatures are paired with requests
- **THEN** at most MAX_PAIRED_PRE_SIGNATURES (100) may be paired per key ID

### Requirement: App Subnet Size Classification
SMALL_APP_SUBNET_MAX_SIZE classifies app subnets for configuration purposes.

#### Scenario: Small vs large app subnet
- **WHEN** an app subnet has at most SMALL_APP_SUBNET_MAX_SIZE (13) nodes
- **THEN** it uses the standard app subnet ic-prep configuration
- **WHEN** an app subnet has more than 13 nodes
- **THEN** it uses the NNS subnet ic-prep configuration

### Requirement: Cycles Logging Threshold
LOG_CANISTER_OPERATION_CYCLES_THRESHOLD reduces logging load for canister operations involving cycles.

#### Scenario: Cycles logging
- **WHEN** a canister operation involves cycles
- **THEN** detailed logging is suppressed if the amount is below LOG_CANISTER_OPERATION_CYCLES_THRESHOLD (100 billion cycles)

### Requirement: Memory Size Constants
MAX_STABLE_MEMORY_IN_BYTES, MAX_WASM_MEMORY_IN_BYTES, and MAX_WASM64_MEMORY_IN_BYTES define canister memory limits.

#### Scenario: Stable memory limit
- **WHEN** a canister's stable memory is checked
- **THEN** it MUST NOT exceed MAX_STABLE_MEMORY_IN_BYTES (500 GiB)

#### Scenario: Wasm32 memory limit
- **WHEN** a Wasm32 canister's main memory is checked
- **THEN** it MUST NOT exceed MAX_WASM_MEMORY_IN_BYTES (4 GiB)

#### Scenario: Wasm64 memory limit
- **WHEN** a Wasm64 canister's main memory is checked
- **THEN** it MUST NOT exceed MAX_WASM64_MEMORY_IN_BYTES (6 GiB)
