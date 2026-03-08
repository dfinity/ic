# Nervous System Common

**Crates**: `ic-neurons-fund`, `ic-neurons-fund-audit`, `ic-nervous-system-access-list`, `ic-nervous-system-canisters`, `ic-nervous-system-common-build-metadata`, `ic-nervous-system-common-validation`, `ic-nervous-system-governance`, `ic-nervous-system-linear-map`, `ic-nervous-system-rate-limits`

The nervous system common libraries provide shared types, utilities, clients, and runtime support used by both the NNS and SNS governance systems. This includes common protobuf types, client abstractions, timer infrastructure, and matched funding (Neurons' Fund) logic.

## Requirements

### Requirement: NNS Common Types
The NNS common library defines core types used throughout the NNS governance system.

#### Scenario: NeuronId type
- **WHEN** a NeuronId is created
- **THEN** it wraps a u64 identifier
- **AND** it supports MIN (u64::MIN) and MAX (u64::MAX) constants
- **AND** it implements Storable for stable memory with fixed size of 8 bytes
- **AND** it supports next() for iteration

#### Scenario: ProposalId type
- **WHEN** a ProposalId is created
- **THEN** it wraps a u64 identifier
- **AND** it supports MIN (u64::MIN) and MAX (u64::MAX) constants
- **AND** it implements Storable for stable memory with fixed size of 8 bytes

### Requirement: NNS Constants
The NNS constants library defines well-known canister IDs and configuration values.

#### Scenario: NNS canister installation order
- **WHEN** NNS canisters are installed
- **THEN** they must be installed in order: Registry (0), Governance (1), Ledger (2), Root (3), CMC (4), Lifeline (5), GTC (6), Identity (7), NNS-UI (8), ICP Ledger Archive (9), SNS-WASM (10), Ledger Index (11), plus archive canisters, subnet rental, node rewards, and migration canisters

#### Scenario: Memory allocation per canister
- **WHEN** memory allocation is queried for an NNS canister
- **THEN** ICP Ledger Archive gets 8 GiB
- **AND** Ledger gets 4 GiB
- **AND** Root, CMC, Lifeline, and GTC get 1 GiB
- **AND** all other canisters get best-effort allocation (0)

#### Scenario: Protocol canister identification
- **WHEN** determining if a canister is a protocol canister
- **THEN** the PROTOCOL_CANISTER_IDS list identifies all protocol-level canisters
- **AND** this includes NNS canisters plus Bitcoin, Exchange Rate, Cycles Ledger, and Dogecoin canisters

#### Scenario: SNS governance memory limit
- **WHEN** an SNS governance canister is configured
- **THEN** DEFAULT_SNS_GOVERNANCE_CANISTER_WASM_MEMORY_LIMIT is 4 GiB
- **AND** DEFAULT_SNS_NON_GOVERNANCE_CANISTER_WASM_MEMORY_LIMIT is 3 GiB

### Requirement: Nervous System Clients
The nervous system clients library provides abstractions for inter-canister communication.

#### Scenario: Client modules available
- **WHEN** the clients library is used
- **THEN** it provides: canister_id_record, canister_metadata, canister_status, delete_canister, ledger_client, load_canister_snapshot, management_canister_client, stop_canister, take_canister_snapshot, update_settings

### Requirement: Nervous System Runtime
The nervous system runtime library provides a platform abstraction for canister execution.

#### Scenario: Runtime abstraction
- **WHEN** governance code runs
- **THEN** it uses the runtime abstraction for canister operations
- **AND** the abstraction supports both production (WASM) and test environments

### Requirement: Nervous System Timer Tasks
The timer task infrastructure provides a framework for periodic background operations.

#### Scenario: Timer task execution
- **WHEN** a timer task is scheduled
- **THEN** it runs periodically based on its configured interval
- **AND** it respects instruction limits to avoid blocking the canister

### Requirement: Neurons' Fund (Matched Funding)
The Neurons' Fund enables NNS neurons to automatically participate in SNS token swaps using their maturity. The participation amount is a function of the swap's direct participation.

#### Scenario: Neurons' Fund participation limits
- **WHEN** the Neurons' Fund participates in an SNS swap
- **THEN** it uses at most MAX_NEURONS_FUND_PARTICIPATION_BASIS_POINTS (1,000 = 10%) of its total maturity
- **AND** at most MAX_NEURONS_FUND_PARTICIPANTS (5,000) neurons can participate

#### Scenario: Matched funding curve
- **WHEN** the Neurons' Fund matched funding is calculated
- **THEN** it uses a polynomial matching function configured via NeuronsFundEconomics
- **AND** the default max_theoretical_participation is 750,000 XDR
- **AND** the contribution_threshold is 75,000 XDR
- **AND** the one_third_participation_milestone is 225,000 XDR
- **AND** the full_participation_milestone is 375,000 XDR

#### Scenario: ICP/XDR rate bounds for Neurons' Fund
- **WHEN** the ICP/XDR rate is used for Neurons' Fund calculations
- **THEN** minimum_icp_xdr_rate is 1:1 (10,000 basis points)
- **AND** maximum_icp_xdr_rate is 1:100 (1,000,000 basis points)

#### Scenario: Polynomial matching function
- **WHEN** the matching function is applied
- **THEN** it implements the IdealMatchingFunction trait
- **AND** it can be serialized/deserialized for swap parameter transfer
- **AND** the serialized representation must not exceed MAX_MATCHING_FUNCTION_SERIALIZED_REPRESENTATION_SIZE_BYTES (1,000)

#### Scenario: Linear scaling coefficients
- **WHEN** ideal Neurons' Fund participation is scaled to effective participation
- **THEN** linear scaling coefficients are used
- **AND** the number of intervals must not exceed MAX_LINEAR_SCALING_COEFFICIENT_VEC_LEN (100,000)

### Requirement: Neurons' Fund Snapshot
A snapshot captures which neurons participate and how much maturity each contributes.

#### Scenario: Snapshot creation
- **WHEN** a CreateServiceNervousSystem proposal is adopted
- **THEN** a NeuronsFundSnapshot is created listing all participating neurons
- **AND** each neuron's portion includes: neuron ID, amount in ICP e8s, maturity equivalent, controller, whether capped, and hotkeys

#### Scenario: Settle Neurons' Fund participation
- **WHEN** an SNS swap completes
- **THEN** SettleNeuronsFundParticipationRequest is processed
- **AND** maturity is drawn from or refunded to participating neurons
- **AND** the settlement result is returned including per-neuron details

### Requirement: Neurons' Fund Audit
Audit information is maintained for Neurons' Fund participation.

#### Scenario: Audit info query
- **WHEN** GetNeuronsFundAuditInfoRequest is processed
- **THEN** the full audit trail of Neurons' Fund participation is returned
- **AND** it includes the snapshot, participation constraints, and settlement details

### Requirement: Nervous System Lock
The lock module provides concurrency control for nervous system operations.

#### Scenario: Lock prevents concurrent access
- **WHEN** a nervous system operation acquires a lock
- **THEN** other operations for the same resource are blocked until the lock is released

### Requirement: Nervous System Agent
The nervous system agent provides tools for interacting with nervous system canisters from external environments.

#### Scenario: Agent functionality
- **WHEN** the nervous system agent is used
- **THEN** it provides tools for submitting proposals, managing neurons, and querying governance state
