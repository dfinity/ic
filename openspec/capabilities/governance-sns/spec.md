# Governance: SNS Capability Specification

**Source narrative**: `openspec/specs/governance/sns/sns-governance.md`
**Crates**: `ic-sns-governance`, `ic-sns-root`, `ic-sns-swap`
**Key files**: `rs/sns/governance/src/`

---

## REQ-SNS-001: Governance Initialization

The SNS governance canister MUST be initialized with a valid configuration.

### SCENARIO-SNS-001: Valid governance proto accepted
**Given** a `GovernanceProto` is provided with all required fields (root_canister_id, ledger_canister_id, swap_canister_id, parameters, sns_metadata, mode)
**When** initialization runs
**Then** the governance canister initializes successfully
**And** the genesis timestamp is set to current time if not already set
**And** a dummy reward event is created at genesis

### SCENARIO-SNS-002: Missing required fields rejected
**Given** a `GovernanceProto` is provided without root_canister_id, ledger_canister_id, or swap_canister_id
**When** initialization runs
**Then** initialization fails with an error indicating the missing field

---

## REQ-SNS-002: Governance Mode Management

The SNS governance canister MUST operate in distinct modes that gate permitted operations.

### SCENARIO-SNS-003: PreInitializationSwap mode limits operations
**Given** governance is in `PreInitializationSwap` mode
**When** a ManageNeuron command is received
**Then** only Follow, MakeProposal, RegisterVote, AddNeuronPermissions, and RemoveNeuronPermissions are allowed
**And** all other commands (Disburse, Split, MergeMaturity, etc.) are rejected

### SCENARIO-SNS-004: Swap canister transitions to Normal mode
**Given** the swap canister calls `set_mode` with `Normal`
**When** the call is processed
**Then** governance transitions to Normal mode
**And** all ManageNeuron commands become available

### SCENARIO-SNS-005: Non-swap caller cannot set mode
**Given** a caller that is not the swap canister attempts to call `set_mode`
**When** the call is processed
**Then** the call panics with "Caller must be the swap canister"

---

## REQ-SNS-003: Neuron Management

Neurons MUST hold staked tokens, accumulate voting power, and participate in governance.

### SCENARIO-SNS-006: Neuron state determination
**Given** a neuron has `dissolve_delay_seconds > 0` and is not dissolving
**When** its state is checked
**Then** its state is `NotDissolving`

**Given** a neuron has `when_dissolved_timestamp_seconds` in the past or dissolve_delay of zero
**When** its state is checked
**Then** its state is `Dissolved` and it can be disbursed

### SCENARIO-SNS-007: Neuron voting power calculation
**Given** a neuron's voting power is calculated
**When** the calculation runs
**Then** it equals `stake * dissolve_delay_bonus * age_bonus * voting_power_percentage_multiplier`
**And** dissolve_delay_bonus ranges 0% to `max_dissolve_delay_bonus_percentage`
**And** age_bonus ranges 0% to `max_age_bonus_percentage`

### SCENARIO-SNS-008: Neuron permission authorization
**Given** a principal attempts an action on a neuron
**When** authorization is checked
**Then** the principal must have the corresponding `NeuronPermissionType`
**And** `NotAuthorized` is returned if the principal lacks the required permission

### SCENARIO-SNS-009: Maturity disbursement delay
**Given** maturity is disbursed from a neuron
**When** disbursement is processed
**Then** a 7-day delay (`MATURITY_DISBURSEMENT_DELAY_SECONDS = 604800`) is applied
**And** maturity modulation is applied unless disabled in nervous system parameters

---

## REQ-SNS-004: Proposal Lifecycle

Proposals MUST follow submission validation rules and a defined lifecycle.

### SCENARIO-SNS-010: Proposal submission validation
**Given** a proposal is submitted
**When** validation runs
**Then** title ≤ 256 bytes, summary ≤ 30,000 bytes, URL ≤ 2,048 characters
**And** motion_text ≤ 10,000 bytes for motion proposals

### SCENARIO-SNS-011: Maximum proposals with ballots
**Given** the number of unsettled proposals reaches `MAX_NUMBER_OF_PROPOSALS_WITH_BALLOTS` (700)
**When** a new proposal is submitted
**Then** the submission is rejected until existing proposals settle

### SCENARIO-SNS-012: Proposal rejection cost
**Given** a proposal is rejected
**When** rejection is processed
**Then** `reject_cost_e8s` (default: 1 governance token) is deducted from the proposer's neuron

---

## REQ-SNS-005: Voting and Decision Making

Voting MUST support direct voting, following-based delegation, and wait-for-quiet.

### SCENARIO-SNS-013: Wait-for-quiet mechanism
**Given** a vote changes the proposal's trajectory near the deadline
**When** the extension is computed
**Then** the voting deadline is extended by `wait_for_quiet_deadline_increase_seconds`
**And** the extension is bounded by the initial voting period

### SCENARIO-SNS-014: Normal proposal adoption thresholds
**Given** a normal (non-critical) proposal is evaluated
**When** the threshold is checked
**Then** it requires ≥ 3% of total voting power as yes votes (300bp)
**And** ≥ 50% of exercised voting power as yes votes (5000bp)

### SCENARIO-SNS-015: Critical proposal adoption thresholds
**Given** a critical proposal is evaluated
**When** the threshold is checked
**Then** it requires ≥ 20% of total voting power as yes votes (2000bp)
**And** ≥ 67% of exercised voting power as yes votes (6700bp)

---

## REQ-SNS-006: Following (Vote Delegation)

Neurons MUST be able to follow other neurons for automatic vote delegation.

### SCENARIO-SNS-016: Topic-based following
**Given** a neuron sets following for a specific topic
**When** a followee votes
**Then** the follower automatically casts the same vote
**And** up to 15 followees can be specified per topic (`MAX_FOLLOWEES_PER_TOPIC`)

### SCENARIO-SNS-017: Catch-all following does not apply to critical proposals
**Given** a neuron has catch-all/fallback following configured
**And** a critical proposal is submitted
**When** the followee votes
**Then** the catch-all following does NOT cascade to the critical proposal
**And** only topic-specific following for that critical topic is applied

---

## Traceability

| ID | Description | Status | Tests |
|----|-------------|--------|-------|
| REQ-SNS-001 | Governance initialization | narrative | rs/sns/governance/tests/ |
| REQ-SNS-002 | Mode management | narrative | rs/sns/governance/tests/ |
## REQ-SNS-007: Native Proposal Action Types

The governance canister MUST support a defined set of native proposal actions with stable numeric IDs.

### SCENARIO-SNS-019: Native action types available
**Given** the governance canister is initialized
**When** action types are queried
**Then** the following native actions are available with their IDs:
  - Motion (1), ManageNervousSystemParameters (2), UpgradeSnsControlledCanister (3)
  - AddGenericNervousSystemFunction (4), RemoveGenericNervousSystemFunction (5)
  - ExecuteGenericNervousSystemFunction (6), UpgradeSnsToNextVersion (7)

---

## Traceability

| ID | Description | Status | Tests |
|----|-------------|--------|-------|
| REQ-SNS-001 | Governance initialization | narrative | rs/sns/governance/tests/ |
| REQ-SNS-002 | Mode management | linked | rs/sns/governance/tests/governance.rs |
| REQ-SNS-003 | Neuron management | linked | rs/sns/governance/tests/governance.rs |
| REQ-SNS-004 | Proposal lifecycle | linked | rs/sns/governance/tests/governance.rs |
| REQ-SNS-005 | Voting and decision | linked | rs/sns/governance/tests/governance.rs |
| REQ-SNS-006 | Following (delegation) | linked | rs/sns/governance/tests/governance.rs |
| REQ-SNS-007 | Native action types | narrative | rs/sns/governance/tests/ |
