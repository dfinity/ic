# Governance: NNS Capability Specification

**Source narrative**: `openspec/specs/governance/nns-governance.md`
**Crates**: `ic-nns-governance`, `ic-make-proposal`, `ic-nns-init`
**Key files**: `rs/nns/governance/src/governance.rs`, `rs/nns/governance/src/`

---

## REQ-NNS-001: Governance Canister Identity

The NNS governance canister MUST have a fixed canister ID on the NNS subnet.

### SCENARIO-NNS-001: Governance canister has fixed canister ID
**Given** the NNS governance canister is deployed
**When** its identity is checked
**Then** it is assigned index 1 on the NNS subnet
**And** its canister ID is `rrkah-fqaaa-aaaaa-aaaaq-cai`

---

## REQ-NNS-002: Governance State Management

The governance canister MUST preserve all state across upgrades.

### SCENARIO-NNS-002: State preserved across upgrades
**Given** the governance canister is upgraded
**When** the upgrade completes
**Then** the state is serialized to stable memory before upgrade
**And** deserialized from stable memory after upgrade
**And** all neurons, proposals, and configuration are preserved

---

## REQ-NNS-003: Proposal Lifecycle

Proposals MUST follow the lifecycle: Open → (Adopted | Rejected) → (Executed | Failed).

### SCENARIO-NNS-003: Proposal created and enters Open state
**Given** a neuron submits a valid proposal
**When** creation completes
**Then** the proposal is assigned a unique monotonically increasing `ProposalId`
**And** ballots are created for all eligible neurons
**And** the proposal status is Open

### SCENARIO-NNS-004: Proposal adopted by absolute majority
**Given** yes votes exceed half the total voting power
**When** the vote tally is evaluated
**Then** the proposal is marked as accepted
**And** the corresponding system function is invoked

### SCENARIO-NNS-005: Proposal rejected
**Given** no votes reach or exceed half the total voting power (making adoption impossible)
**When** the tally is evaluated
**Then** the proposal is marked as rejected
**And** a rejection fee is levied on the submitting neuron

### SCENARIO-NNS-006: Proposal execution succeeds
**Given** an adopted proposal's system function executes successfully
**When** execution completes
**Then** the proposal status becomes Executed
**And** `executed_timestamp_seconds` is set

### SCENARIO-NNS-007: Proposal execution fails
**Given** an adopted proposal's system function fails
**When** execution completes
**Then** the proposal status becomes Failed
**And** `failed_timestamp_seconds` is set
**And** the failure reason is recorded

---

## REQ-NNS-004: Wait For Quiet

The NNS MUST use Wait For Quiet to dynamically extend voting deadlines when votes flip.

### SCENARIO-NNS-008: Deadline extended on vote flip
**Given** a vote causes the leading side to switch
**And** the proposal has not yet been decided
**When** the extension is computed
**Then** the deadline is extended by a margin based on elapsed time
**And** the maximum extension per flip is `WAIT_FOR_QUIET_DEADLINE_INCREASE_SECONDS` (2 days)

### SCENARIO-NNS-009: Deadline not extended when no flip
**Given** a vote does not change which side is leading
**When** the extension is computed
**Then** the deadline remains unchanged

### SCENARIO-NNS-010: Minimum participation for simple majority
**Given** wait for quiet is used
**When** a simple majority is attempted
**Then** at least `MIN_NUMBER_VOTES_FOR_PROPOSAL_RATIO` (3%) of total voting power must participate

---

## REQ-NNS-005: Proposal Limits and Resource Protection

The governance canister MUST enforce proposal limits to prevent spam.

### SCENARIO-NNS-011: Maximum unsettled proposals enforced
**Given** the number of proposals with stored ballots reaches `MAX_NUMBER_OF_PROPOSALS_WITH_BALLOTS` (200)
**When** a non-critical proposal is submitted
**Then** the proposal is rejected until some proposals settle

### SCENARIO-NNS-012: Maximum open manage neuron proposals
**Given** the number of open ManageNeuron proposals reaches `MAX_NUMBER_OF_OPEN_MANAGE_NEURON_PROPOSALS` (10,000)
**When** a new ManageNeuron proposal is submitted
**Then** the proposal is rejected

---

## REQ-NNS-006: Rejection Cost

When a proposal is rejected, a fee MUST be charged to the submitting neuron.

### SCENARIO-NNS-013: Rejection cost applied
**Given** a proposal is rejected
**When** the rejection is processed
**Then** `neuron_fees_e8s` of the submitting neuron increases by `reject_cost_e8s` (default: 1 ICP)
**And** ManageNeuron proposals use `neuron_management_fee_per_proposal_e8s` (default: 0.01 ICP)

---

## REQ-NNS-007: Obsolete Proposal Actions

Certain obsolete proposal actions MUST be rejected.

### SCENARIO-NNS-014: Obsolete actions rejected
**Given** a SetDefaultFollowees, OpenSnsTokenSwap, or SetSnsTokenSwapOpenTimeWindow proposal is submitted
**When** the proposal is processed
**Then** it is rejected with an appropriate obsolescence message

---

## REQ-NNS-008: Neuron Rate Limiting

Neuron creation MUST be rate limited to prevent abuse.

### SCENARIO-NNS-015: Neuron creation rate limited
**Given** neurons are being created at a sustained rate
**When** the rate exceeds limits
**Then** at most `MAX_SUSTAINED_NEURONS_PER_HOUR` (15) neurons can be created per hour sustained
**And** a burst of up to `MAX_NEURON_CREATION_SPIKE` (300) is allowed

### SCENARIO-NNS-016: Maximum neurons enforced
**Given** the total number of neurons would exceed `MAX_NUMBER_OF_NEURONS` (500,000)
**When** a new neuron is created
**Then** the neuron creation is rejected

---

## Traceability

| ID | Description | Status | Tests |
|----|-------------|--------|-------|
| REQ-NNS-001 | Canister identity | narrative | rs/nns/governance/tests/ |
| REQ-NNS-002 | State management | narrative | rs/nns/governance/tests/ |
| REQ-NNS-003 | Proposal lifecycle | narrative | rs/nns/governance/tests/ |
| REQ-NNS-004 | Wait for quiet | narrative | rs/nns/governance/tests/ |
| REQ-NNS-005 | Proposal limits | narrative | rs/nns/governance/tests/ |
| REQ-NNS-006 | Rejection cost | narrative | rs/nns/governance/tests/ |
| REQ-NNS-007 | Obsolete actions | narrative | rs/nns/governance/tests/ |
| REQ-NNS-008 | Neuron rate limiting | narrative | rs/nns/governance/tests/ |
