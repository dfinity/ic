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
## REQ-NNS-009: Network Economics Configuration

The governance canister MUST maintain configurable economic parameters.

### SCENARIO-NNS-017: Default network economics values
**Given** network economics are initialized with defaults
**When** the defaults are checked
**Then** `reject_cost_e8s` = 100,000,000 (1 ICP)
**And** `neuron_management_fee_per_proposal_e8s` = 1,000,000 (0.01 ICP)
**And** `neuron_minimum_stake_e8s` = 100,000,000 (1 ICP)
**And** `neuron_spawn_dissolve_delay_seconds` = 7 days
**And** `max_proposals_to_keep_per_topic` = 100

### SCENARIO-NNS-018: Network economics validation
**Given** a `ManageNetworkEconomics` proposal is applied
**When** validation runs
**Then** `max_proposals_to_keep_per_topic` must be positive
**And** `neurons_fund_economics` must be set and valid
**And** `voting_power_economics` must be set and valid

---

## REQ-NNS-010: Proposal Topics

Each proposal type MUST be assigned a topic that determines eligible voters.

### SCENARIO-NNS-019: Proposal topic assignment by type
**Given** proposals of various types are submitted
**When** topic assignment occurs
**Then** ManageNeuron → `NeuronManagement`
**And** ManageNetworkEconomics → `NetworkEconomics`
**And** Motion → `Governance`
**And** ApproveGenesisKyc → `Kyc`
**And** AddOrRemoveNodeProvider → `ParticipantManagement`
**And** RewardNodeProvider → `NodeProviderRewards`
**And** CreateServiceNervousSystem → `SnsAndCommunityFund`

---

## REQ-NNS-011: Proposal Content Limits

Proposal content MUST respect configurable size limits.

### SCENARIO-NNS-020: Motion text size enforced
**Given** a Motion proposal is submitted with text exceeding `PROPOSAL_MOTION_TEXT_BYTES_MAX` (10,000 bytes)
**When** validation runs
**Then** the proposal is rejected

### SCENARIO-NNS-021: ExecuteNnsFunction payload size enforced
**Given** an `ExecuteNnsFunction` proposal is submitted with payload exceeding 70,000 bytes
**When** validation runs
**Then** the proposal is rejected

---

## REQ-NNS-012: Timer Tasks

The governance canister MUST run periodic timer tasks for background operations.

### SCENARIO-NNS-022: Timer tasks execute periodic operations
**Given** the governance timer fires
**When** timer tasks run
**Then** reward calculations are performed and distributed to neurons
**And** maturity disbursements are finalized
**And** neuron data validation runs
**And** voting power snapshots are taken
**And** stale following is pruned
**And** spawning neurons are processed

---

## REQ-NNS-013: Vote Casting

Neurons MUST be able to cast votes directly, with eligibility rules and cascade processing.

### SCENARIO-NNS-023: Direct vote
**Given** a neuron's controller or hot key submits a vote (Yes or No) on a proposal
**When** the vote is cast
**Then** the vote is recorded in the proposal's ballots
**And** cascade follow processing is triggered
**And** the proposal tally is recomputed

### SCENARIO-NNS-024: Vote eligibility
**Given** a neuron attempts to vote on a proposal
**When** eligibility is checked
**Then** the neuron must have been created before the proposal was submitted
**And** the neuron must have a ballot in the proposal's ballots map

### SCENARIO-NNS-025: Votes eligible for rewards
**Given** a vote is cast
**When** reward eligibility is checked
**Then** Yes or No votes are eligible for voting rewards
**And** Unspecified votes are NOT eligible for rewards

---

## REQ-NNS-014: Voting State Machine

The voting system MUST use a state machine that processes votes across message boundaries to avoid instruction limits.

### SCENARIO-NNS-026: Vote processing with instruction limits
**Given** a vote is cast
**When** cascade follow processing runs
**Then** processing continues until either voting is finished or the soft instruction limit (1 billion instructions) is reached
**And** if the soft limit is reached, processing continues in the next message via self-call
**And** if the hard limit (750 billion instructions) is reached, remaining processing moves to timer jobs

### SCENARIO-NNS-027: Background vote processing
**Given** timer tasks run
**When** unfinished voting state machines exist
**Then** they are processed, tallies are recomputed, and decided proposals are handled

---

## REQ-NNS-015: Tally Recomputation

After votes are cast, the proposal tally MUST be recomputed to determine the outcome.

### SCENARIO-NNS-028: Tally counts
**Given** a proposal tally is recomputed
**When** the computation runs
**Then** `yes` = sum of voting power of all Yes ballots
**And** `no` = sum of voting power of all No ballots
**And** `total` = sum of voting power of ALL ballots (yes + no + undecided)

### SCENARIO-NNS-029: Proposal decided by majority
**Given** a proposal tally is evaluated
**When** `yes > total / 2`
**Then** the proposal is accepted (adopted)

**When** `no >= ceil(total / 2)`
**Then** the proposal is rejected (adoption becomes impossible)

---

## REQ-NNS-016: Reward Rate Calculation

The reward rate MUST decrease from 10% to 5% per year over 8 years following a quadratic curve.

### SCENARIO-NNS-030: Reward rate at genesis
**Given** rewards are calculated at IC genesis
**When** the rate is computed
**Then** the rate is `INITIAL_VOTING_REWARD_RELATIVE_RATE` (10% per year / 365.25 days)

### SCENARIO-NNS-031: Reward rate after 8 years
**Given** rewards are calculated at or after `REWARD_FLATTENING_DATE` (8 years * 365.25 days)
**When** the rate is computed
**Then** the rate is `FINAL_VOTING_REWARD_RELATIVE_RATE` (5% per year / 365.25 days)

### SCENARIO-NNS-032: Reward rate quadratic curve
**Given** rewards are calculated between genesis and 8 years
**When** the rate is computed
**Then** `R(t) = Rf + (R0 - Rf) * [(t - T) / (G - T)]^2`
**And** the curve is differentiable at the flattening date (smooth transition)
**And** the rate decreases monotonically

---

## REQ-NNS-017: Reward Distribution

Rewards MUST be distributed daily as maturity, with rollover for periods with no settled proposals.

### SCENARIO-NNS-033: Daily reward pool
**Given** the daily reward pool is calculated for a given day since genesis
**When** the calculation runs
**Then** pool = supply fraction rate * total ICP supply
**And** undistributed rewards are rolled over

### SCENARIO-NNS-034: Rewards rolled over when no proposals settle
**Given** a reward event has no settled proposals
**When** the event is processed
**Then** `total_available_e8s_equivalent` and `rounds_since_last_distribution` are rolled over to the next event

### SCENARIO-NNS-035: Rewards distributed as maturity
**Given** rewards are distributed to a neuron with `auto_stake_maturity = false`
**When** distribution runs
**Then** the reward is added to `maturity_e8s_equivalent`

### SCENARIO-NNS-036: Rewards auto-staked
**Given** rewards are distributed to a neuron with `auto_stake_maturity = true`
**When** distribution runs
**Then** the reward is added to `staked_maturity_e8s_equivalent`

### SCENARIO-NNS-037: Reward distribution uses state machine
**Given** a reward distribution is scheduled
**When** processing runs
**Then** it is processed across multiple messages respecting instruction limits (1 billion per message)
**And** each neuron's reward is applied atomically

---

## REQ-NNS-018: Maturity Disbursement

Neuron maturity MUST be disbursable with a 7-day delay and subject to maturity modulation.

### SCENARIO-NNS-038: Initiate maturity disbursement
**Given** a neuron controller initiates a maturity disbursement
**And** the percentage is between 1 and 100
**And** the neuron is not spawning
**And** in-progress disbursements < `MAX_NUM_DISBURSEMENTS` (10)
**And** the disbursement amount ≥ `MINIMUM_DISBURSEMENT_E8S` (1 ICP)
**When** the request is processed
**Then** a `MaturityDisbursement` record is created
**And** `disbursement_maturity_e8s` is deducted from the neuron's maturity
**And** the disbursement will be finalized after `DISBURSEMENT_DELAY_SECONDS` (7 days)

### SCENARIO-NNS-039: Disbursement finalization with modulation
**Given** the 7-day delay has passed
**When** finalization runs
**Then** maturity modulation is applied to determine the actual ICP amount
**And** the ICP is minted to the specified destination account

### SCENARIO-NNS-040: Disbursement destination rules
**Given** no destination is specified
**When** disbursement runs
**Then** ICP is sent to the caller's default account

**Given** both Account and AccountIdentifier are specified
**When** disbursement runs
**Then** the disbursement fails with an error

### SCENARIO-NNS-041: Too many disbursements
**Given** a neuron already has `MAX_NUM_DISBURSEMENTS` (10) in progress
**When** a new disbursement is requested
**Then** the request is rejected

---

## REQ-NNS-019: Maturity Modulation

Maturity modulation MUST adjust the conversion rate between maturity and ICP within a bounded range.

### SCENARIO-NNS-042: Maturity modulation range
**Given** maturity modulation is applied
**When** the modulation value is checked
**Then** it is within `VALID_MATURITY_MODULATION_BASIS_POINTS_RANGE` (-500 to +500 basis points)
**And** the actual ICP minted can vary by +/- 5% from the maturity amount

---

## REQ-NNS-020: Voting Power Snapshots

Periodic snapshots of neuron voting power MUST be taken for reward computation.

### SCENARIO-NNS-043: Voting power snapshots taken
**Given** the `snapshot_voting_power` timer task runs
**When** the snapshot is taken
**Then** a snapshot of all neuron voting powers is stored in `VOTING_POWER_SNAPSHOTS` stable storage
**And** these snapshots are used for reward calculations

---

## Traceability

| ID | Description | Status | Tests |
|----|-------------|--------|-------|
| REQ-NNS-001 | Canister identity | narrative | rs/nns/governance/tests/ |
| REQ-NNS-002 | State management | narrative | rs/nns/governance/tests/ |
| REQ-NNS-003 | Proposal lifecycle | linked | rs/nns/governance/tests/governance.rs |
| REQ-NNS-004 | Wait for quiet | linked | rs/nns/governance/tests/governance.rs |
| REQ-NNS-005 | Proposal limits | linked | rs/nns/governance/tests/governance.rs |
| REQ-NNS-006 | Rejection cost | linked | rs/nns/governance/tests/governance.rs |
| REQ-NNS-007 | Obsolete actions | narrative | rs/nns/governance/tests/ |
| REQ-NNS-008 | Neuron rate limiting | linked | rs/nns/governance/tests/governance.rs |
| REQ-NNS-009 | Network economics | narrative | rs/nns/governance/tests/ |
| REQ-NNS-010 | Proposal topics | narrative | rs/nns/governance/tests/ |
| REQ-NNS-011 | Proposal content limits | narrative | rs/nns/governance/tests/ |
| REQ-NNS-012 | Timer tasks | narrative | rs/nns/governance/tests/ |
| REQ-NNS-013 | Vote casting | narrative | rs/nns/governance/src/voting.rs |
| REQ-NNS-014 | Voting state machine | narrative | rs/nns/governance/src/voting.rs |
| REQ-NNS-015 | Tally recomputation | narrative | rs/nns/governance/tests/ |
| REQ-NNS-016 | Reward rate calculation | narrative | rs/nns/governance/src/reward/ |
| REQ-NNS-017 | Reward distribution | narrative | rs/nns/governance/src/reward/ |
| REQ-NNS-018 | Maturity disbursement | narrative | rs/nns/governance/tests/ |
| REQ-NNS-019 | Maturity modulation | narrative | rs/nns/governance/tests/ |
| REQ-NNS-020 | Voting power snapshots | narrative | rs/nns/governance/tests/ |
