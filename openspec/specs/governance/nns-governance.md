# NNS Governance

**Crates**: `ic-make-proposal`, `nns_dapp`, `ic-nns-init`

The Network Nervous System (NNS) is the open, decentralized governance system of the Internet Computer (IC). It has complete control over all aspects of the IC network, including protocol upgrades, subnet management, node operator onboarding, economic parameters, and canister management. The NNS operates by accepting proposals submitted by neurons, deciding whether to adopt or reject them based on neuron voting activity.

## Requirements

### Requirement: Governance Canister Identity
The NNS Governance canister is installed at index 1 on the NNS subnet with canister ID `rrkah-fqaaa-aaaaa-aaaaq-cai`. It interfaces with the ICP Ledger canister for token transfers and the Registry canister for distributing configuration to all subnets.

#### Scenario: Governance canister has a fixed canister ID
- **WHEN** the NNS governance canister is deployed
- **THEN** it is assigned index 1 on the NNS subnet
- **AND** its canister ID is `rrkah-fqaaa-aaaaa-aaaaq-cai`

### Requirement: Governance State Management
The governance canister maintains its state across heap and stable memory, splitting data to manage memory efficiently. It stores proposals, neurons, cached metrics, and configuration in a `GovernanceProto` structure.

#### Scenario: State is preserved across upgrades
- **WHEN** the governance canister is upgraded
- **THEN** the state is serialized to stable memory before upgrade
- **AND** the state is deserialized from stable memory after upgrade
- **AND** all neurons, proposals, and configuration are preserved

### Requirement: Proposal Lifecycle
Proposals follow a lifecycle: Open -> (Adopted | Rejected) -> (Executed | Failed). A proposal is created when a neuron submits it, and is decided based on voting activity. Adopted proposals trigger execution of their associated system function.

#### Scenario: Proposal is created and enters Open state
- **WHEN** a neuron submits a valid proposal
- **THEN** the proposal is assigned a unique monotonically increasing ProposalId
- **AND** ballots are created for all eligible neurons
- **AND** the proposal status is Open
- **AND** the proposal timestamp is recorded

#### Scenario: Proposal is adopted by absolute majority
- **WHEN** yes votes exceed half the total voting power
- **THEN** the proposal is marked as accepted
- **AND** the decided_timestamp_seconds is set
- **AND** the corresponding system function is invoked

#### Scenario: Proposal is rejected
- **WHEN** no votes reach or exceed half the total voting power (making adoption impossible)
- **THEN** the proposal is marked as rejected
- **AND** a rejection fee is levied on the submitting neuron
- **AND** the decided_timestamp_seconds is set

#### Scenario: Proposal execution succeeds
- **WHEN** an adopted proposal's system function executes successfully
- **THEN** the proposal status becomes Executed
- **AND** the executed_timestamp_seconds is set

#### Scenario: Proposal execution fails
- **WHEN** an adopted proposal's system function fails
- **THEN** the proposal status becomes Failed
- **AND** the failed_timestamp_seconds is set
- **AND** the failure reason is recorded

### Requirement: Wait For Quiet
The NNS uses a "Wait For Quiet" algorithm to dynamically extend voting deadlines when votes flip. This allows decisions without a quorum while preventing last-minute vote manipulation.

#### Scenario: Voting deadline is extended when vote flips
- **WHEN** a vote causes the leading side to switch (from yes-leading to no-leading or vice versa)
- **AND** the proposal has not yet been decided
- **AND** the deadline has not been reached
- **THEN** the deadline is extended by a margin based on elapsed time
- **AND** the maximum extension per flip is WAIT_FOR_QUIET_DEADLINE_INCREASE_SECONDS (2 days)

#### Scenario: Voting deadline is not extended when vote does not flip
- **WHEN** a vote does not change which side is leading
- **THEN** the deadline remains unchanged

#### Scenario: Minimum votes required for simple majority
- **WHEN** wait for quiet is used
- **THEN** a minimum of 3% of total possible voting power (MIN_NUMBER_VOTES_FOR_PROPOSAL_RATIO) must participate for a simple majority to suffice

### Requirement: Proposal Limits and Resource Protection
The governance canister enforces limits on proposals to prevent spam and protect resources.

#### Scenario: Maximum unsettled proposals enforced
- **WHEN** the number of proposals with stored ballots reaches MAX_NUMBER_OF_PROPOSALS_WITH_BALLOTS (200)
- **THEN** new proposals of non-critical types are rejected until some settle

#### Scenario: Maximum open manage neuron proposals enforced
- **WHEN** the number of open ManageNeuron proposals reaches MAX_NUMBER_OF_OPEN_MANAGE_NEURON_PROPOSALS (10,000)
- **THEN** new ManageNeuron proposals are rejected

#### Scenario: Resource-critical proposals allowed when resources are low
- **WHEN** heap growth potential is low
- **THEN** only resource-critical proposals (InstallCode for governance canister, UpdateCanisterSettings, certain ExecuteNnsFunction types, RegisterVote, MakeProposal) are allowed

#### Scenario: Maximum list results enforced
- **WHEN** listing proposals
- **THEN** at most MAX_LIST_PROPOSAL_RESULTS (100) proposals are returned
- **WHEN** listing neurons
- **THEN** at most MAX_LIST_NEURONS_RESULTS (50) neurons are returned

### Requirement: Proposal Topics
Each proposal type belongs to a specific topic that determines processing details and eligible voters.

#### Scenario: Proposal topic assignment
- **WHEN** a ManageNeuron proposal is submitted
- **THEN** its topic is NeuronManagement
- **WHEN** a ManageNetworkEconomics proposal is submitted
- **THEN** its topic is NetworkEconomics
- **WHEN** a Motion proposal is submitted
- **THEN** its topic is Governance
- **WHEN** an ApproveGenesisKyc proposal is submitted
- **THEN** its topic is Kyc
- **WHEN** an AddOrRemoveNodeProvider proposal is submitted
- **THEN** its topic is ParticipantManagement
- **WHEN** a RewardNodeProvider proposal is submitted
- **THEN** its topic is NodeProviderRewards
- **WHEN** a CreateServiceNervousSystem proposal is submitted
- **THEN** its topic is SnsAndCommunityFund

### Requirement: Obsolete Proposal Actions Rejected
Certain proposal actions are obsolete and must be rejected.

#### Scenario: Obsolete actions rejected
- **WHEN** a SetDefaultFollowees proposal is submitted
- **THEN** it is rejected with "SetDefaultFollowees is obsolete"
- **WHEN** an OpenSnsTokenSwap proposal is submitted
- **THEN** it is rejected with "OpenSnsTokenSwap is obsolete"
- **WHEN** a SetSnsTokenSwapOpenTimeWindow proposal is submitted
- **THEN** it is rejected with "SetSnsTokenSwapOpenTimeWindow is obsolete"

### Requirement: Rejection Cost
When a proposal is rejected, a fee is charged to the submitting neuron to prevent spam.

#### Scenario: Rejection cost applied
- **WHEN** a proposal is rejected
- **THEN** the neuron_fees_e8s of the submitting neuron is increased by reject_cost_e8s (default: 1 ICP)
- **AND** the neuron management fee for ManageNeuron proposals is neuron_management_fee_per_proposal_e8s (default: 0.01 ICP)

### Requirement: Network Economics Configuration
The governance canister maintains configurable economic parameters that control fees, rewards, and other economic aspects.

#### Scenario: Default network economics values
- **WHEN** network economics are initialized with defaults
- **THEN** reject_cost_e8s is 1 ICP (100,000,000 e8s)
- **AND** neuron_management_fee_per_proposal_e8s is 0.01 ICP (1,000,000 e8s)
- **AND** neuron_minimum_stake_e8s is 1 ICP
- **AND** neuron_spawn_dissolve_delay_seconds is 7 days
- **AND** maximum_node_provider_rewards_e8s is 1,000,000 ICP
- **AND** max_proposals_to_keep_per_topic is 100

#### Scenario: Network economics validation
- **WHEN** a ManageNetworkEconomics proposal is applied
- **THEN** max_proposals_to_keep_per_topic must be positive
- **AND** neurons_fund_economics must be set and valid
- **AND** voting_power_economics must be set and valid

### Requirement: Motion Text Size Limit
Motion proposals have a maximum text size.

#### Scenario: Motion text size enforced
- **WHEN** a Motion proposal is submitted with text exceeding PROPOSAL_MOTION_TEXT_BYTES_MAX (10,000 bytes)
- **THEN** the proposal is rejected

### Requirement: NNS Function Execution Payload Limit
ExecuteNnsFunction proposals have a maximum payload size.

#### Scenario: Payload size enforced
- **WHEN** an ExecuteNnsFunction proposal is submitted with payload exceeding 70,000 bytes
- **THEN** the proposal is rejected

### Requirement: Timer Tasks
The governance canister uses periodic timer tasks for background operations.

#### Scenario: Timer tasks execute periodic operations
- **WHEN** timer tasks run
- **THEN** reward calculations are performed
- **AND** rewards are distributed to neurons
- **AND** maturity disbursements are finalized
- **AND** neuron data validation runs
- **AND** voting power snapshots are taken
- **AND** stale following is pruned
- **AND** maturity of dissolved neurons is unstaked
- **AND** spawning neurons are processed

### Requirement: Neuron Rate Limiting
Neuron creation is rate limited to prevent abuse.

#### Scenario: Neuron creation rate limited
- **WHEN** neurons are being created
- **THEN** at most MAX_SUSTAINED_NEURONS_PER_HOUR (15) neurons can be created per hour sustained
- **AND** a burst of up to MAX_NEURON_CREATION_SPIKE (300) neurons is allowed
- **AND** the allowance increases at a rate of one every MINIMUM_SECONDS_BETWEEN_ALLOWANCE_INCREASE (240) seconds

### Requirement: Maximum Number of Neurons
The governance canister enforces a maximum number of neurons.

#### Scenario: Maximum neurons enforced
- **WHEN** a new neuron would exceed MAX_NUMBER_OF_NEURONS (500,000)
- **THEN** the neuron creation is rejected
