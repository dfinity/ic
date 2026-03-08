# Proposals

Proposals are the mechanism through which changes are made to the Internet Computer via NNS governance. Each proposal has a specific type (action) that determines its topic, processing, and the system function invoked upon adoption.

## Requirements

### Requirement: Proposal Validation
All proposals must pass validation before being submitted. This includes checking that the action is present and not obsolete, and that action-specific validation passes.

#### Scenario: Action is required
- **WHEN** a proposal is submitted without an action
- **THEN** it is rejected with "Action is required"

#### Scenario: Valid proposal title
- **WHEN** a proposal title is provided
- **THEN** it must pass validate_proposal_title validation

#### Scenario: Valid proposal summary
- **WHEN** a proposal summary is provided
- **THEN** it must pass validate_proposal_summary validation

#### Scenario: Valid proposal URL
- **WHEN** a proposal URL is provided
- **THEN** it must pass validate_proposal_url validation

### Requirement: Motion Proposals
Motion proposals allow the community to express sentiment on any topic without triggering automatic execution.

#### Scenario: Motion proposal submitted
- **WHEN** a Motion proposal is submitted
- **THEN** its topic is Governance
- **AND** the motion text must not exceed PROPOSAL_MOTION_TEXT_BYTES_MAX (10,000 bytes)

### Requirement: ManageNetworkEconomics Proposals
These proposals modify the NNS economic parameters.

#### Scenario: Network economics updated
- **WHEN** a ManageNetworkEconomics proposal is adopted
- **THEN** the new economics values are applied
- **AND** the new values must pass validation (max_proposals_to_keep_per_topic > 0, substructs set and valid)
- **AND** fields set to zero in the proposal inherit the current value

### Requirement: ExecuteNnsFunction Proposals
These proposals invoke specific NNS functions identified by an NnsFunction enum value.

#### Scenario: ExecuteNnsFunction validated
- **WHEN** an ExecuteNnsFunction proposal is submitted
- **THEN** the NnsFunction ID must be valid (not Unspecified)
- **AND** the payload must not exceed PROPOSAL_EXECUTE_NNS_FUNCTION_PAYLOAD_BYTES_MAX (70,000 bytes) for non-upgrade functions
- **AND** the topic is determined by the specific NnsFunction

#### Scenario: Payload truncated in listings
- **WHEN** proposals are listed
- **THEN** ExecuteNnsFunction payloads are truncated to EXECUTE_NNS_FUNCTION_PAYLOAD_LISTING_BYTES_MAX (1,000 bytes)

### Requirement: ManageNeuron Proposals
ManageNeuron proposals allow managing a specific neuron through governance voting rather than direct controller action.

#### Scenario: ManageNeuron proposal scope
- **WHEN** a ManageNeuron proposal is submitted
- **THEN** its topic is NeuronManagement
- **AND** only neurons that follow the managed neuron on the NeuronManagement topic can vote
- **AND** the proposal is ineligible for voting rewards (ProposalRewardStatus::Ineligible)

### Requirement: AddOrRemoveNodeProvider Proposals
These proposals add or remove node providers from the network.

#### Scenario: AddOrRemoveNodeProvider validated
- **WHEN** an AddOrRemoveNodeProvider proposal is submitted
- **THEN** the change field must be present
- **AND** if adding, the node provider must have a valid principal ID

### Requirement: RewardNodeProvider and RewardNodeProviders Proposals
These proposals reward node providers for hosting infrastructure.

#### Scenario: RewardNodeProvider topic
- **WHEN** a RewardNodeProvider or RewardNodeProviders proposal is submitted
- **THEN** its topic is NodeProviderRewards

### Requirement: RegisterKnownNeuron Proposals
Known neurons are publicly visible neurons with a name and optional description.

#### Scenario: RegisterKnownNeuron proposal
- **WHEN** a RegisterKnownNeuron proposal is adopted
- **THEN** the neuron is marked as a known neuron with the given name and description
- **AND** its topic is Governance

### Requirement: DeregisterKnownNeuron Proposals
Known neurons can be deregistered.

#### Scenario: DeregisterKnownNeuron proposal
- **WHEN** a DeregisterKnownNeuron proposal is adopted
- **THEN** the neuron is no longer a known neuron
- **AND** its topic is Governance

### Requirement: CreateServiceNervousSystem Proposals
These proposals create a new SNS (Service Nervous System) and optionally involve the Neurons' Fund.

#### Scenario: CreateServiceNervousSystem topic
- **WHEN** a CreateServiceNervousSystem proposal is submitted
- **THEN** its topic is SnsAndCommunityFund
- **AND** it triggers deployment of a new SNS via the SNS-WASM canister

### Requirement: InstallCode Proposals
These proposals install code (upgrade) on protocol canisters.

#### Scenario: InstallCode topic varies by target
- **WHEN** an InstallCode proposal targets a protocol canister
- **THEN** its topic is determined by the target canister (e.g., NetworkCanisterManagement for most, ProtocolCanisterManagement for protocol canisters)
- **AND** upgrades to the governance canister itself are allowed when resources are low

### Requirement: StopOrStartCanister Proposals
These proposals stop or start canisters managed by the NNS.

#### Scenario: StopOrStartCanister topic varies by target
- **WHEN** a StopOrStartCanister proposal is submitted
- **THEN** its topic is determined by whether the target is a protocol canister

### Requirement: UpdateCanisterSettings Proposals
These proposals update settings on NNS-managed canisters.

#### Scenario: UpdateCanisterSettings allowed when resources are low
- **WHEN** an UpdateCanisterSettings proposal targets a protocol canister
- **THEN** it is allowed even when resources are low

### Requirement: FulfillSubnetRentalRequest Proposals
These proposals fulfill subnet rental requests.

#### Scenario: FulfillSubnetRentalRequest validated
- **WHEN** a FulfillSubnetRentalRequest proposal is submitted
- **THEN** the request is validated
- **AND** its topic is SubnetRental

### Requirement: BlessAlternativeGuestOsVersion Proposals
These proposals bless new versions of the guest OS for node machines.

#### Scenario: BlessAlternativeGuestOsVersion topic
- **WHEN** a BlessAlternativeGuestOsVersion proposal is submitted
- **THEN** its topic is NodeAdmin

### Requirement: TakeCanisterSnapshot and LoadCanisterSnapshot Proposals
These proposals manage canister snapshots for backup and restore purposes.

#### Scenario: TakeCanisterSnapshot topic varies by target
- **WHEN** a TakeCanisterSnapshot proposal is submitted
- **THEN** its topic is determined by the target canister

#### Scenario: LoadCanisterSnapshot topic varies by target
- **WHEN** a LoadCanisterSnapshot proposal is submitted
- **THEN** its topic is determined by the target canister

### Requirement: Proposal Reward Status
Proposals have a reward status that determines how they affect voting rewards.

#### Scenario: AcceptVotes status
- **WHEN** a non-ManageNeuron proposal has reward_event_round == 0
- **AND** the voting deadline has not passed
- **THEN** its reward status is AcceptVotes

#### Scenario: ReadyToSettle status
- **WHEN** a non-ManageNeuron proposal has reward_event_round == 0
- **AND** the voting deadline has passed
- **THEN** its reward status is ReadyToSettle

#### Scenario: Settled status
- **WHEN** a proposal has reward_event_round != 0
- **THEN** its reward status is Settled

#### Scenario: ManageNeuron proposals ineligible
- **WHEN** a proposal's topic is NeuronManagement
- **THEN** its reward status is Ineligible

### Requirement: Self-Describing Proposal Actions
Proposal actions can be converted to self-describing formats for display purposes, including decoding Candid arguments to human-readable form.

#### Scenario: Proposal display conversion
- **WHEN** a proposal is displayed to users
- **THEN** proposal_data_to_info converts internal ProposalData to the external ProposalInfo format
- **AND** action details can be rendered as self-describing values
