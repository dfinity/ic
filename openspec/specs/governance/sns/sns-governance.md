# SNS Governance

The SNS Governance canister is the decision-making engine of a Service Nervous System. It manages neurons, proposals, voting, following, rewards, and the execution of adopted proposals. It operates in two modes: `PreInitializationSwap` (limited functionality during token sale) and `Normal` (full functionality after successful decentralization swap).

## Requirements

### Requirement: Governance Initialization

The governance canister must be initialized with a valid configuration including references to root, ledger, and swap canisters, valid nervous system parameters, and initial neurons.

#### Scenario: Valid governance proto accepted
- **WHEN** a `GovernanceProto` is provided with all required fields populated (root_canister_id, ledger_canister_id, swap_canister_id, parameters, sns_metadata, mode)
- **THEN** the governance canister initializes successfully
- **AND** the genesis timestamp is set to the current time if not already set
- **AND** all neuron timestamps are set to genesis time
- **AND** a dummy reward event is created at genesis to mark the SNS era origin

#### Scenario: Missing required fields rejected
- **WHEN** a `GovernanceProto` is provided without root_canister_id, ledger_canister_id, or swap_canister_id
- **THEN** initialization fails with an error indicating the missing field

#### Scenario: Invalid mode rejected
- **WHEN** the mode field is set to `Unspecified` or an unknown value
- **THEN** initialization fails with an error

#### Scenario: PreInitializationSwap mode requires swap_canister_id
- **WHEN** the mode is `PreInitializationSwap`
- **THEN** the swap_canister_id field must be populated
- **AND** initialization fails if it is missing

### Requirement: Governance Mode Management

The governance canister operates in distinct modes that gate which operations are permitted.

#### Scenario: PreInitializationSwap mode limits operations
- **WHEN** governance is in `PreInitializationSwap` mode
- **THEN** only Follow, MakeProposal, RegisterVote, AddNeuronPermissions, and RemoveNeuronPermissions commands are allowed for regular callers
- **AND** ClaimOrRefresh is allowed only when the caller is the swap canister
- **AND** all other ManageNeuron commands (e.g., Disburse, Split, MergeMaturity, StartDissolving, etc.) are rejected

#### Scenario: Swap canister transitions governance to Normal mode
- **WHEN** the swap canister calls `set_mode` with `Normal`
- **THEN** governance transitions to Normal mode
- **AND** all ManageNeuron commands become available

#### Scenario: Non-swap caller cannot set mode
- **WHEN** a caller that is not the swap canister attempts to call `set_mode`
- **THEN** the call panics with "Caller must be the swap canister"

#### Scenario: Only Normal mode transition allowed
- **WHEN** any caller attempts to set mode to something other than `Normal`
- **THEN** the call panics indicating the mode transition is not allowed

### Requirement: Neuron Management

Neurons are the fundamental governance entities that hold staked tokens, accumulate voting power, and participate in governance decisions.

#### Scenario: Neuron state determination
- **WHEN** a neuron has a `dissolve_delay_seconds` greater than zero and is not dissolving
- **THEN** its state is `NotDissolving`
- **WHEN** a neuron has a `when_dissolved_timestamp_seconds` in the future
- **THEN** its state is `Dissolving`
- **WHEN** a neuron has a `when_dissolved_timestamp_seconds` in the past or dissolve_delay of zero
- **THEN** its state is `Dissolved` and can be disbursed

#### Scenario: Neuron voting power calculation
- **WHEN** a neuron's voting power is calculated
- **THEN** it equals stake * dissolve_delay_bonus * age_bonus * voting_power_percentage_multiplier
- **AND** dissolve_delay_bonus ranges from 0% (at 0 delay) up to max_dissolve_delay_bonus_percentage (at max_dissolve_delay_seconds)
- **AND** age_bonus ranges from 0% (at 0 age) up to max_age_bonus_percentage (at max_neuron_age_for_age_bonus)
- **AND** voting_power_percentage_multiplier is a percentage (0-100) applied to the total

#### Scenario: Neuron permission authorization
- **WHEN** a principal attempts an action on a neuron
- **THEN** the principal must have the corresponding `NeuronPermissionType` in the neuron's permission list
- **AND** if the principal lacks the required permission, a `NotAuthorized` error is returned

#### Scenario: Permission modification authorization
- **WHEN** a principal attempts to modify neuron permissions
- **AND** the permissions being changed are exclusively voting-related (Vote, SubmitProposal, ManageVotingPermission)
- **THEN** either `ManagePrincipals` or `ManageVotingPermission` permission is sufficient
- **WHEN** the permissions being changed include non-voting permissions
- **THEN** only `ManagePrincipals` permission is sufficient

#### Scenario: List neurons
- **WHEN** `list_neurons` is called
- **THEN** at most 100 neurons are returned per call (MAX_LIST_NEURONS_RESULTS)

#### Scenario: Neuron validation at initialization
- **WHEN** neurons are validated during governance initialization
- **THEN** each neuron's `voting_power_percentage_multiplier` must be between 0 and 100 inclusive
- **AND** neurons exceeding 100 cause a validation error

### Requirement: Neuron Disbursement

Dissolved neurons can be disbursed, returning their staked tokens to the owner.

#### Scenario: Disburse dissolved neuron
- **WHEN** a neuron is in the `Dissolved` state
- **AND** the caller has the appropriate permissions
- **THEN** the neuron's staked tokens are transferred to the specified account
- **AND** the ledger transaction fee is deducted

#### Scenario: Maturity disbursement delay
- **WHEN** maturity is disbursed from a neuron
- **THEN** the disbursement is subject to a 7-day delay (MATURITY_DISBURSEMENT_DELAY_SECONDS = 604800)
- **AND** maturity modulation is applied unless disabled in nervous system parameters

### Requirement: Proposal Lifecycle

Proposals are the mechanism through which governance decisions are made. They follow a lifecycle from submission through voting to execution or rejection.

#### Scenario: Proposal submission validation
- **WHEN** a proposal is submitted
- **THEN** the title must not exceed 256 bytes (PROPOSAL_TITLE_BYTES_MAX)
- **AND** the summary must not exceed 30,000 bytes (PROPOSAL_SUMMARY_BYTES_MAX)
- **AND** the URL must not exceed 2,048 characters (PROPOSAL_URL_CHAR_MAX)
- **AND** for motion proposals, the motion_text must not exceed 10,000 bytes (PROPOSAL_MOTION_TEXT_BYTES_MAX)

#### Scenario: Proposal listing
- **WHEN** `list_proposals` is called
- **THEN** at most 100 proposals are returned per call (MAX_LIST_PROPOSAL_RESULTS)
- **AND** proposals with payloads exceeding 1 KB have their payloads excluded from the response (EXECUTE_NERVOUS_SYSTEM_FUNCTION_PAYLOAD_LISTING_BYTES_MAX)
- **AND** ballots are limited to 100 per proposal in list responses (MAX_NUMBER_OF_BALLOTS_IN_LIST_PROPOSALS_RESPONSE)

#### Scenario: Maximum proposals with ballots
- **WHEN** the number of unsettled proposals (with active ballots) reaches 700
- **THEN** no additional proposals can be submitted until existing proposals are settled (MAX_NUMBER_OF_PROPOSALS_WITH_BALLOTS)

#### Scenario: Proposal allowed during low resources
- **WHEN** the governance canister's heap growth potential is low
- **THEN** only proposals whose actions are marked as `allowed_when_resources_are_low` can be submitted

#### Scenario: Proposal rejection cost
- **WHEN** a proposal is rejected
- **THEN** the reject_cost_e8s (default: 1 governance token) is deducted from the proposer's neuron

### Requirement: Voting and Decision Making

Voting determines the outcome of proposals. The system supports both direct voting and following-based delegation.

#### Scenario: Wait-for-quiet mechanism
- **WHEN** a vote is cast that changes the proposal's trajectory near the deadline
- **THEN** the voting deadline is extended by `wait_for_quiet_deadline_increase_seconds`
- **AND** the extension is bounded by the initial voting period

#### Scenario: Proposal adoption thresholds (normal proposals)
- **WHEN** a normal (non-critical) proposal is being evaluated
- **THEN** it requires at least 3% of total voting power as "yes" votes (DEFAULT_MINIMUM_YES_PROPORTION_OF_TOTAL_VOTING_POWER = 300bp)
- **AND** at least 50% of exercised voting power as "yes" votes (DEFAULT_MINIMUM_YES_PROPORTION_OF_EXERCISED_VOTING_POWER = 5000bp)

#### Scenario: Proposal adoption thresholds (critical proposals)
- **WHEN** a critical proposal is being evaluated
- **THEN** it requires at least 20% of total voting power as "yes" votes (CRITICAL_MINIMUM_YES_PROPORTION_OF_TOTAL_VOTING_POWER = 2000bp)
- **AND** at least 67% of exercised voting power as "yes" votes (CRITICAL_MINIMUM_YES_PROPORTION_OF_EXERCISED_VOTING_POWER = 6700bp)

#### Scenario: Initial voting period
- **WHEN** a proposal's voting period is set
- **THEN** it must be between 1 day (INITIAL_VOTING_PERIOD_SECONDS_FLOOR) and 30 days (INITIAL_VOTING_PERIOD_SECONDS_CEILING)
- **AND** the default is 4 days

### Requirement: Following (Vote Delegation)

Neurons can follow other neurons on specific topics or function IDs, enabling automatic voting through delegation.

#### Scenario: Topic-based following
- **WHEN** a neuron sets following for a specific topic
- **THEN** up to 15 followees can be specified per topic (MAX_FOLLOWEES_PER_TOPIC)
- **AND** when a followee votes, the follower automatically casts the same vote

#### Scenario: Catch-all following does not apply to critical proposals
- **WHEN** a neuron has catch-all/fallback following configured
- **AND** a critical proposal (e.g., TransferSnsTreasuryFunds) is submitted
- **THEN** the catch-all following does NOT cascade to the critical proposal
- **AND** only topic-specific following for that critical topic is applied

#### Scenario: Topic-specific following on critical proposals
- **WHEN** a neuron follows another neuron specifically on a critical topic
- **AND** the followee votes on a proposal with that critical topic
- **THEN** the vote cascades to the follower normally

#### Scenario: Followee alias management
- **WHEN** a followee is assigned an alias
- **THEN** the alias must not exceed 128 bytes (MAX_NEURON_ALIAS_BYTES)
- **AND** each neuron ID must have at most one alias (i.e., the same neuron cannot have two different aliases)

### Requirement: Proposal Actions

The governance canister supports a comprehensive set of native proposal actions, each identified by a unique numeric ID.

#### Scenario: Native action types
- **WHEN** the governance canister is initialized
- **THEN** the following native actions are available:
  - Motion (1)
  - ManageNervousSystemParameters (2)
  - UpgradeSnsControlledCanister (3)
  - AddGenericNervousSystemFunction (4)
  - RemoveGenericNervousSystemFunction (5)
  - ExecuteGenericNervousSystemFunction (6)
  - UpgradeSnsToNextVersion (7)
  - ManageSnsMetadata (8)
  - TransferSnsTreasuryFunds (9)
  - RegisterDappCanisters (10)
  - DeregisterDappCanisters (11)
  - MintSnsTokens (12)
  - ManageLedgerParameters (13)
  - ManageDappCanisterSettings (14)
  - AdvanceSnsTargetVersion (15)
  - SetTopicsForCustomProposals (16)
  - RegisterExtension (17)
  - ExecuteExtensionOperation (18)
  - UpgradeExtension (19)

#### Scenario: Generic nervous system functions
- **WHEN** a generic nervous system function is added via proposal
- **THEN** up to 200,000 generic functions can be registered (MAX_NUMBER_OF_GENERIC_NERVOUS_SYSTEM_FUNCTIONS)
- **AND** deleted function IDs cannot be recycled (deletion markers are preserved in id_to_nervous_system_functions)

#### Scenario: Dapp management proposals scope limit
- **WHEN** a RegisterDappCanisters, DeregisterDappCanisters, or ManageDappCanisterSettings proposal is submitted
- **THEN** it can manage at most 1,000 dapp canisters per proposal (MAX_NUMBER_OF_DAPPS_TO_MANAGE_PER_PROPOSAL)

### Requirement: Topics

Proposals are categorized into topics that affect voting behavior and criticality.

#### Scenario: Topic categorization
- **WHEN** topics are listed
- **THEN** seven topics are returned:
  - DaoCommunitySettings (critical) - tokenomics, branding, parameters
  - SnsFrameworkManagement - upgrade and manage the SNS framework
  - DappCanisterManagement - upgrade registered dapp canisters
  - ApplicationBusinessLogic - custom dapp proposals
  - Governance - community polls (motion proposals)
  - TreasuryAssetManagement (critical) - move and manage DAO-owned assets
  - CriticalDappOperations (critical) - deregister dapps, manage functions, extensions

### Requirement: Treasury Management

The governance canister manages treasury operations including token transfers and minting.

#### Scenario: Treasury transfer proposals retained for 7 days
- **WHEN** a TransferSnsTreasuryFunds proposal is successfully executed
- **THEN** it is retained for 7 days (EXECUTED_TRANSFER_SNS_TREASURY_FUNDS_PROPOSAL_RETENTION_DURATION_SECONDS)
- **AND** this retention is used to enforce 7-day rolling limits on treasury transfers

#### Scenario: Mint SNS tokens proposals retained for 7 days
- **WHEN** a MintSnsTokens proposal is successfully executed
- **THEN** it is retained for 7 days (EXECUTED_MINT_SNS_TOKENS_PROPOSAL_RETENTION_DURATION_SECONDS)

#### Scenario: Treasury valuation
- **WHEN** a treasury transfer is proposed
- **THEN** a valuation is computed considering token balance, ICP-per-token price, and XDR-per-ICP price
- **AND** the valuation is stored as action auxiliary data on the proposal

### Requirement: Voting Rewards

Voting rewards are distributed to neurons that participate in governance.

#### Scenario: Reward rate schedule
- **WHEN** the reward rate is calculated at a given point in time
- **THEN** it transitions linearly from `initial_reward_rate_basis_points` to `final_reward_rate_basis_points`
- **AND** the transition takes `reward_rate_transition_duration_seconds` to complete
- **AND** the initial reward rate ceiling is 10,000 basis points (100%)

#### Scenario: Reward round duration
- **WHEN** the reward round duration is configured
- **THEN** it must be between 1 second and 1 year (MAX_REWARD_ROUND_DURATION_SECONDS)

#### Scenario: Maturity modulation
- **WHEN** maturity modulation is applied to reward disbursement
- **THEN** the modulation is obtained from the Cycles Minting Canister
- **AND** if `maturity_modulation_disabled` is set in parameters, a modulation of 0 is used instead

### Requirement: SNS Upgrade Management

The governance canister orchestrates the upgrade of all SNS canisters.

#### Scenario: Upgrade steps caching
- **WHEN** the governance canister refreshes its upgrade steps
- **THEN** it queries the SNS-WASM canister for the upgrade path
- **AND** the cache is refreshed every 1 hour (UPGRADE_STEPS_INTERVAL_REFRESH_BACKOFF_SECONDS)

#### Scenario: Upgrade proposal blocking
- **WHEN** an adopted-but-not-yet-executed upgrade proposal exists
- **THEN** it blocks other upgrade proposals from executing
- **AND** this blocking expires after 1 day (UPGRADE_PROPOSAL_BLOCK_EXPIRY_SECONDS) to prevent permanent deadlock

#### Scenario: Upgrade periodic task lock
- **WHEN** a periodic upgrade task is running
- **THEN** the lock is automatically released after 10 minutes (UPGRADE_PERIODIC_TASK_LOCK_TIMEOUT_SECONDS)
- **AND** this prevents interleaving of upgrade-related periodic tasks

### Requirement: Nervous System Parameters Validation

Nervous system parameters define the operational boundaries of governance.

#### Scenario: Parameter bounds
- **WHEN** nervous system parameters are validated
- **THEN** max_proposals_to_keep_per_action must not exceed 700
- **AND** max_number_of_neurons must not exceed 200,000
- **AND** max_number_of_proposals_with_ballots must not exceed 700
- **AND** max_followees_per_function must not exceed 15
- **AND** max_number_of_principals_per_neuron must be between 5 and 15
- **AND** max_dissolve_delay_bonus_percentage must not exceed 900%
- **AND** max_age_bonus_percentage must not exceed 400%

#### Scenario: Required claimer permissions
- **WHEN** `neuron_claimer_permissions` are validated
- **THEN** they must include ManagePrincipals, Vote, and SubmitProposal at minimum

#### Scenario: Default parameter values
- **WHEN** nervous system parameters are created with defaults
- **THEN** reject_cost_e8s is 1 governance token (10^8 e8s)
- **AND** neuron_minimum_stake_e8s is 1 governance token
- **AND** initial_voting_period_seconds is 4 days
- **AND** wait_for_quiet_deadline_increase_seconds is 1 day
- **AND** max_number_of_neurons is 200,000

### Requirement: Extensions

SNS Governance supports registering and operating extensions -- additional canisters that extend SNS functionality.

#### Scenario: Extension feature flag
- **WHEN** the SNS_EXTENSIONS_ENABLED flag is checked
- **THEN** it defaults to true
- **AND** extensions can be temporarily enabled/disabled in tests

#### Scenario: Extension registration via allowlist
- **WHEN** a RegisterExtension proposal is submitted
- **THEN** the extension's WASM hash must match an entry in the allowed extensions list
- **AND** the extension is installed and controlled by both Root and Governance

#### Scenario: Extension operations
- **WHEN** an ExecuteExtensionOperation proposal is adopted
- **THEN** the governance canister calls the extension canister with the specified arguments
- **AND** only Treasury Manager extensions are currently supported

### Requirement: Claim Swap Neurons

After a successful swap, the governance canister creates neurons for swap participants.

#### Scenario: Batch neuron claiming
- **WHEN** the swap canister sends `ClaimSwapNeuronsRequest`
- **THEN** neurons are claimed in batches of 500 (CLAIM_SWAP_NEURONS_BATCH_SIZE)
- **AND** this avoids XNET message size limits and instruction limits

#### Scenario: Neurons Fund participant permissions
- **WHEN** neurons are claimed for Neurons' Fund participants
- **THEN** the NNS neuron controller receives ManageVotingPermission, SubmitProposal, and Vote permissions
- **AND** the NNS neuron hotkeys receive SubmitProposal and Vote permissions

### Requirement: Default Followees

Default followees are validated but not currently supported.

#### Scenario: Default followees must be empty
- **WHEN** governance proto is validated
- **THEN** default_followees must be set but its followees map must be empty
- **AND** any non-empty default_followees causes a validation error
