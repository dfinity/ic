# Neurons

Neurons are the fundamental unit of governance participation in the NNS. They are created by locking ICP tokens and provide voting power proportional to their stake, dissolve delay, and age. Neurons earn rewards for participating in governance.

## Requirements

### Requirement: Neuron Creation
A neuron is created by transferring ICP tokens to a governance-controlled ledger account. The neuron must meet minimum stake requirements and is assigned a random subaccount.

#### Scenario: Create neuron with defaults
- **WHEN** a user calls create_neuron with a valid amount
- **THEN** a random subaccount is generated for the neuron
- **AND** a unique neuron ID is assigned
- **AND** the ICP is transferred from the caller's account via icrc2_transfer_from
- **AND** the neuron is created with the default dissolve delay of 7 days (INITIAL_NEURON_DISSOLVE_DELAY)
- **AND** the neuron controller is set to the caller
- **AND** the neuron's created_timestamp_seconds is set to the current time
- **AND** the neuron's aging_since_timestamp_seconds is set to the current time

#### Scenario: Create neuron with custom parameters
- **WHEN** a user calls create_neuron with custom dissolve_delay_seconds, controller, followees, dissolving flag, and auto_stake_maturity
- **THEN** the neuron is created with the specified parameters
- **AND** the dissolve delay must be between INITIAL_NEURON_DISSOLVE_DELAY (7 days) and MAX_DISSOLVE_DELAY_SECONDS (8 years)

#### Scenario: Neuron creation fails below minimum stake
- **WHEN** the amount_e8s is less than neuron_minimum_stake_e8s (default: 1 ICP)
- **THEN** the creation fails with InsufficientFunds error

#### Scenario: Neuron creation fails with invalid source subaccount
- **WHEN** the source_subaccount is not exactly 32 bytes
- **THEN** the creation fails with InvalidCommand error

### Requirement: Neuron Identity
Each neuron has a unique ID, a subaccount on the ICP ledger, a controller principal, and optional hot keys.

#### Scenario: Neuron controller authorization
- **WHEN** an operation requires controller privileges (e.g., disburse, set dissolving)
- **THEN** only the neuron's controller principal can perform it

#### Scenario: Hot key authorization
- **WHEN** a non-privileged operation is attempted (e.g., vote, follow)
- **THEN** both the controller and any hot keys can perform it
- **AND** a neuron can have at most MAX_NUM_HOT_KEYS_PER_NEURON (10) hot keys

### Requirement: Neuron Visibility
Neurons have a visibility setting that controls how much unprivileged principals can see.

#### Scenario: Known neurons are always public
- **WHEN** a neuron has known_neuron_data set
- **THEN** its visibility is treated as Public regardless of the visibility field

#### Scenario: Private neurons hide details
- **WHEN** a neuron's visibility is Private
- **THEN** unprivileged principals cannot see detailed neuron information

### Requirement: Neuron Dissolve State
A neuron has one of three states: NotDissolving, Dissolving, or Dissolved. The state is determined by the dissolve_state_and_age enum and the current time.

#### Scenario: Not dissolving neuron
- **WHEN** a neuron is NotDissolving
- **THEN** it has a dissolve_delay_seconds greater than 0
- **AND** it has an aging_since_timestamp_seconds tracking when it started aging
- **AND** its age increases over time

#### Scenario: Dissolving neuron
- **WHEN** a neuron is DissolvingOrDissolved with when_dissolved_timestamp_seconds in the future
- **THEN** its state is Dissolving
- **AND** its dissolve delay decreases over time
- **AND** its age is 0

#### Scenario: Dissolved neuron
- **WHEN** a neuron is DissolvingOrDissolved with when_dissolved_timestamp_seconds in the past or at now
- **THEN** its state is Dissolved
- **AND** its dissolve delay is 0
- **AND** it can be disbursed

#### Scenario: Spawning neuron
- **WHEN** a neuron has spawn_at_timestamp_seconds set
- **THEN** its state is Spawning regardless of dissolve state

### Requirement: Start Dissolving
A non-dissolving neuron can be placed into dissolve mode by its controller.

#### Scenario: Start dissolving a non-dissolving neuron
- **WHEN** start_dissolving is called on a NotDissolving neuron
- **THEN** the neuron transitions to DissolvingOrDissolved
- **AND** when_dissolved_timestamp_seconds is set to now + dissolve_delay_seconds
- **AND** the neuron's age resets (aging_since_timestamp_seconds becomes irrelevant)

#### Scenario: Start dissolving on already dissolving neuron is a no-op
- **WHEN** start_dissolving is called on a Dissolving or Dissolved neuron
- **THEN** no change occurs

### Requirement: Stop Dissolving
A dissolving neuron can be stopped by its controller, returning it to a non-dissolving state.

#### Scenario: Stop dissolving a dissolving neuron
- **WHEN** stop_dissolving is called on a Dissolving neuron with remaining delay > 0
- **THEN** the neuron transitions to NotDissolving
- **AND** dissolve_delay_seconds is set to the remaining time until dissolution
- **AND** aging_since_timestamp_seconds is set to now

#### Scenario: Stop dissolving on a dissolved neuron is a no-op
- **WHEN** stop_dissolving is called on a Dissolved neuron (remaining delay is 0)
- **THEN** no change occurs

### Requirement: Increase Dissolve Delay
Neuron owners can increase dissolve delay up to MAX_DISSOLVE_DELAY_SECONDS (8 years).

#### Scenario: Increase dissolve delay of non-dissolving neuron
- **WHEN** increase_dissolve_delay is called with additional_dissolve_delay_seconds > 0
- **AND** the neuron is NotDissolving
- **THEN** dissolve_delay_seconds increases by the specified amount
- **AND** the new delay is capped at MAX_DISSOLVE_DELAY_SECONDS (8 years)
- **AND** the aging_since_timestamp_seconds remains unchanged

#### Scenario: Increase dissolve delay of dissolving neuron
- **WHEN** increase_dissolve_delay is called on a Dissolving neuron
- **THEN** when_dissolved_timestamp_seconds is increased
- **AND** the effective new delay is capped at MAX_DISSOLVE_DELAY_SECONDS

#### Scenario: Increase dissolve delay of dissolved neuron transitions to non-dissolving
- **WHEN** increase_dissolve_delay is called on a Dissolved neuron
- **THEN** the neuron transitions to NotDissolving
- **AND** dissolve_delay_seconds is set to the additional amount (capped)
- **AND** aging_since_timestamp_seconds is set to now

#### Scenario: Zero additional delay is a no-op
- **WHEN** increase_dissolve_delay is called with additional_dissolve_delay_seconds = 0
- **THEN** no change occurs

### Requirement: Neuron Voting Power
Voting power is computed from the neuron's stake, dissolve delay bonus, and age bonus.

#### Scenario: Potential voting power calculation
- **WHEN** potential voting power is computed
- **THEN** the base is the neuron's stake (cached_neuron_stake_e8s - neuron_fees_e8s + staked_maturity_e8s_equivalent)
- **AND** a dissolve delay bonus of up to 100% is applied (linear from 0 at 0 delay to 100% at 8 years)
- **AND** an age bonus of up to 25% is applied on top (linear from 0 at age 0 to 25% at 4 years, MAX_NEURON_AGE_FOR_AGE_BONUS)

#### Scenario: Deciding voting power adjustment
- **WHEN** deciding voting power is computed
- **THEN** an adjustment factor is applied based on time since last voting power refresh
- **AND** the adjustment factor starts at 1.0 when recently refreshed
- **AND** the adjustment factor decreases to 0.0 after the configured period of inactivity
- **AND** voting power is refreshed by voting directly or setting following

### Requirement: Following (Liquid Democracy)
Neurons can be configured to follow other neurons on specific topics, enabling automatic voting.

#### Scenario: Set following for a topic
- **WHEN** a neuron sets followees for a specific topic
- **THEN** the neuron will automatically vote on proposals of that topic
- **AND** at most MAX_FOLLOWEES_PER_TOPIC (15) followees can be set per topic

#### Scenario: Catch-all following
- **WHEN** a neuron sets followees for the Unspecified topic
- **THEN** those followees are used for any topic where specific followees are not defined

#### Scenario: Automatic vote via following (majority yes)
- **WHEN** more than half of a neuron's followees on a topic vote Yes
- **THEN** the neuron automatically votes Yes

#### Scenario: Automatic vote via following (majority no or impossible yes)
- **WHEN** half or more of a neuron's followees on a topic vote No (making Yes impossible by majority)
- **THEN** the neuron automatically votes No

#### Scenario: Following cascade
- **WHEN** a neuron votes (directly or via following)
- **THEN** its vote triggers cascade evaluation for neurons that follow it
- **AND** the cascade continues until no more votes are cast
- **AND** voting state machines process the cascade across messages to avoid instruction limits

### Requirement: Following Pruning
Following relationships are pruned for neurons that have not refreshed their voting power.

#### Scenario: Stale following pruned
- **WHEN** a neuron has not refreshed voting power within the configured timeframe (start_reducing_voting_power_after_seconds + clear_following_after_seconds)
- **THEN** all following is cleared except for NeuronManagement topic following
- **AND** the neuron's deciding voting power is reduced to 0

### Requirement: Neuron Merge
Two neurons can be merged, combining their stake, maturity, and age.

#### Scenario: Successful neuron merge
- **WHEN** merge is requested for source and target neurons
- **AND** both neurons are NotDissolving with dissolve delay > 0
- **AND** both neurons have the same controller (as caller)
- **AND** both neurons have the same neuron managers, KYC status, not_for_profit status, and neuron type
- **AND** neither neuron is spawning or in the Neurons' Fund
- **AND** neither neuron is involved in an open proposal
- **THEN** stake is transferred from source to target (via ledger)
- **AND** neuron fees on the source are burned first
- **AND** maturity is transferred from source to target
- **AND** staked maturity is transferred from source to target
- **AND** the combined age is computed proportional to stake

#### Scenario: Merge fails for dissolving neurons
- **WHEN** either source or target neuron is Dissolving or Dissolved
- **THEN** the merge fails with RequiresNotDissolving error

#### Scenario: Merge fails for same source and target
- **WHEN** source and target neuron IDs are the same
- **THEN** the merge fails with InvalidCommand error

#### Scenario: Merge fails for Neurons' Fund members
- **WHEN** either neuron is a member of the Neurons' Fund
- **THEN** the merge fails with PreconditionFailed error

### Requirement: Neuron Split
A neuron can be split into two neurons, transferring a portion of stake and maturity to a new child neuron.

#### Scenario: Successful neuron split
- **WHEN** split is requested with a valid amount
- **THEN** a new child neuron is created
- **AND** the specified stake amount is transferred to the child
- **AND** maturity is split proportionally to the stake ratio (split_amount / parent_stake)
- **AND** staked maturity is split proportionally to the stake ratio
- **AND** the child inherits the parent's dissolve delay and followees

#### Scenario: Split preserves invariants
- **WHEN** split maturity and staked_maturity are calculated
- **THEN** transfer_maturity_e8s is always <= source_neuron_maturity_e8s
- **AND** transfer_staked_maturity_e8s is always <= source_neuron_staked_maturity_e8s

### Requirement: Combine Aged Stakes
When combining two stakes with different ages, the resulting age is a weighted average.

#### Scenario: Combined age calculation
- **WHEN** two stakes with different ages are combined
- **THEN** the combined age is (x_stake * x_age + y_stake * y_age) / (x_stake + y_stake)
- **AND** the combined stake is x_stake + y_stake
- **AND** the combined age is always between the two input ages

#### Scenario: Both stakes zero
- **WHEN** both stakes are zero
- **THEN** the combined stake is 0 and age is 0

### Requirement: Neuron Stake
The neuron's effective stake is computed from its cached fields.

#### Scenario: Effective stake calculation
- **WHEN** the neuron stake is computed
- **THEN** it is cached_neuron_stake_e8s minus neuron_fees_e8s plus staked_maturity_e8s_equivalent

### Requirement: Recent Ballots
Each neuron maintains a circular buffer of recent voting activity.

#### Scenario: Recent ballots stored
- **WHEN** a neuron votes on a proposal
- **THEN** the vote is recorded in the neuron's recent_ballots
- **AND** at most MAX_NEURON_RECENT_BALLOTS (100) ballots are kept
- **AND** oldest ballots are overwritten

### Requirement: Maturity Auto-Staking
Neurons can be configured to automatically stake maturity rewards.

#### Scenario: Auto stake maturity enabled
- **WHEN** a neuron has auto_stake_maturity set to true
- **AND** rewards are distributed to the neuron
- **THEN** the reward is added to staked_maturity_e8s_equivalent instead of maturity_e8s_equivalent

#### Scenario: Auto stake maturity disabled
- **WHEN** a neuron has auto_stake_maturity set to false or unset
- **AND** rewards are distributed
- **THEN** the reward is added to maturity_e8s_equivalent

### Requirement: Maturity Unstaking on Dissolution
When a neuron is dissolved, its staked maturity is converted to regular maturity.

#### Scenario: Staked maturity unstaked on dissolution
- **WHEN** a neuron is in Dissolved state
- **AND** it has staked_maturity_e8s_equivalent > 0
- **THEN** the staked maturity is moved to maturity_e8s_equivalent
- **AND** staked_maturity_e8s_equivalent is set to 0

### Requirement: Neurons' Fund Membership
Neurons can join the Neurons' Fund (formerly Community Fund) to participate in SNS swaps.

#### Scenario: Neuron is a Neurons' Fund member
- **WHEN** a neuron has joined_community_fund_timestamp_seconds > 0
- **THEN** the neuron is a member of the Neurons' Fund
- **AND** its maturity may be used to participate in SNS token swaps
- **AND** it cannot be merged with other neurons

### Requirement: Neuron Locking
Neurons are locked during operations that involve ledger interactions to prevent interleaving.

#### Scenario: Neuron locked during async operation
- **WHEN** an async operation (e.g., disburse, merge, create) is in progress for a neuron
- **THEN** a NeuronInFlightCommand is recorded
- **AND** no other async operations can start for that neuron
- **AND** the lock is released when the operation completes (via Drop)
- **AND** if a trap occurs, the lock is retained to prevent further operations until investigation
