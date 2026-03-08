# Voting and Rewards

The NNS incentivizes participation through voting rewards. Neurons earn rewards proportional to their voting power and participation rate. Rewards are distributed daily as maturity.

## Requirements

### Requirement: Vote Casting
Neurons can cast votes directly or have votes cast automatically via following.

#### Scenario: Direct vote
- **WHEN** a neuron's controller or hot key submits a vote (Yes or No) on a proposal
- **THEN** the vote is recorded in the proposal's ballots
- **AND** cascade follow processing is triggered
- **AND** the proposal tally is recomputed

#### Scenario: Vote eligibility
- **WHEN** a neuron attempts to vote on a proposal
- **THEN** the neuron must have been created before the proposal was submitted
- **AND** the neuron must have a ballot in the proposal's ballots map

#### Scenario: Votes are eligible for rewards
- **WHEN** a vote is Yes or No
- **THEN** the vote is eligible for voting rewards
- **WHEN** a vote is Unspecified
- **THEN** the vote is not eligible for rewards

### Requirement: Voting State Machine
The voting system uses a state machine architecture that processes votes across message boundaries to avoid instruction limits.

#### Scenario: Vote processing with instruction limits
- **WHEN** a vote is cast
- **THEN** the vote is recorded in the voting state machine
- **AND** cascade follow processing continues until either voting is finished or the soft instruction limit (1 billion instructions) is reached
- **AND** if the soft limit is reached, processing continues in the next message via self-call
- **AND** if the hard limit (750 billion instructions) is reached, remaining processing moves to timer jobs

#### Scenario: Background vote processing
- **WHEN** timer tasks run
- **THEN** unfinished voting state machines are processed
- **AND** tallies are recomputed for proposals with new votes
- **AND** decided proposals are processed

### Requirement: Tally Recomputation
After votes are cast, the proposal tally is recomputed.

#### Scenario: Tally counts
- **WHEN** a proposal tally is recomputed
- **THEN** yes is the sum of voting power of all Yes ballots
- **AND** no is the sum of voting power of all No ballots
- **AND** total is the sum of voting power of all ballots (yes + no + undecided)

#### Scenario: Proposal decided by majority
- **WHEN** yes votes > total / 2
- **THEN** the proposal is accepted (adopted)
- **WHEN** no votes >= ceil(total / 2)
- **THEN** the proposal is rejected (adoption becomes impossible)

### Requirement: Reward Rate Calculation
The reward rate decreases over time from 10% per year at genesis to 5% per year after 8 years.

#### Scenario: Reward rate at genesis
- **WHEN** calculating rewards at IC genesis
- **THEN** the reward rate is INITIAL_VOTING_REWARD_RELATIVE_RATE (10% per year / 365.25 days)

#### Scenario: Reward rate after 8 years
- **WHEN** calculating rewards at or after REWARD_FLATTENING_DATE (8 years * 365.25 days)
- **THEN** the reward rate is FINAL_VOTING_REWARD_RELATIVE_RATE (5% per year / 365.25 days)

#### Scenario: Reward rate between genesis and 8 years
- **WHEN** calculating rewards between genesis and 8 years
- **THEN** the reward rate follows a quadratic curve: R(t) = Rf + (R0 - Rf) * [(t - T) / (G - T)]^2
- **AND** the curve is differentiable at the flattening date (smooth transition)
- **AND** the rate decreases monotonically

### Requirement: Reward Distribution Period
Rewards are distributed daily.

#### Scenario: Reward distribution period
- **WHEN** rewards are distributed
- **THEN** no two consecutive reward events happen with less than REWARD_DISTRIBUTION_PERIOD_SECONDS (1 day) between them

### Requirement: Reward Pool Calculation
The daily reward pool is calculated as a fraction of the total ICP supply.

#### Scenario: Daily reward pool
- **WHEN** the daily reward pool is calculated for a given day since genesis
- **THEN** it equals the supply fraction rate for that day times the total ICP supply
- **AND** rewards not distributed (e.g., due to no settled proposals) are rolled over

### Requirement: Reward Rollover
When no proposals settle in a reward period, the rewards are rolled over.

#### Scenario: Rewards rolled over when no proposals settle
- **WHEN** a reward event has no settled proposals
- **THEN** the total_available_e8s_equivalent is rolled over to the next event
- **AND** rounds_since_last_distribution is rolled over

#### Scenario: Rewards not rolled over after distribution
- **WHEN** a reward event has settled proposals
- **THEN** nothing is rolled over (e8s_equivalent_to_be_rolled_over returns 0)

### Requirement: Reward Distribution to Neurons
Rewards are distributed to individual neurons as maturity based on their voting participation and voting power.

#### Scenario: Rewards distributed as maturity
- **WHEN** rewards are distributed to a neuron
- **AND** auto_stake_maturity is false or unset
- **THEN** the reward is added to maturity_e8s_equivalent

#### Scenario: Rewards auto-staked
- **WHEN** rewards are distributed to a neuron
- **AND** auto_stake_maturity is true
- **THEN** the reward is added to staked_maturity_e8s_equivalent

#### Scenario: Reward distribution uses state machine
- **WHEN** a reward distribution is scheduled
- **THEN** it is added to the RewardsDistributionStateMachine
- **AND** it is processed across multiple messages respecting instruction limits (1 billion per message)
- **AND** each neuron's reward is applied atomically

### Requirement: Maturity Disbursement
Neuron maturity can be disbursed (converted to ICP) with a 7-day delay and subject to maturity modulation.

#### Scenario: Initiate maturity disbursement
- **WHEN** a neuron controller initiates a maturity disbursement
- **AND** the percentage is between 1 and 100
- **AND** the neuron is not spawning
- **AND** the number of in-progress disbursements is less than MAX_NUM_DISBURSEMENTS (10)
- **AND** the disbursement amount is at least MINIMUM_DISBURSEMENT_E8S (1 ICP)
- **THEN** a MaturityDisbursement record is created
- **AND** the disbursement_maturity_e8s is deducted from the neuron's maturity
- **AND** the disbursement will be finalized after DISBURSEMENT_DELAY_SECONDS (7 days)

#### Scenario: Disbursement finalization
- **WHEN** the 7-day delay has passed
- **THEN** maturity modulation is applied to determine the actual ICP amount
- **AND** the ICP is minted to the specified destination account

#### Scenario: Disbursement destination
- **WHEN** no destination is specified
- **THEN** the ICP is sent to the caller's default account
- **WHEN** an Account is specified
- **THEN** the ICP is sent to that ICRC-1 account
- **WHEN** an AccountIdentifier is specified
- **THEN** the ICP is sent to that account identifier
- **WHEN** both Account and AccountIdentifier are specified
- **THEN** the disbursement fails with an error

#### Scenario: Disbursement too small
- **WHEN** the disbursement amount (accounting for worst-case maturity modulation) is less than MINIMUM_DISBURSEMENT_E8S
- **THEN** the disbursement is rejected

#### Scenario: Too many disbursements
- **WHEN** a neuron already has MAX_NUM_DISBURSEMENTS (10) disbursements in progress
- **THEN** new disbursement requests are rejected

### Requirement: Maturity Modulation
Maturity modulation adjusts the conversion rate between maturity and ICP.

#### Scenario: Maturity modulation range
- **WHEN** maturity modulation is applied
- **THEN** the modulation is within VALID_MATURITY_MODULATION_BASIS_POINTS_RANGE (-500 to +500 basis points)
- **AND** this means the actual ICP minted can vary by +/- 5% from the maturity amount

### Requirement: Voting Power Snapshots
Periodic snapshots of neuron voting power are taken for reward computation.

#### Scenario: Voting power snapshots taken
- **WHEN** the snapshot_voting_power timer task runs
- **THEN** a snapshot of all neuron voting powers is stored in VOTING_POWER_SNAPSHOTS stable storage
- **AND** these snapshots are used for reward calculations
