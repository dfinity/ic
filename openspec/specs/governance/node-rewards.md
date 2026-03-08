# Node Rewards

**Crates**: `ic-node-rewards-canister`, `ic-node-rewards-canister-api`, `rewards-calculation`

The node rewards system calculates and distributes rewards to node providers for hosting nodes on the Internet Computer. It uses a performance-based algorithm that accounts for node failure rates, subnet-level metrics, and reward tables from the registry.

## Requirements

### Requirement: Node Rewards Canister Identity
The Node Rewards canister is installed at index 16 on the NNS subnet with canister ID `sgymv-uiaaa-aaaaa-aaaia-cai`.

#### Scenario: Node Rewards canister has a fixed canister ID
- **WHEN** the Node Rewards canister is deployed
- **THEN** it is assigned index 16 on the NNS subnet

### Requirement: Performance-Based Reward Algorithm
Node rewards are calculated using a versioned performance-based algorithm. The algorithm is designed for historical reproducibility -- past calculations must remain verifiable.

#### Scenario: Algorithm versioning
- **WHEN** a new reward algorithm is needed
- **THEN** a new version (e.g., V2) is created implementing the PerformanceBasedAlgorithm trait
- **AND** existing versions (V1, V2) are never modified to preserve historical reproducibility
- **AND** each version has a VERSION constant identifying it

### Requirement: Reward Calculation Period
Rewards are calculated over a date range, processing each day individually.

#### Scenario: Multi-day reward calculation
- **WHEN** calculate_rewards is called with from_date and to_date
- **AND** from_date <= to_date
- **THEN** each day in the range is processed independently
- **AND** daily rewards per provider are accumulated into total_rewards_xdr_permyriad
- **AND** both daily and total results are returned in RewardsCalculatorResults

#### Scenario: Invalid date range
- **WHEN** from_date > to_date
- **THEN** the calculation returns an error "from_day must be before to_day"

### Requirement: Reward Period Duration
The reward period corresponds to approximately one month.

#### Scenario: Reward period days
- **WHEN** the reward period is calculated
- **THEN** REWARDS_TABLE_DAYS is 30.4375 days (derived from NODE_PROVIDER_REWARD_PERIOD_SECONDS / SECONDS_IN_DAY)

### Requirement: Daily Reward Calculation Steps
Each day's reward calculation follows a multi-step process.

#### Scenario: Daily calculation pipeline
- **WHEN** daily rewards are calculated for a date
- **THEN** Step 1: Reward tables are loaded from the registry for that date
- **AND** Step 2: Daily node metrics by subnet are loaded
- **AND** Step 3: Rewardable nodes per provider are loaded
- **AND** Step 4: Subnet and node failure rates are calculated
- **AND** Step 5: Per-provider rewards are calculated

### Requirement: Subnet Failure Rate Calculation
Subnet failure rates are calculated using a percentile of individual node failure rates within the subnet.

#### Scenario: V1 subnet failure rate percentile
- **WHEN** calculating subnet failure rate in V1
- **THEN** the 75th percentile (SUBNET_FAILURE_RATE_PERCENTILE = 0.75) of node failure rates is used
- **AND** node failure rate = num_blocks_failed / (num_blocks_proposed + num_blocks_failed)

#### Scenario: Subnet failure rate computation
- **WHEN** a subnet has nodes with failure rates [0.05, 0.10, 0.25, 0.50]
- **THEN** sorted failure rates are [0.05, 0.10, 0.25, 0.50]
- **AND** the 75th percentile index is ceil(4 * 0.75) - 1 = 2
- **AND** the subnet failure rate is 0.25

### Requirement: Relative Node Failure Rate
Individual node failure rates are adjusted relative to their subnet's failure rate.

#### Scenario: Relative failure rate calculation
- **WHEN** a node has an original failure rate
- **THEN** its relative failure rate = max(0, original_failure_rate - subnet_failure_rate)
- **AND** nodes performing at or better than the subnet norm have relative failure rate of 0

#### Scenario: Node in multiple subnets same day
- **WHEN** a node appears in metrics for multiple subnets on the same day
- **THEN** only the subnet with more total blocks (proposed + failed) is used for that node

### Requirement: Performance Multiplier
The performance multiplier penalizes nodes with high relative failure rates.

#### Scenario: V1 failure rate thresholds
- **WHEN** calculating the performance multiplier in V1
- **THEN** MIN_FAILURE_RATE is 0.1 (nodes below this are not penalized)
- **AND** MAX_FAILURE_RATE is 0.6 (nodes above this get maximum penalty)
- **AND** MIN_REWARDS_REDUCTION is 0 (minimum penalty)
- **AND** MAX_REWARDS_REDUCTION is 0.8 (maximum 80% reduction)

#### Scenario: Node below minimum failure rate
- **WHEN** a node's relative failure rate is below MIN_FAILURE_RATE (0.1)
- **THEN** the node receives no penalty (performance multiplier = 1.0)

#### Scenario: Node above maximum failure rate
- **WHEN** a node's relative failure rate is above MAX_FAILURE_RATE (0.6)
- **THEN** the node receives maximum penalty (MAX_REWARDS_REDUCTION = 0.8, multiplier = 0.2)

### Requirement: Base Rewards from Rewards Table
Base rewards for each node are determined by the node's type and geographic region, using the registry's NodeRewardsTable.

#### Scenario: Base rewards lookup
- **WHEN** base rewards are calculated for a node
- **THEN** the rewards table is queried for the node's reward type and region
- **AND** Type 3 nodes have separate region-based base rewards

### Requirement: Extrapolated Failure Rate for Unassigned Nodes
Nodes not assigned to any subnet use an extrapolated failure rate.

#### Scenario: Unassigned node failure rate
- **WHEN** a provider has nodes not assigned to any subnet
- **THEN** the extrapolated failure rate is the average of relative failure rates for the provider's assigned nodes
- **AND** if the provider has no assigned nodes, the extrapolated rate is 0

### Requirement: Adjusted Rewards
Final rewards are the base rewards adjusted by the performance multiplier.

#### Scenario: Adjusted rewards calculation
- **WHEN** adjusted rewards are calculated for a node
- **THEN** adjusted_reward = base_reward * performance_multiplier
- **AND** rewards are expressed in XDR permyriad

### Requirement: Node Rewards Canister Storage
The Node Rewards canister stores metrics and results in stable memory.

#### Scenario: Metrics stored with NaiveDate key
- **WHEN** metrics are stored
- **THEN** NaiveDateStorable is used as the key type
- **AND** dates are stored as 4-byte big-endian i32 (days since CE epoch)
- **AND** SubnetMetricsKey combines timestamp_nanos with subnet_id

#### Scenario: Subnet and node metrics storage
- **WHEN** subnet metrics are stored
- **THEN** SubnetMetricsValue is stored with Unbounded size
- **AND** NodeMetrics includes node_id, num_blocks_proposed_total, and num_blocks_failed_total

### Requirement: Registry Synchronization
The Node Rewards canister synchronizes with the registry for node information and reward tables.

#### Scenario: Registry sync
- **WHEN** the canister periodically syncs with the registry
- **THEN** it fetches the latest node reward types, regions, and reward tables
- **AND** it updates its local view of rewardable nodes per provider

### Requirement: Node Provider Rewards API
The canister exposes APIs for querying rewards.

#### Scenario: Monthly XDR rewards query
- **WHEN** GetNodeProvidersMonthlyXdrRewardsRequest is processed
- **THEN** GetNodeProvidersMonthlyXdrRewardsResponse returns the monthly rewards per provider

#### Scenario: Provider rewards query
- **WHEN** GetNodeProvidersRewardsRequest is processed
- **THEN** GetNodeProvidersRewardsResponse returns detailed rewards information per provider

### Requirement: Governance Integration for Node Provider Rewards
The NNS governance canister records and lists node provider reward history.

#### Scenario: Record node provider rewards
- **WHEN** rewards are calculated and distributed
- **THEN** ArchivedMonthlyNodeProviderRewards entries are stored
- **AND** at most MAX_LIST_NODE_PROVIDER_REWARDS_RESULTS (24) entries are returned when listing

#### Scenario: Node provider reward period
- **WHEN** node provider rewards are distributed
- **THEN** the reward period is NODE_PROVIDER_REWARD_PERIOD_SECONDS (approximately 1 month / 2,629,800 seconds)
