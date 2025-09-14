# Technical Algorithm Specification: RewardsCalculationV1

## Algorithm Overview

The `RewardsCalculationV1` algorithm implements a performance-based reward distribution system for Internet Computer nodes. It calculates daily rewards based on node performance relative to subnet peers using a 75th percentile threshold.

## Core Constants

```rust
const SUBNET_FAILURE_RATE_PERCENTILE: f64 = 0.75;  // 75th percentile
const MIN_FAILURE_RATE: Decimal = 0.1;             // 10% minimum for penalties
const MAX_FAILURE_RATE: Decimal = 0.6;             // 60% maximum penalty threshold
const MIN_REWARDS_REDUCTION: Decimal = 0.0;        // 0% minimum reduction
const MAX_REWARDS_REDUCTION: Decimal = 0.8;        // 80% maximum reduction
const REWARDS_TABLE_DAYS: f64 = 30.4375;           // Average days per month
```

## Data Structures

### Input Data
```rust
struct NodeMetricsDailyRaw {
    node_id: NodeId,
    num_blocks_proposed: u64,
    num_blocks_failed: u64,
}

struct RewardableNode {
    node_id: NodeId,
    node_reward_type: NodeRewardType,
    region: String,
    dc_id: String,
}
```

### Output Data
```rust
struct RewardsCalculatorResults {
    daily_results: BTreeMap<DayUtc, DailyResults>,
}

struct DailyResults {
    subnets_fr: BTreeMap<SubnetId, Decimal>,
    provider_results: BTreeMap<PrincipalId, NodeProviderRewards>,
}

struct NodeResults {
    node_id: NodeId,
    performance_multiplier: Decimal,
    rewards_reduction: Decimal,
    base_rewards: Decimal,
    rewards_total: Decimal,
    region: String,
}
```

## Algorithm Implementation

### Step 1: Failure Rate Calculation

```rust
fn calculate_daily_node_fr(num_blocks_proposed: u64, num_blocks_failed: u64) -> Decimal {
    let total_blocks = Decimal::from(num_blocks_proposed + num_blocks_failed);
    if total_blocks == Decimal::ZERO {
        Decimal::ZERO
    } else {
        let num_blocks_failed = Decimal::from(num_blocks_failed);
        num_blocks_failed / total_blocks
    }
}
```

**Formula**: `failure_rate = num_blocks_failed / (num_blocks_proposed + num_blocks_failed)`

### Step 2: Subnet Performance Calculation (75th Percentile)

```rust
let failure_rates = nodes_fr.iter().sorted().collect::<Vec<_>>();
let index = ((nodes_fr.len() as f64) * SUBNET_FAILURE_RATE_PERCENTILE).ceil() as usize - 1;
let subnet_fr = *failure_rates[index];
```

**Formula**: `index = ceil(n * 0.75) - 1`

### Step 3: Relative Performance Calculation

```rust
let relative_fr = (original_fr - subnet_fr).max(Decimal::ZERO);
```

**Formula**: `relative_fr = max(0, node_fr - subnet_fr)`

### Step 4: Performance Multiplier Calculation

```rust
let performance_multiplier = if relative_fr < Self::MIN_FAILURE_RATE {
    Decimal::ONE
} else if relative_fr >= Self::MAX_FAILURE_RATE {
    Decimal::ONE - Self::MAX_REWARDS_REDUCTION
} else {
    let penalty = (relative_fr - Self::MIN_FAILURE_RATE) 
        / (Self::MAX_FAILURE_RATE - Self::MIN_FAILURE_RATE) 
        * Self::MAX_REWARDS_REDUCTION;
    Decimal::ONE - penalty
};
```

**Formula**:
- If `relative_fr < 0.1`: `multiplier = 1.0`
- If `relative_fr >= 0.6`: `multiplier = 0.2`
- Else: `multiplier = 1.0 - ((relative_fr - 0.1) / 0.5) × 0.8`

### Step 5: Type3 Special Logic

For Type3 and Type3.1 nodes in the same country:

```rust
// Group nodes by continent + country
let mut country_groups: BTreeMap<String, Vec<&RewardableNode>> = BTreeMap::new();
for node in rewardable_nodes {
    let country_key = format!("{},{}", continent, country);
    country_groups.entry(country_key).or_default().push(node);
}

// Calculate average coefficient for each group
for (country, nodes) in country_groups {
    let total_coefficient: Decimal = nodes.iter()
        .map(|n| get_coefficient_for_node(n))
        .sum();
    let avg_coefficient = total_coefficient / Decimal::from(nodes.len());
    
    // Apply coefficient to all nodes in group
    for node in nodes {
        adjusted_rewards = base_rewards * performance_multiplier * avg_coefficient;
    }
}
```

## Mathematical Examples

### Example 1: 4-Node Subnet

**Input Data:**
- Node A: 100 proposed, 1 failed → 0.99% failure rate
- Node B: 100 proposed, 5 failed → 4.76% failure rate  
- Node C: 100 proposed, 20 failed → 16.67% failure rate
- Node D: 100 proposed, 50 failed → 33.33% failure rate

**Calculations:**
1. **Sort failure rates**: [0.99%, 4.76%, 16.67%, 33.33%]
2. **75th percentile index**: `ceil(4 × 0.75) - 1 = 2`
3. **Subnet performance**: 16.67%
4. **Relative performance**:
   - Node A: `max(0, 0.99% - 16.67%) = 0%` → No penalty
   - Node B: `max(0, 4.76% - 16.67%) = 0%` → No penalty
   - Node C: `max(0, 16.67% - 16.67%) = 0%` → No penalty
   - Node D: `max(0, 33.33% - 16.67%) = 16.66%` → Penalty

5. **Performance multipliers**:
   - Nodes A, B, C: 100% (no penalty)
   - Node D: 89.34% (10.66% penalty)

### Example 2: Single Node Subnet

**Input Data:**
- Node: 100 proposed, 10 failed → 9.09% failure rate

**Calculations:**
1. **Subnet performance**: 9.09% (same as node)
2. **Relative performance**: `max(0, 9.09% - 9.09%) = 0%`
3. **Performance multiplier**: 100% (no penalty)

### Example 3: Type3 Grouping

**Input Data:**
- 3 Type3 nodes in California (coefficient: 90%)
- 2 Type3.1 nodes in Nevada (coefficient: 70%)

**Calculations:**
1. **Group by country**: USA (California + Nevada)
2. **Average coefficient**: `(90% × 3 + 70% × 2) ÷ 5 = 82%`
3. **All nodes get**: `base_rewards × performance_multiplier × 82%`

## Edge Cases

### Empty Subnet
- **Subnet failure rate**: 0%
- **All nodes**: No penalty (relative performance = 0%)

### Zero Blocks
- **0 proposed, 0 failed**: 0% failure rate
- **0 proposed, N failed**: 100% failure rate
- **N proposed, 0 failed**: 0% failure rate

### Single Node
- **Subnet failure rate**: Node's failure rate
- **Node penalty**: 0% (relative performance = 0%)

## Performance Characteristics

### Time Complexity
- **O(n log n)** for sorting failure rates
- **O(n)** for percentile calculation
- **O(n)** for relative performance calculation
- **Overall**: O(n log n) where n = number of nodes

### Space Complexity
- **O(n)** for storing failure rates
- **O(n)** for storing results
- **Overall**: O(n)

## Validation and Testing

### Unit Tests
- Individual failure rate calculations
- Percentile calculations with various node counts
- Performance multiplier edge cases
- Type3 grouping logic

### Integration Tests
- End-to-end reward calculations
- Multi-day scenarios
- Provider filtering
- Error handling

### Edge Case Tests
- Empty subnets
- Single node subnets
- Zero block scenarios
- Extreme failure rates

## Error Handling

### Validation Errors
- Invalid date ranges
- Missing rewards tables
- Missing metrics data
- Missing rewardable nodes

### Graceful Degradation
- Empty subnets default to 0% failure rate
- Missing data returns appropriate error messages
- Invalid calculations are caught and reported

## Security Considerations

### Data Integrity
- All calculations use precise decimal arithmetic
- Input validation prevents invalid data
- Results are deterministic and reproducible

### Financial Accuracy
- Decimal precision prevents rounding errors
- All monetary calculations use XDR
- Audit trail for all calculations

## Monitoring and Observability

### Metrics
- Subnet failure rates
- Node performance multipliers
- Reward distributions
- Calculation timing

### Logging
- Algorithm execution steps
- Performance data
- Error conditions
- Audit events

---

*This specification is based on the RewardsCalculationV1 implementation in the rewards-calculation module.*
