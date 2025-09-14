# Node Rewards Calculation Algorithm

## Overview

The Internet Computer (IC) uses a performance-based rewards system to incentivize reliable node operation. This document explains how rewards are calculated for node providers based on their nodes' performance.

## Key Concepts

### What Are Rewards?
- **Daily rewards** are distributed to node providers based on their nodes' performance
- Rewards are calculated in **XDR** (Special Drawing Rights) - a stable international currency
- Only **rewardable nodes** (active, healthy nodes) are eligible for rewards

### Performance Measurement
- **Failure Rate** = Failed Blocks ÷ (Proposed Blocks + Failed Blocks)
- **Subnet Performance** = 75th percentile of all node failure rates in the subnet
- **Relative Performance** = Max(0, Node Failure Rate - Subnet Performance)

## Algorithm Steps

### Step 1: Calculate Individual Node Failure Rates

For each node in a subnet, the system calculates:
```
Node Failure Rate = Failed Blocks / (Proposed Blocks + Failed Blocks)
```

**Example:**
- Node proposed 100 blocks and failed 5 blocks
- Failure Rate = 5 / (100 + 5) = 4.76%

### Step 2: Calculate Subnet Performance (75th Percentile)

The subnet's performance is determined by the 75th percentile of all node failure rates:

```
Index = Ceil(Number of Nodes × 0.75) - 1
Subnet Performance = Sorted Failure Rates[Index]
```

**Example with 4 nodes:**
- Node failure rates: [0.99%, 4.76%, 16.67%, 33.33%] (sorted)
- Index = Ceil(4 × 0.75) - 1 = 3 - 1 = 2
- Subnet Performance = 16.67%

### Step 3: Calculate Relative Performance

For each node:
```
Relative Performance = Max(0, Node Failure Rate - Subnet Performance)
```

**Example:**
- Node failure rate: 33.33%
- Subnet performance: 16.67%
- Relative performance: Max(0, 33.33% - 16.67%) = 16.66%

### Step 4: Calculate Performance Multiplier

The performance multiplier determines how much of the base reward a node receives:

```
If Relative Performance < 10%:
    Performance Multiplier = 1.0 (No penalty)
Else If Relative Performance ≥ 60%:
    Performance Multiplier = 0.2 (Maximum penalty - 80% reduction)
Else:
    Performance Multiplier = 1.0 - ((Relative Performance - 10%) / (60% - 10%)) × 80%
```

**Example:**
- Relative performance: 16.66%
- Since 10% ≤ 16.66% < 60%:
- Penalty = ((16.66% - 10%) / (60% - 10%)) × 80% = 10.66%
- Performance Multiplier = 1.0 - 10.66% = 89.34%

### Step 5: Calculate Base Rewards

Base rewards depend on:
- **Node Type** (Type1, Type2, Type3, Type3.1)
- **Geographic Region**
- **Daily reward rates** (set by governance)

**Example Base Rewards (per day):**
- Type1 in Europe: 10,000 XDR
- Type1 in North America: 12,000 XDR
- Type2 in Europe: 20,000 XDR
- Type3 in North America: 30,000 XDR

### Step 6: Apply Type3 Special Logic

For Type3 and Type3.1 nodes in the same country:
1. **Group nodes** by continent + country
2. **Average the coefficients** of all nodes in the group
3. **Apply reduction** based on the number of nodes from the same provider

**Example:**
- 3 Type3 nodes + 2 Type3.1 nodes in USA
- Average coefficient: (90% × 3 + 70% × 2) ÷ 5 = 82%
- All nodes in the group get 82% of their base rewards

### Step 7: Calculate Final Rewards

```
Final Rewards = Base Rewards × Performance Multiplier × Type3 Coefficient (if applicable)
```

## Real-World Examples

### Example 1: Excellent Performance
- **Node**: Type1 in Europe
- **Performance**: 100 proposed, 1 failed (0.99% failure rate)
- **Subnet Performance**: 16.67%
- **Relative Performance**: Max(0, 0.99% - 16.67%) = 0%
- **Performance Multiplier**: 1.0 (no penalty)
- **Base Rewards**: 10,000 XDR
- **Final Rewards**: 10,000 × 1.0 = **10,000 XDR**

### Example 2: Poor Performance
- **Node**: Type1 in Europe
- **Performance**: 100 proposed, 50 failed (33.33% failure rate)
- **Subnet Performance**: 16.67%
- **Relative Performance**: Max(0, 33.33% - 16.67%) = 16.66%
- **Performance Multiplier**: 89.34% (10.66% penalty)
- **Base Rewards**: 10,000 XDR
- **Final Rewards**: 10,000 × 0.8934 = **8,934 XDR**

### Example 3: Type3 Node with Grouping
- **Node**: Type3 in North America, California
- **Performance**: 100 proposed, 5 failed (4.76% failure rate)
- **Subnet Performance**: 16.67%
- **Relative Performance**: Max(0, 4.76% - 16.67%) = 0%
- **Performance Multiplier**: 1.0 (no penalty)
- **Base Rewards**: 30,000 XDR
- **Type3 Group**: 5 nodes in USA (3 Type3 + 2 Type3.1)
- **Group Coefficient**: 82%
- **Final Rewards**: 30,000 × 1.0 × 0.82 = **24,600 XDR**

## Penalty Thresholds

| Relative Performance | Penalty | Performance Multiplier |
|---------------------|---------|----------------------|
| 0% - 9.99%          | 0%      | 100%                 |
| 10% - 59.99%        | 0% - 80%| 100% - 20%           |
| 60%+                | 80%     | 20%                  |

## Key Benefits

### For Node Providers
1. **Fair Rewards**: Only nodes performing worse than 75% of their peers get penalized
2. **Clear Metrics**: Simple failure rate calculation based on block production
3. **Predictable**: Performance thresholds are clearly defined
4. **Incentivized**: Rewards encourage reliable node operation

### For the Network
1. **Reliability**: Penalties discourage poor performance
2. **Stability**: 75th percentile reduces impact of outlier nodes
3. **Transparency**: All calculations are deterministic and verifiable
4. **Scalability**: Algorithm works regardless of subnet size

## Important Notes

### Zero Blocks Handling
- If a node has 0 proposed and 0 failed blocks: 0% failure rate
- If a node has 0 proposed but some failed blocks: 100% failure rate
- Empty subnets have 0% failure rate

### Single Node Subnets
- Subnet performance equals the single node's failure rate
- The node gets no penalty (relative performance = 0)

### Multi-Day Calculations
- Rewards are calculated daily
- Each day's performance is independent
- Total rewards = Sum of daily rewards

## Monitoring Your Performance

To maximize your rewards:

1. **Monitor Block Production**: Ensure your nodes are consistently proposing blocks
2. **Minimize Failures**: Keep failure rates below 10% relative to subnet performance
3. **Check Subnet Performance**: Understand how your nodes compare to peers
4. **Review Daily Reports**: Track performance trends over time

## Technical Details

- **Calculation Frequency**: Daily
- **Data Source**: Block production metrics
- **Precision**: Decimal arithmetic for financial accuracy
- **Rounding**: Standard financial rounding rules apply
- **Validation**: All calculations are verified and auditable

---

*This documentation is based on the RewardsCalculationV1 algorithm implementation. For technical details, refer to the source code in the rewards-calculation module.*
