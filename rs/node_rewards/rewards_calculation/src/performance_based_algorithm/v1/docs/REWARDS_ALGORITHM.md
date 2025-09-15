# Node Rewards Calculation Algorithm

## Overview

The Internet Computer (IC) uses a performance-based rewards system to incentivize reliable node operation. This document
explains how rewards are calculated for node providers based on their nodes' performance.

# RewardsCalculationV1

## Algorithm Overview

The `RewardsCalculationV1` algorithm implements a performance-based reward distribution system for Internet Computer
nodes. It calculates daily rewards based on node performance relative to subnet peers using a 75th percentile threshold.

## Core Constants

```rust
const SUBNET_FAILURE_RATE_PERCENTILE: f64 = 0.75;  // 75th percentile
const MIN_FAILURE_RATE: Decimal = 0.1;             // 10% minimum for penalties
const MAX_FAILURE_RATE: Decimal = 0.6;             // 60% maximum reduction threshold
const MIN_REWARDS_REDUCTION: Decimal = 0.0;        // 0% minimum reduction
const MAX_REWARDS_REDUCTION: Decimal = 0.8;        // 80% maximum reduction
const REWARDS_TABLE_DAYS: f64 = 30.4375;           // Average days per month
```

## Key Concepts

### What Are Rewards?

- **Daily rewards** are distributed to node providers based on their nodes' performance
- Rewards are calculated in **XDR** (Special Drawing Rights)

### Failure Rate Measurement

- **Failure Rate** = Failed Blocks ÷ (Proposed Blocks + Failed Blocks)
- **Subnet Failure Rate** = 75th percentile of all node failure rates in the subnet
- **Relative Failure Rate** = Max(0, Node Failure Rate - Subnet Performance)

## Algorithm Steps

### Step 1: Calculate Individual Node Failure Rates

For each node in a subnet, the system calculates:

```
Node Failure Rate = Failed Blocks / (Proposed Blocks + Failed Blocks)
```

**Example:**

- Node proposed 100 blocks and failed 5 blocks
- Failure Rate = 5 / (100 + 5) = 4.76%

### Step 2: Calculate Subnet Failure Rate (75th Percentile)

The subnet's Failure Rate is determined by the 75th percentile of all node failure rates:

```
Index = Ceil(Number of Nodes × 0.75) - 1
Subnet Failure Rate = Sorted Failure Rates[Index]
```

**Example with 4 nodes:**

- Node failure rates: [0.99%, 4.76%, 16.67%, 33.33%] (sorted)
- Index = Ceil(4 × 0.75) - 1 = 3 - 1 = 2
- Subnet Failure Rate = 16.67%

### Step 3: Calculate Relative Failure Rate

For each node:

```
Relative Failure Rate = Max(0, Node Failure Rate - Subnet Failure Rate)
```

**Example:**

- Node failure rate: 33.33%
- Subnet Failure Rate: 16.67%
- Relative Failure Rate: Max(0, 33.33% - 16.67%) = 16.66%

### Step 4: Calculate Performance Multiplier

The performance multiplier determines how much of the base reward a node receives:

```
If Relative Failure Rate < 10%:
    Performance Multiplier = 1.0 (No reduction)
Else If Relative Failure Rate ≥ 60%:
    Performance Multiplier = 0.2 (Maximum reduction - 80% reduction)
Else:
    Performance Multiplier = 1.0 - ((Relative Failure Rate - 10%) / (60% - 10%)) × 80%
```

**Example:**

- Relative Failure Rate: 16.66%
- Since 10% ≤ 16.66% < 60%:
- Reduction = ((16.66% - 10%) / (60% - 10%)) × 80% = 10.66%
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

## Examples

### Example 1: Excellent Performance

- **Node**: Type1 in Europe
- **Failure Rate**: 100 proposed, 1 failed (0.99% failure rate)
- **Subnet Failure Rate**: 16.67%
- **Relative Failure Rate**: Max(0, 0.99% - 16.67%) = 0%
- **Performance Multiplier**: 1.0 (no reduction)
- **Base Rewards**: 10,000 XDR
- **Final Rewards**: 10,000 × 1.0 = **10,000 XDR**

### Example 2: Poor Performance

- **Node**: Type1 in Europe
- **Failure Rate**: 100 proposed, 50 failed (33.33% failure rate)
- **Subnet Failure Rate**: 16.67%
- **Relative Failure Rate**: Max(0, 33.33% - 16.67%) = 16.66%
- **Performance Multiplier**: 89.34% (10.66% reduction)
- **Base Rewards**: 10,000 XDR
- **Final Rewards**: 10,000 × 0.8934 = **8,934 XDR**

### Example 3: Type3 Node with Grouping

- **Node**: Type3 in North America, California
- **Failure Rate**: 100 proposed, 5 failed (4.76% failure rate)
- **Subnet Failure Rate**: 16.67%
- **Relative Failure Rate**: Max(0, 4.76% - 16.67%) = 0%
- **Performance Multiplier**: 1.0 (no reduction)
- **Base Rewards**: 30,000 XDR
- **Type3 Group**: 5 nodes in USA (3 Type3 + 2 Type3.1)
- **Group Coefficient**: 82%
- **Final Rewards**: 30,000 × 1.0 × 0.82 = **24,600 XDR**
