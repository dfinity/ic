# Quick Reference: Rewards Calculation Algorithm

## TL;DR

**How it works**: Nodes get daily rewards based on their performance relative to their subnet peers. Only nodes performing worse than 75% of their peers get penalized.

## Key Formulas

### Failure Rate
```
Failure Rate = Failed Blocks / (Proposed Blocks + Failed Blocks)
```

### Subnet Performance (75th Percentile)
```
Index = Ceil(Number of Nodes × 0.75) - 1
Subnet Performance = Sorted Failure Rates[Index]
```

### Relative Performance
```
Relative Performance = Max(0, Node Failure Rate - Subnet Performance)
```

### Performance Multiplier
```
If Relative Performance < 10%:     Multiplier = 100% (No penalty)
If Relative Performance ≥ 60%:     Multiplier = 20%  (Max penalty)
Else:                              Multiplier = 100% - Penalty%

Where: Penalty% = ((Relative Performance - 10%) / 50%) × 80%
```

### Final Rewards
```
Final Rewards = Base Rewards × Performance Multiplier × Type3 Coefficient
```

## Examples

### Example 1: Good Performance
- **Node**: 100 proposed, 5 failed (4.76% failure rate)
- **Subnet**: 16.67% (75th percentile)
- **Relative**: Max(0, 4.76% - 16.67%) = 0%
- **Penalty**: 0%
- **Result**: Full rewards

### Example 2: Poor Performance
- **Node**: 100 proposed, 50 failed (33.33% failure rate)
- **Subnet**: 16.67% (75th percentile)
- **Relative**: Max(0, 33.33% - 16.67%) = 16.66%
- **Penalty**: 10.66%
- **Result**: 89.34% of base rewards

### Example 3: Type3 Grouping
- **3 Type3 nodes** (90% coefficient) + **2 Type3.1 nodes** (70% coefficient) in USA
- **Average coefficient**: (90% × 3 + 70% × 2) ÷ 5 = 82%
- **All nodes get**: Base rewards × Performance multiplier × 82%

## Penalty Thresholds

| Relative Performance | Penalty | Multiplier |
|---------------------|---------|------------|
| 0% - 9.99%          | 0%      | 100%       |
| 10% - 59.99%        | 0% - 80%| 100% - 20% |
| 60%+                | 80%     | 20%        |

## Edge Cases

| Scenario | Subnet Performance | Node Penalty |
|----------|-------------------|--------------|
| Empty subnet | 0% | 0% |
| Single node | Node's failure rate | 0% |
| 0 proposed, 0 failed | - | 0% |
| 0 proposed, N failed | - | 100% |

## Common Questions

**Q: Why 75th percentile?**
A: It ensures only the worst 25% of nodes get penalized, making the system fair and stable.

**Q: What if my node has 0 blocks?**
A: 0 proposed + 0 failed = 0% failure rate (no penalty). 0 proposed + N failed = 100% failure rate.

**Q: How are Type3 nodes different?**
A: They're grouped by country and get a reduced coefficient based on the average of all nodes in that country.

**Q: Can I get negative rewards?**
A: No, minimum rewards are 20% of base rewards (80% maximum penalty).

**Q: How often are rewards calculated?**
A: Daily, based on the previous day's block production data.

## Performance Tips

1. **Keep failure rate < 10%** relative to subnet performance
2. **Monitor daily performance** trends
3. **Understand your subnet** - check what the 75th percentile is
4. **For Type3 nodes** - consider the impact of other nodes in your country

## Code Examples

### Calculate Failure Rate
```rust
let failure_rate = num_blocks_failed / (num_blocks_proposed + num_blocks_failed);
```

### Calculate 75th Percentile
```rust
let sorted_rates = failure_rates.iter().sorted().collect::<Vec<_>>();
let index = ((failure_rates.len() as f64) * 0.75).ceil() as usize - 1;
let subnet_performance = sorted_rates[index];
```

### Calculate Performance Multiplier
```rust
let relative_performance = (node_failure_rate - subnet_performance).max(0.0);
let multiplier = if relative_performance < 0.1 {
    1.0
} else if relative_performance >= 0.6 {
    0.2
} else {
    1.0 - ((relative_performance - 0.1) / 0.5) * 0.8
};
```

---

*For detailed documentation, see [REWARDS_ALGORITHM.md](./REWARDS_ALGORITHM.md) and [TECHNICAL_ALGORITHM_SPEC.md](./TECHNICAL_ALGORITHM_SPEC.md)*
