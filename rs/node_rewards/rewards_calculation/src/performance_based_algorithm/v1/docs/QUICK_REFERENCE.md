# Quick Reference: Rewards Calculation Algorithm

## TL;DR

## Key Formulas

### Failure Rate

```
Failure Rate = Failed Blocks / (Proposed Blocks + Failed Blocks)
```

### Subnet Failure Rate (75th Percentile)

```
Index = Ceil(Number of Nodes × 0.75) - 1
Subnet Failure Rate = Sorted Failure Rates[Index]
```

### Relative Failure Rate

```
Relative Failure Rate = Max(0, Node Failure Rate - Subnet Failure Rate)
```

### Performance Multiplier

```
If Relative Failure Rate < 10%:     Multiplier = 100% (No penalty)
If Relative Failure Rate ≥ 60%:     Multiplier = 20%  (Max penalty)
Else:                              Multiplier = 100% - Reduction%

Where: Reduction% = ((Relative Failure Rate - 10%) / (60% - 10%) × 80%
```

### Final Rewards

```
Final Rewards = Base Rewards × Failure Rate Multiplier 
```

## Examples

### Example 1: Good Performance

- **Node**: 100 proposed, 5 failed (4.76% failure rate)
- **Subnet**: 16.67% (75th percentile)
- **Relative**: Max(0, 4.76% - 16.67%) = 0%
- **Reduction**: 0%
- **Result**: Full rewards

### Example 2: Poor Performance

- **Node**: 100 proposed, 50 failed (33.33% failure rate)
- **Subnet**: 16.67% (75th percentile)
- **Relative**: Max(0, 33.33% - 16.67%) = 16.66%
- **Reduction**: 10.66%
- **Result**: 89.34% of base rewards

### Example 3: Worst Performance

- **Node**: 0 proposed, 5 failed (100% failure rate)
- **Subnet**: 16.67% (75th percentile)
- **Relative**: Max(0, 100% - 16.67%) = 83.33%
- **Reduction**: 83.33%
- **Result**: 20% of base rewards

### Example 3: Type3 Grouping

- **3 Type3 nodes** (90% coefficient) + **2 Type3.1 nodes** (70% coefficient) in USA
- **Average coefficient**: (90% × 3 + 70% × 2) ÷ 5 = 82%
- **All nodes get**: Base rewards × Performance multiplier × 82%

## Penalty Thresholds

| Relative Performance | Penalty  | Multiplier |
|----------------------|----------|------------|
| 0% - 9.99%           | 0%       | 100%       |
| 10% - 59.99%         | 0% - 80% | 100% - 20% |
| 60%+                 | 80%      | 20%        |

## Common Questions

**Q: What if my node has 0 blocks?**
A: 0 proposed + 0 failed = 0% failure rate (no penalty). 0 proposed + N failed = 100% failure rate.

**Q: How are Type3 nodes different?**
A: They're grouped by country and get a reduced coefficient based on the average of all nodes in that country.

