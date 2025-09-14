# Rewards Calculation Algorithm Flowchart

## Visual Representation of the Algorithm

```
┌─────────────────────────────────────────────────────────────────┐
│                    REWARDS CALCULATION ALGORITHM                │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────┐
│   INPUT DATA    │
│                 │
│ • Node Metrics  │
│ • Rewardable    │
│   Nodes         │
│ • Rewards Table │
└─────────┬───────┘
          │
          ▼
┌─────────────────┐
│  STEP 1: CALCULATE │
│  NODE FAILURE   │
│  RATES          │
│                 │
│ For each node:  │
│ FR = Failed /   │
│      (Proposed +│
│       Failed)   │
└─────────┬───────┘
          │
          ▼
┌─────────────────┐
│  STEP 2: CALCULATE │
│  SUBNET         │
│  PERFORMANCE    │
│  (75th PERCENTILE)│
│                 │
│ 1. Sort all FRs │
│ 2. Index =      │
│    ceil(n×0.75)-1│
│ 3. Subnet FR =  │
│    Sorted[Index]│
└─────────┬───────┘
          │
          ▼
┌─────────────────┐
│  STEP 3: CALCULATE │
│  RELATIVE       │
│  PERFORMANCE    │
│                 │
│ For each node:  │
│ Rel FR = max(0, │
│          Node FR│
│          - Subnet FR)│
└─────────┬───────┘
          │
          ▼
┌─────────────────┐
│  STEP 4: CALCULATE │
│  PERFORMANCE    │
│  MULTIPLIER     │
│                 │
│ If Rel FR < 10%:│
│   Multiplier = 1.0│
│ Else if Rel FR ≥ 60%:│
│   Multiplier = 0.2│
│ Else:           │
│   Multiplier = 1.0 -│
│   ((Rel FR - 10%)/│
│    50%) × 80%   │
└─────────┬───────┘
          │
          ▼
┌─────────────────┐
│  STEP 5: CALCULATE │
│  BASE REWARDS   │
│                 │
│ Based on:       │
│ • Node Type     │
│ • Region        │
│ • Daily Rates   │
└─────────┬───────┘
          │
          ▼
┌─────────────────┐
│  STEP 6: TYPE3  │
│  SPECIAL LOGIC  │
│                 │
│ For Type3/3.1:  │
│ 1. Group by     │
│    country      │
│ 2. Average      │
│    coefficients │
│ 3. Apply to all │
│    nodes in group│
└─────────┬───────┘
          │
          ▼
┌─────────────────┐
│  STEP 7: FINAL  │
│  REWARDS        │
│                 │
│ Final = Base ×  │
│         Multiplier ×│
│         Type3 Coeff│
└─────────────────┘
```

## Decision Tree for Performance Multiplier

```
                    Relative Performance
                           │
                    ┌──────┴──────┐
                    │             │
              < 10% │             │ ≥ 10%
                    │             │
                    ▼             ▼
              ┌─────────┐    ┌─────────┐
              │Multiplier│    │ Check if│
              │ = 100%  │    │ ≥ 60%   │
              │(No Penalty)│    │         │
              └─────────┘    │         │
                             │         │
                             ▼         ▼
                        ┌─────────┐ ┌─────────┐
                        │Multiplier│ │Multiplier│
                        │ = 20%   │ │ = 100% -│
                        │(Max Penalty)│ │ Penalty%│
                        └─────────┘ └─────────┘
```

## Example Calculation Flow

```
Node Performance: 100 proposed, 50 failed
                  ↓
Failure Rate: 50 / (100 + 50) = 33.33%
                  ↓
Subnet Performance: 16.67% (75th percentile)
                  ↓
Relative Performance: max(0, 33.33% - 16.67%) = 16.66%
                  ↓
Performance Multiplier: 1.0 - ((16.66% - 10%) / 50%) × 80% = 89.34%
                  ↓
Base Rewards: 10,000 XDR (Type1, Europe)
                  ↓
Final Rewards: 10,000 × 89.34% = 8,934 XDR
```

## Type3 Grouping Flow

```
Type3 Nodes in USA:
├── 3 Type3 nodes (90% coefficient)
├── 2 Type3.1 nodes (70% coefficient)
    ↓
Average Coefficient: (90% × 3 + 70% × 2) ÷ 5 = 82%
    ↓
All nodes in USA group get: Base × Multiplier × 82%
```

## Edge Cases

```
Empty Subnet:
├── Subnet Performance: 0%
├── All nodes: No penalty
└── Result: Full rewards

Single Node:
├── Subnet Performance: Node's failure rate
├── Node: No penalty (relative = 0%)
└── Result: Full rewards

Zero Blocks:
├── 0 proposed, 0 failed: 0% failure rate
├── 0 proposed, N failed: 100% failure rate
└── N proposed, 0 failed: 0% failure rate
```

---

*This flowchart provides a visual guide to understanding the rewards calculation algorithm step by step.*
