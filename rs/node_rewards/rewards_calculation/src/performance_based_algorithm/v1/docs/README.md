# Rewards Calculation Algorithm Documentation

This directory contains comprehensive documentation for the Internet Computer's node rewards calculation algorithm.

## Documentation Files

### 📖 [REWARDS_ALGORITHM.md](./REWARDS_ALGORITHM.md)
**For Node Providers and Stakeholders**
- User-friendly explanation of how rewards work
- Real-world examples with calculations
- Performance tips and monitoring advice
- Clear explanation of penalties and thresholds

### 🔧 [TECHNICAL_ALGORITHM_SPEC.md](./TECHNICAL_ALGORITHM_SPEC.md)
**For Developers and System Administrators**
- Detailed technical specification
- Algorithm implementation details
- Data structures and formulas
- Performance characteristics and edge cases
- Code examples and validation methods

### ⚡ [QUICK_REFERENCE.md](./QUICK_REFERENCE.md)
**For Quick Lookups**
- TL;DR summary
- Key formulas and examples
- Common questions and answers
- Performance tips
- Code snippets

### 📊 [ALGORITHM_FLOWCHART.md](./ALGORITHM_FLOWCHART.md)
**Visual Guide**
- Step-by-step algorithm flowchart
- Decision trees for performance calculations
- Example calculation flows
- Edge case handling diagrams

## Algorithm Overview

The Internet Computer uses a **performance-based rewards system** that:

1. **Measures node performance** using block production success rates
2. **Compares nodes to their peers** using the 75th percentile threshold
3. **Applies penalties** only to nodes performing worse than 75% of their subnet
4. **Distributes daily rewards** based on performance multipliers

## Key Features

- ✅ **Fair**: Only the worst 25% of nodes get penalized
- ✅ **Stable**: 75th percentile reduces impact of outliers
- ✅ **Transparent**: All calculations are deterministic and verifiable
- ✅ **Scalable**: Works regardless of subnet size
- ✅ **Financial**: Uses precise decimal arithmetic for accuracy

## Quick Start

1. **New to rewards?** Start with [REWARDS_ALGORITHM.md](./REWARDS_ALGORITHM.md)
2. **Need technical details?** Read [TECHNICAL_ALGORITHM_SPEC.md](./TECHNICAL_ALGORITHM_SPEC.md)
3. **Looking for quick answers?** Check [QUICK_REFERENCE.md](./QUICK_REFERENCE.md)
4. **Want visual understanding?** See [ALGORITHM_FLOWCHART.md](./ALGORITHM_FLOWCHART.md)

## Contributing

When updating the algorithm or documentation:

1. Update the technical specification first
2. Update the user-facing documentation
3. Update the quick reference
4. Test all examples and calculations
5. Ensure consistency across all files

## Related Code

- **Implementation**: `rs/node_rewards/rewards_calculation/src/performance_based_algorithm/v1.rs`
- **Tests**: `rs/node_rewards/rewards_calculation/src/performance_based_algorithm/e2e_tests.rs`
- **Types**: `rs/node_rewards/rewards_calculation/src/types.rs`

---

*Last updated: Based on RewardsCalculationV1 implementation*
