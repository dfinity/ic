# Evaluator Report: governance-sns

**Date**: 2026-04-01  **Grade**: PASS_WITH_NOTES  **Score**: 7/10

## Hard-Fail Checklist
- [x] All REQ-* have SCENARIO-*
- [x] Traceability complete
- [~] All narrative requirements captured — 2 gaps

## Findings

### Missing Requirements

**Gap 1: Native Proposal Action Types**
The narrative enumerates all native SNS action types with their numeric IDs:
- Motion (1), ManageNervousSystemParameters (2), UpgradeSnsControlledCanister (3), AddGenericNervousSystemFunction (4), RemoveGenericNervousSystemFunction (5), ExecuteGenericNervousSystemFunction (6), UpgradeSnsToNextVersion (7)

Not captured in the spec.
**Recommendation**: Add `REQ-SNS-007: Native Proposal Action Types` with scenario listing all types and their IDs.

**Gap 2: Followee Alias Management**
The narrative specifies: aliases for followees must not exceed 128 bytes (`MAX_NEURON_ALIAS_BYTES`), and each neuron ID must have at most one alias. Not captured.
**Recommendation**: Add SCENARIO-SNS-018 under REQ-SNS-006: followee alias size limit.

### Quality: GOOD

**Strong scenarios:**
- SCENARIO-SNS-013 (wait-for-quiet: bounded by initial voting period) — precise constraint
- SCENARIO-SNS-014/015 (normal vs critical thresholds: 3%/50% vs 20%/67%) — the basis points notation (300bp, 5000bp) is precise and directly testable

**Weak scenarios:**
- SCENARIO-SNS-007 (neuron voting power): Formula `stake * dissolve_delay_bonus * age_bonus * voting_power_percentage_multiplier` — should note the bonuses are multipliers between 1.0 and (1 + max_bonus), not percentages. The exact formula is `(1 + delay_bonus_fraction) * (1 + age_bonus_fraction)`.
- SCENARIO-SNS-003 (PreInitializationSwap limits): ClaimOrRefresh is "only when caller is the swap canister" — should also note that `StakeMaturity` is explicitly allowed for swap canister during PreInitializationSwap.

### Test Linkage: LINKED
`rs/sns/governance/tests/governance.rs` → REQ-SNS-002..006

## Recommendations
1. Add REQ-SNS-007: Native Proposal Action Types (7 types with numeric IDs)
2. Add SCENARIO-SNS-018: followee alias size limit (128 bytes)
3. SCENARIO-SNS-007: clarify bonus formula as (1 + fraction) multiplier
