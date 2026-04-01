# Evaluator Report: state-manager

**Date**: 2026-04-01
**Evaluator**: Quinn (independent evaluation pass)
**Spec**: openspec/capabilities/state-manager/spec.md
**Source narrative**: openspec/specs/state-management/state-manager.md

---

## Grade: PASS_WITH_NOTES

---

## Hard-Fail Checklist

- [x] All REQ-* have at least one SCENARIO-*
- [x] Traceability table includes all REQ-* IDs
- [~] All narrative requirements captured — **2 gaps found**
- [x] No REQ-* IDs describe the same thing

---

## Quality Score: 7/10

---

## Findings

### Missing Requirements

**Gap 1: Overlay Merging Strategy not captured**

The narrative specifies a dedicated `Overlay Merging Strategy` requirement with two scenarios:
- Merge triggered by file count: when a page map shard exceeds `NUMBER_OF_FILES_HARD_LIMIT` (20) overlay files
- Merge within soft budget: shards with highest storage overhead merged first within `MERGE_SOFT_BUDGET_BYTES` (250 GiB)

Neither of these scenarios appears in the spec. The tip thread section (SCENARIO-STMGR-031+) mentions merging in passing but lacks the hard limit and budget scenarios.
**Recommendation**: Add `REQ-STMGR-010: Overlay Merge Strategy` with two scenarios covering the hard limit and soft budget triggers.

**Gap 2: Asynchronous Tip Thread operations partially missing**

The narrative has a full `Asynchronous Tip Thread` requirement with 6 distinct scenarios:
- TipToCheckpointAndSwitch
- FilterTipCanisters
- FlushPageMapDeltas
- ResetTipAndMerge
- ComputeManifest
- ValidateReplicatedStateAndFinalize

The spec has SCENARIO-STMGR-009 (commit with full scope) which covers the general checkpoint flow, but the individual tip thread operations (FilterTipCanisters, FlushPageMapDeltas, ComputeManifest) are not separately enumerated. These are important because they have distinct error modes and performance characteristics.
**Recommendation**: Add `REQ-STMGR-010+` or expand the existing REQ-STMGR-003 with sub-scenarios for each tip thread operation.

### Weak Scenarios

**SCENARIO-STMGR-010** (skip cloning during catch-up): References `MAX_CONSECUTIVE_ROUNDS_WITHOUT_STATE_CLONING (10)` and `NUM_ROUNDS_BEFORE_CHECKPOINT_TO_WRITE_OVERLAY (50)` correctly — these are precise and testable. No issue.

**SCENARIO-STMGR-011** (pre-checkpoint overlay flush): Well specified with the constant `50`.

**SCENARIO-STMGR-025** (cleaning old diverged states): Correctly references `MAX_ARCHIVED_DIVERGED_CHECKPOINTS_TO_KEEP (1)` and 30-day threshold.

**SCENARIO-STMGR-019** (reading latest state): Somewhat vague — "the most recent snapshot in memory" doesn't specify whether this includes uncommitted states or only committed ones. The narrative is clear that `get_latest_state()` returns the committed snapshot. Should say "most recently committed snapshot."
**Recommendation**: Clarify "committed snapshot" vs general state.

### Positives
- The certification delivery scenarios are excellent — STMGR-016, 017, 018 cleanly separate normal delivery, optimistic delivery, and hash mismatch
- State sync scenarios (STMGR-022, 023) correctly capture the "local checkpoint matches hash" optimization
- Diverged state management is well-specified with the 30-day cleanup threshold

### Test Linkage: LINKED
`rs/state_manager/tests/state_manager.rs` header covers REQ-STMGR-001..007, REQ-CKPT-001,003.

---

## Recommendations

1. Add REQ-STMGR-010: Overlay Merge Strategy (hard limit + soft budget scenarios)
2. Clarify SCENARIO-STMGR-019: "most recently committed snapshot in memory"
3. Consider expanding tip thread operations (FilterTipCanisters, ComputeManifest) to explicit scenarios
