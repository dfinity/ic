# Evaluator Report: query-stats

**Date**: 2026-04-01  **Grade**: PASS_WITH_NOTES  **Score**: 7/10

## Hard-Fail Checklist
- [x] All REQ-* have SCENARIO-*
- [x] Traceability complete
- [~] All narrative requirements captured — 2 gaps

## Findings

### Missing Requirements

**Gap 1: State Machine Delivery**
The narrative has a `deliver_query_stats` function that aggregates query statistics from consensus blocks into the replicated state, updating the highest aggregated epoch. Not captured as a distinct REQ.
**Recommendation**: Add `REQ-QS-005: State Machine Delivery` with one scenario.

**Gap 2: Metrics Requirement**
The narrative specifies comprehensive metrics: current epoch, number of tracked canister IDs, accumulated stats (calls, instructions, payload sizes), plus duration metrics for build and validate operations. Not captured.
**Recommendation**: Add `REQ-QS-006: Metrics` with scenarios for collector and payload builder metrics.

### Quality: GOOD

**Strong scenarios:**
- SCENARIO-QS-006 (channel full → stats dropped + warning) — correct severity level for this observable failure
- SCENARIO-QS-009 (per-node deduplication only — different nodes CAN report same canister) — important invariant that enables cross-node aggregation
- SCENARIO-QS-014 (duplicate canister ID — within payload OR with past payloads) — correct scope

**Weak scenarios:**
- SCENARIO-QS-003 (set epoch from height): Formula `height / query_stats_epoch_length` — should clarify this is integer division (floor), not rounding
- SCENARIO-QS-007 (build payload with current stats): "statistics already in past payloads or the certified state are excluded" — could be clearer: "excluded per-node, not globally"

### Test Linkage: LINKED
`rs/query_stats/src/payload_builder.rs` → REQ-QS-003,004

## Recommendations
1. Add REQ-QS-005: State Machine Delivery (deliver_query_stats)
2. Add REQ-QS-006: Metrics (collector and payload builder metrics)
3. SCENARIO-QS-003: clarify integer division
