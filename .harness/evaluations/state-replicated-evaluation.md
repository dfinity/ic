# Evaluator Report: state-replicated

**Date**: 2026-04-01  **Grade**: PASS_WITH_NOTES  **Score**: 7/10

## Hard-Fail Checklist
- [x] All REQ-* have SCENARIO-*
- [x] Traceability complete
- [~] All narrative requirements captured — 2 gaps

## Findings

### Missing Requirements

**Gap 1: Dropped Message Metrics**
The narrative has a `Dropped Message Metrics` requirement with two scenarios:
- `observe_timed_out_message`: recorded with kind (request/response), context (inbound/outbound), class (guaranteed/best-effort)
- `observe_shed_message`: recorded with kind, context, and byte size

These are observable monitoring properties not captured in the spec.
**Recommendation**: Add `REQ-STATE-010: Dropped Message Metrics` with two scenarios.

**Gap 2: Output Queue Iteration order (REQ-STATE-004)**
The narrative specifies that output queue iteration goes round-robin across canisters, with subnet queues processed FIRST (before canister queues), and within each canister, output queues are iterated round-robin across destinations. The spec (SCENARIO-STATE-006) only covers input queue round-robin. Output queue ordering is a distinct and testable behavior.
**Recommendation**: Add SCENARIO-STATE-015 under REQ-STATE-004 for output queue ordering.

### Quality: GOOD

**Strong scenarios:**
- SCENARIO-STATE-007 (queue full → QueueFull with capacity) — error type and payload precise
- SCENARIO-STATE-012/013 (hard vs soft invariants correctly distinguished: hard fails load, soft self-heals) — important design property
- SCENARIO-STATE-014 (split removes non-assigned canisters, prunes streams, updates subnet ID) — comprehensive

**Weak scenarios:**
- SCENARIO-STATE-001 (top-level composition): Lists `SubnetQueues` as a component but the actual type name is `CanisterQueues` for subnet-level queues. Should note the naming inconsistency.
- SCENARIO-STATE-010 (ingress status lifecycle): Transitions listed as linear but `Done` is actually a terminal state that precedes garbage collection. Should note `Done` → GC.

### Test Linkage: LINKED
`rs/replicated_state/tests/replicated_state.rs` → REQ-STATE-003,004,005,008

## Recommendations
1. Add REQ-STATE-010: Dropped Message Metrics (2 scenarios)
2. Add SCENARIO-STATE-015: Output queue round-robin iteration (subnet queues first)
3. SCENARIO-STATE-010: note `Done` is terminal before GC
