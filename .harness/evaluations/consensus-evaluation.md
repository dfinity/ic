# Evaluator Report: consensus

**Date**: 2026-04-01
**Evaluator**: Quinn (independent evaluation pass)
**Spec**: openspec/capabilities/consensus/spec.md
**Source narrative**: openspec/specs/consensus/spec.md (37KB)

---

## Grade: FAIL

---

## Hard-Fail Checklist

- [x] All existing REQ-* have at least one SCENARIO-*
- [x] Traceability table complete for existing REQs
- [~] **FAIL: Multiple narrative requirements NOT captured**
- [x] No duplicate REQ-* IDs

---

## Quality Score: 5/10

---

## Findings

### Missing Requirements (Hard-Fail)

The source narrative is 37KB and covers 17 major sections. The spec only captures 10 requirements, omitting at minimum the following:

**Gap 1: Random Tape (completely missing)**
The narrative has a full `Random Tape` section distinct from Random Beacon. Random tape generates randomness for canister execution (not block ordering). It has scenarios for share creation and combination. Not present in spec at all.
**Required**: Add `REQ-CONS-011: Random Tape` with scenarios for tape share creation and tape aggregate.

**Gap 2: Share Aggregation (partially missing)**
The narrative has a dedicated `Share Aggregation` requirement covering how individual shares (notarization, finalization, random beacon, random tape) are combined into full artifacts. The spec only mentions aggregation implicitly within REQ-CONS-004 and REQ-CONS-005 without explicit aggregation scenarios.
**Required**: Add `REQ-CONS-012: Share Aggregation` with scenarios for threshold checking and artifact promotion.

**Gap 3: Validation Subcomponent (completely missing)**
The narrative has a `Validation` section covering how each type of consensus artifact is validated before being moved from unvalidated to validated pool. This is a critical subcomponent with scenarios for block validation, share validation, and rejection of invalid artifacts.
**Required**: Add `REQ-CONS-013: Artifact Validation` with scenarios for block proposal validation, notarization share validation, and finalization share validation.

**Gap 4: Consensus Status and Halting (partially captured)**
The narrative has scenarios for: subnet halt by registry (captured as SCENARIO-CONS-003), protocol version check (NOT captured), and DKG availability check (NOT captured).
**Required**: Add SCENARIO-CONS-023 (protocol version check rejects mismatched artifacts) and SCENARIO-CONS-024 (DKG availability check).

**Gap 5: Pool Bounds (completely missing)**
The narrative specifies pool bounds: maximum artifacts retained per height, purge below the minimum chain length, and bounds on unvalidated pool size. Not captured.
**Required**: Add `REQ-CONS-014: Pool Bounds`.

**Gap 6: Membership (completely missing)**
The narrative covers how consensus determines subnet membership from the registry, including how nodes verify their own membership and handle registry version updates.
**Required**: Add `REQ-CONS-015: Membership`.

**Gap 7: Block Payload — DKG data block details (partially captured)**
REQ-CONS-008 captures summary vs data block distinction, but misses:
- The specific data block scenarios for DKG dealings inclusion
- Payload size limits
- Subnet type differences in payload limits

### Weak Scenarios

**SCENARIO-CONS-004** (block maker election): Says "within top f+1 nodes" but doesn't specify how `f` is determined (from subnet record's `max_malicious_nodes`). Should reference the registry-sourced fault tolerance.

**SCENARIO-CONS-009** (block maker delay): The formula `base delay = unit_delay * r` is present but the dynamic delay component (added when rank > 0 and sufficient non-rank-0 finalized blocks in last 30 heights) is vague. The condition "sufficient" should be "more than 10."

### Positives
- The 10 captured REQs are accurate — no factual errors
- SCENARIO-CONS-007 and SCENARIO-CONS-008 correctly capture the validation context monotonicity and block time selection formula

---

## Recommendations (in priority order)

1. **[REQUIRED]** Add REQ-CONS-011: Random Tape (share creation, combination)
2. **[REQUIRED]** Add REQ-CONS-012: Share Aggregation
3. **[REQUIRED]** Add REQ-CONS-013: Artifact Validation
4. **[REQUIRED]** Add SCENARIO-CONS-023,024 to REQ-CONS-001 (protocol version check, DKG availability)
5. **[RECOMMENDED]** Add REQ-CONS-014: Pool Bounds
6. **[RECOMMENDED]** Add REQ-CONS-015: Membership
7. **[MINOR]** Clarify SCENARIO-CONS-004: `f = max_malicious_nodes` from subnet registry record
8. **[MINOR]** Clarify SCENARIO-CONS-009: dynamic delay condition is `> 10 non-rank-0 finalized blocks`
