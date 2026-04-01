# Evaluator Report: execution-cycles

**Date**: 2026-04-01
**Evaluator**: Quinn (independent evaluation pass)
**Spec**: openspec/capabilities/execution-cycles/spec.md
**Source narrative**: openspec/specs/execution/cycles.md

---

## Grade: PASS_WITH_NOTES

---

## Hard-Fail Checklist

- [x] All REQ-* have at least one SCENARIO-*
- [x] Traceability table includes all REQ-* IDs
- [~] All narrative requirements captured — **3 gaps found (see below)**
- [x] No REQ-* IDs describe the same thing

---

## Quality Score: 7/10

---

## Findings

### Missing Requirements (hard-fail threshold not reached, but should be fixed)

**Gap 1: HTTP Request Fee Variants not fully captured**

The narrative `cycles.md` describes THREE distinct HTTP fee formulas:
- **v1**: `(http_request_linear_baseline_fee + http_request_quadratic_baseline_fee * subnet_size + ...) * subnet_size`
- **v2**: accounts for roundtrip time and transform instructions: `(1_000_000 + 50 * request_size + 140_000 * n + 800 * n^2 + ...) * n`
- **beta** (payload-based): `(4_000_000 + 50_000 * subnet_size + ...) * subnet_size`

The spec has `REQ-CYC-010: HTTP Outcall Fees` with only `SCENARIO-CYC-025` (a single generic scenario). The three formula variants each need a distinct SCENARIO-* to be testable.
**Recommendation**: Add SCENARIO-CYC-025a, 025b, 025c for each formula variant (or renumber as SCENARIO-CYC-025, 043, 044).

**Gap 2: Canister Deletion Leftover Cycles missing from traceability**

`REQ-CYC-017: Canister Deletion Leftover Cycles` is in the spec with `SCENARIO-CYC-035` (burn cycles respecting threshold). However the narrative also describes a separate scenario: computing leftover cycles as `balance + reserved_balance` on deletion, converting to `NominalCycles`. This is distinct from the burn scenario and is not captured.
**Recommendation**: Add `SCENARIO-CYC-043: Compute leftover cycles on deletion` under REQ-CYC-017.

**Gap 3: Mint Cycles Validation REQ split**

The narrative has two distinct mint scenarios: (a) normal mint by CMC, and (b) mint rejected for non-CMC. These are in `REQ-CYC-012` as SCENARIO-CYC-027 and SCENARIO-CYC-028 — that part is correct. However SCENARIO-CYC-029 (overflow saturation) is technically a separate validation concern. This is minor and acceptable as-is.

### Weak Scenarios

**SCENARIO-CYC-025 (HTTP fee)**: Currently too vague — just says "based on request size, response size limit, and subnet size." With three distinct formulas in the codebase, this cannot be used to write a deterministic test. **Needs splitting** (see Gap 1).

**SCENARIO-CYC-040 (Execution cost includes per-message fee)**: Formula references `update_message_execution_fee` but doesn't specify whether this is a fixed constant or registry-sourced. Should note it comes from `CyclesAccountManagerConfig`.

### Positives
- The Wasm32 vs Wasm64 fee distinction (REQ-CYC-017) is precisely captured — many systems miss this
- REQ-CYC-016 (reserved balance draining) is excellent — the two-scenario split cleanly separates resource vs non-resource charges
- REQ-CYC-018 (message memory billing) correctly identifies that message memory uses the same per-byte rate as heap memory
- Test linkage is comprehensive: `cycles_account_manager/tests/` covers REQ-CYC-001 through 016

### Consistency: PASS
No contradictions with `_bmad/architecture.md` or other capability specs.

---

## Recommendations

1. Split SCENARIO-CYC-025 into three scenarios for HTTP fee v1, v2, and beta formulas
2. Add SCENARIO-CYC-043 for deletion leftover cycles computation
3. Clarify SCENARIO-CYC-040's `update_message_execution_fee` as `CyclesAccountManagerConfig`-sourced
