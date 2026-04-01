# Evaluator Report: ingress-manager

**Date**: 2026-04-01  **Grade**: PASS_WITH_NOTES  **Score**: 7/10

## Hard-Fail Checklist
- [x] All REQ-* have SCENARIO-*
- [x] Traceability complete
- [~] All narrative requirements captured — 2 minor gaps

## Findings

### Missing Requirements

**Gap 1: Ingress Bouncer not captured**
The narrative has an `Ingress Bouncer` section (`rs/ingress_manager/src/bouncer.rs`) that determines message retention or dropping in the artifact pool. This is structurally separate from the handler and selector. Not present in spec.
**Recommendation**: Add `REQ-ING-005: Ingress Bouncer` with scenario for retention determination.

**Gap 2: Malicious Flag Support**
The narrative specifies `maliciously_disable_ingress_validation` flag which bypasses all validation. While a testing/malicious behavior feature, it's a real documented behavior.
**Recommendation**: Add `REQ-ING-006: Malicious Flag Bypass` or note it within REQ-ING-001 as a conditional bypass scenario.

### Quality: GOOD

**Strong scenarios:**
- SCENARIO-ING-009 (round-robin per-canister selection) is precise and testable
- SCENARIO-ING-010 (pool arrival time ordering, not expiry time) correctly captures the anti-manipulation design
- SCENARIO-ING-016 (cycles cost validation with per-canister accumulation to prevent double-spending) is a subtle but important invariant

**Weak scenarios:**
- SCENARIO-ING-012 (minimum one message per block): Says "configured to 0" — should note this is a registry override, not the normal case
- SCENARIO-ING-015 (expiry validation during selection): Specifies "valid range" but doesn't give the formula. Should say: `context.time ≤ expiry ≤ context.time + MAX_INGRESS_TTL`

### Test Linkage: LINKED
`rs/ingress_manager/src/ingress_selector.rs` covers REQ-ING-002,003.

## Recommendations
1. Add REQ-ING-005: Ingress Bouncer (retention determination)
2. Add SCENARIO-ING-020b or note in REQ-ING-001: malicious validation bypass
3. Fix SCENARIO-ING-015: add explicit expiry validity formula
