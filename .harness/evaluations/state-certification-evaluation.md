# Evaluator Report: state-certification

**Date**: 2026-04-01  **Grade**: PASS_WITH_NOTES  **Score**: 7/10

## Hard-Fail Checklist
- [x] All REQ-* have SCENARIO-*
- [x] Traceability complete
- [~] All narrative requirements captured — 1 gap

## Findings

### Missing Requirement

**Gap 1: Tree Diff Computation**
The narrative has a `Tree Diff Computation` requirement: converting `HashTree` to `RoseHashTree` and computing diffs between states by comparing digests. This is used for incremental certification and change detection. Not captured.
**Recommendation**: Add `REQ-CERT-006: Tree Diff Computation` with two scenarios (HashTree → RoseHashTree conversion, digest-based diff detection).

### Quality: GOOD

**Strong scenarios:**
- SCENARIO-CERT-005 (nested delegation rejected with `MultipleSubnetDelegationsNotAllowed`) — precise error type
- SCENARIO-CERT-012 (certified state read with witness: root hash matches certification) — full roundtrip test
- SCENARIO-CERT-013 (cached signature verification returns immediately) — performance contract

**Acceptable omissions:**
- Specific validation errors for malformed CBOR vs invalid signature length — covered by CERT-008 in general

### Test Linkage: LINKED
`rs/certification/src/tests.rs` → REQ-CERT-001,002,004

## Recommendations
1. Add REQ-CERT-006: Tree Diff Computation (HashTree→RoseHashTree, digest comparison)
