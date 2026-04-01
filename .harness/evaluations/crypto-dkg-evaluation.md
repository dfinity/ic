# Evaluator Report: crypto-dkg

**Date**: 2026-04-01  **Grade**: PASS_WITH_NOTES  **Score**: 6/10

## Hard-Fail Checklist
- [x] All REQ-* have SCENARIO-*
- [x] Traceability complete
- [~] All narrative requirements captured — 3 gaps in IDkg section

## Findings

### Missing Requirements

**Gap 1: IDkg Complaint Verification**
The narrative has a dedicated `IDkg Complaint Verification` requirement: `verify_complaint` verifies the proof of discrete log equivalence, then re-decrypts the complainer's shares to confirm the dealing is faulty. Not captured in spec.
**Recommendation**: Add SCENARIO-DKG-015 under REQ-DKG-007.

**Gap 2: IDkg Transcript Opening**
The narrative has `IDkg Transcript Opening`: `open_transcript` opens shares for a complaint, returning `IDkgOpening`. Not captured.
**Recommendation**: Add SCENARIO-DKG-016 under REQ-DKG-007.

**Gap 3: IDkg Opening Verification**
The narrative has `IDkg Opening Verification`: `verify_opening` checks opening shares against the dealing's polynomial commitment. Not captured.
**Recommendation**: Add SCENARIO-DKG-017 under REQ-DKG-007.

### Quality: GOOD where captured

**Strong scenarios:**
- SCENARIO-DKG-007 (IDkg dealing with Pedersen vs Feldman commitments per operation type) — precise protocol detail
- SCENARIO-DKG-011 (complaint issuance with DH tuple and discrete log proof) — important security property

**Weak scenarios:**
- SCENARIO-DKG-008 (public verification): Lists checks but doesn't specify which check fails for which artifact type. Could be split by operation type.
- SCENARIO-DKG-013 (Random transcript): Says "minimum of reconstruction_threshold dealings required" but doesn't give the exact formula. Should be `≥ reconstruction_threshold` for random operation.

### Test Linkage: LINKED
`rs/crypto/tests/integration_test.rs` covers REQ-DKG-001,004.

## Recommendations
1. Add SCENARIO-DKG-015: IDkg complaint verification
2. Add SCENARIO-DKG-016: IDkg transcript opening
3. Add SCENARIO-DKG-017: IDkg opening verification
4. Clarify SCENARIO-DKG-013: dealings required = `≥ reconstruction_threshold`
