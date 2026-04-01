# Evaluator Report: crypto-signatures

**Date**: 2026-04-01  **Grade**: PASS_WITH_NOTES  **Score**: 7/10

## Hard-Fail Checklist
- [x] All REQ-* have SCENARIO-*
- [x] Traceability complete
- [~] All narrative requirements captured — 2 gaps

## Findings

### Missing Requirements

**Gap 1: Basic Signature Batch Combining**
The narrative has `combine_basic_sig`: takes a non-empty map of NodeId → BasicSigOf and returns a `BasicSignatureBatch`. Also covers the empty-map error case.
**Recommendation**: Add SCENARIO-SIG-013 and SCENARIO-SIG-014 under a new `REQ-SIG-007: Basic Signature Batch Combining`.

**Gap 2: Basic Signature Batch Verification**
The narrative has `verify_basic_sig_batch`: batch verification using Ed25519 batch verification, requiring all keys to be Ed25519, and using a random seed from the vault.
**Recommendation**: Add SCENARIO-SIG-015 through SIG-018 covering: batch verification success, empty batch error, non-Ed25519 algorithm error, batch verification failure.

### Quality: GOOD where captured

**Strong scenarios:**
- SCENARIO-SIG-004 (verify by ECDSA P-256: 64-byte signature) — precise byte requirement
- SCENARIO-SIG-012 (data store capacity: oldest entry evicted when CAPACITY_PER_TAG exceeded) — testable with insertion count
- SCENARIO-SIG-010 (combining threshold shares: indexed by node index from store) — important implementation detail

**Weak scenarios:**
- SCENARIO-SIG-003 (verifying by Ed25519 public key): Mentions "standalone signature verifier" — should note this uses `ic_ed25519::PublicKey::verify_signature_with_public_key` not the vault
- SCENARIO-SIG-011 (verify combined by subnet public key): "initial high-threshold NI-DKG transcript" — should clarify this is the `NiDkgTag::HighThreshold` transcript, not the `LowThreshold` one

### Test Linkage: LINKED
`rs/crypto/tests/integration_test.rs` → REQ-SIG-001,002,004,005

## Recommendations
1. Add REQ-SIG-007: Basic Signature Batch Combining (SCENARIO-SIG-013,014)
2. Add REQ-SIG-008: Basic Signature Batch Verification (SCENARIO-SIG-015..018)
3. SCENARIO-SIG-011: clarify "HighThreshold" NI-DKG tag
