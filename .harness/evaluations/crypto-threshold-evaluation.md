# Evaluator Report: crypto-threshold

**Date**: 2026-04-01  **Grade**: PASS_WITH_NOTES  **Score**: 7/10

## Hard-Fail Checklist
- [x] All REQ-* have SCENARIO-*
- [x] Traceability complete
- [~] All narrative requirements captured — 2 gaps

## Findings

### Missing Requirements

**Gap 1: ECDSA Signature Share Verification**
The narrative has `verify_sig_share` for ECDSA — verifies a signer's share by deserializing transcripts, looking up the signer's index in the key transcript, and calling `verify_ecdsa_signature_share`. Missing from spec.
**Recommendation**: Add SCENARIO-THRESH-014 (verify ECDSA signature share) and SCENARIO-THRESH-015 (missing signer in transcript → InvalidArgumentMissingSignerInTranscript).

**Gap 2: Schnorr Signature Share Verification**
Similarly, `verify_sig_share` for Schnorr (both BIP-340 and Ed25519) is in the narrative but not the spec.
**Recommendation**: Add SCENARIO-THRESH-016 (verify BIP-340 share) and SCENARIO-THRESH-017 (verify Ed25519 share).

### Quality: GOOD where captured

**Strong scenarios:**
- SCENARIO-THRESH-006 (insufficient ECDSA shares) — precise error with threshold and count
- SCENARIO-THRESH-012 (insufficient Schnorr shares) — same precision
- SCENARIO-THRESH-013 (Ingress signature verification capabilities) — correctly lists all 5 required trait implementations including the `Send + Sync` bound

**Weak scenarios:**
- SCENARIO-THRESH-003 (ECDSA share creation): "all required transcripts" should list them explicitly: kappa_unmasked, lambda_masked, kappa_times_lambda, key_times_lambda, key
- SCENARIO-THRESH-008 (masked transcript extraction): "CannotExtractFromMasked" is the error type — should also note this applies to both ECDSA and Schnorr

### Test Linkage: LINKED
`rs/crypto/tests/integration_test.rs` covers REQ-THRESH-002,005.

## Recommendations
1. Add SCENARIO-THRESH-014,015: ECDSA share verification + missing signer error
2. Add SCENARIO-THRESH-016,017: Schnorr share verification (BIP-340 and Ed25519)
3. Expand SCENARIO-THRESH-003: list all 5 transcript inputs explicitly
