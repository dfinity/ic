use crate::vault::api::CspVault;
use ic_types::crypto::AlgorithmId;
use std::sync::Arc;

/// Key should be present only after key generation.
///
/// Note:  Theoretically the invariant is: The key should be present only in the
/// CSP that generated it, and only after generation and before deletion, if
/// deletion is supported for that key type.  Thus ideally there should be a
/// test that generates many sequences of events and verifies that this
/// invariant holds, regardless of the sequence of events, the number or type of
/// keys in the CSP and so on.  Making such a test is hard, so this is just one
/// sequence of events.
pub fn sks_should_contain_keys_only_after_generation(
    csp_vault1: Arc<dyn CspVault>,
    csp_vault2: Arc<dyn CspVault>,
) {
    let (key_id1, _public_key) = csp_vault1
        .gen_key_pair(AlgorithmId::Ed25519)
        .expect("Test setup failed: Failed to generate keys");
    assert!(
        csp_vault1.sks_contains(&key_id1),
        "Key should be present after generation."
    );
    assert!(
        !csp_vault2.sks_contains(&key_id1),
        "Key should be absent if not generated in the CSP."
    );

    let (key_id2, _public_key) = csp_vault2
        .gen_key_pair(AlgorithmId::Ed25519)
        .expect("Test setup failed: Failed to generate keys");
    assert!(
        key_id1 != key_id2,
        "Test failure: Key IDs from different CSPs were the same.  Check random number generation."
    );
    assert!(
        csp_vault2.sks_contains(&key_id2),
        "Key should be present in the CSP that generated it."
    );
    assert!(
        !csp_vault2.sks_contains(&key_id1),
        "The second CSP should not contain thekeys of the first."
    );
    assert!(
        !csp_vault1.sks_contains(&key_id2),
        "Key first CSP should not contain the keys of the second."
    );
}
